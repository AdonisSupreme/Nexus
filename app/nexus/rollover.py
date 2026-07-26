"""Database-environment rollover execution helpers for Sentinel Nexus."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import uuid4

from app.nexus.database_connections import oracle_config_dir_from_datagrip, oracle_dsn_from_datagrip
from app.nexus.models import (
    RolloverAssessment,
    RolloverEnvironment,
    RolloverExecution,
    RolloverReplacementRule,
    RolloverRuleAssignment,
    RolloverRuleCondition,
    RolloverRuleAssessment,
)


IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]*$")


class RolloverOracleGateway:
    """Assess and apply configured Oracle string-replacement rollover rules."""

    def assess_environment(
        self,
        environment: RolloverEnvironment,
        *,
        password: str | None,
        assessed_by: str | None = None,
    ) -> RolloverAssessment:
        connection = self._connect(environment, password=password)
        try:
            self._apply_session_schema(connection, environment)
            return self._assess_with_connection(environment, connection, assessed_by=assessed_by)
        finally:
            self._close_quietly(connection)

    def execute_environment(
        self,
        environment: RolloverEnvironment,
        *,
        password: str | None,
        requested_by: str,
        approved_by: str | None,
        reason: str | None,
    ) -> RolloverExecution:
        execution = RolloverExecution(
            execution_id=f"roll-exec-{uuid4()}",
            environment_id=environment.environment_id,
            environment_name=environment.environment_name,
            status="APPROVED",
            requested_at=datetime.utcnow(),
            requested_by=requested_by,
            approved_by=approved_by,
            reason=reason,
        )
        connection = self._connect(environment, password=password)
        try:
            self._apply_session_schema(connection, environment)
            pre_assessment = self._assess_with_connection(environment, connection, assessed_by=requested_by)
            execution.pre_assessment = pre_assessment
            if pre_assessment.status != "requires_rollover":
                execution.status = "NOOP"
                execution.completed_at = datetime.utcnow()
                execution.result_summary = "No live-source values matched the configured rollover rules."
                execution.post_assessment = pre_assessment
                return execution

            cursor = connection.cursor()
            try:
                rule_results: list[RolloverRuleAssessment] = []
                pre_results = {item.rule_id: item for item in pre_assessment.rule_results}
                for rule in self._enabled_rules(environment):
                    pre_result = pre_results.get(rule.rule_id)
                    if not pre_result or pre_result.source_matches <= 0:
                        continue
                    sql = self._update_sql(rule)
                    cursor.execute(sql, self._update_binds(rule))
                    rows_affected = int(getattr(cursor, "rowcount", 0) or 0)
                    rule_results.append(
                        pre_result.model_copy(
                            update={
                                "rows_affected": rows_affected,
                                "generated_sql": sql,
                                "message": f"{rows_affected} row(s) updated.",
                            }
                        )
                    )
                connection.commit()
                execution.committed = True
                execution.rule_results = rule_results
                execution.post_assessment = self._assess_with_connection(environment, connection, assessed_by=requested_by)
                execution.status = "COMPLETED"
                execution.completed_at = datetime.utcnow()
                execution.result_summary = (
                    f"Rollover committed for {environment.environment_name}; "
                    f"{sum(item.rows_affected for item in rule_results)} row(s) updated."
                )
                return execution
            finally:
                self._close_quietly(cursor)
        except Exception:
            if hasattr(connection, "rollback"):
                connection.rollback()
            raise
        finally:
            self._close_quietly(connection)

    def _assess_with_connection(
        self,
        environment: RolloverEnvironment,
        connection: object,
        *,
        assessed_by: str | None,
    ) -> RolloverAssessment:
        rule_results: list[RolloverRuleAssessment] = []
        cursor = connection.cursor()
        try:
            for rule in sorted(environment.rules, key=lambda item: (item.sequence, item.rule_id)):
                if not rule.enabled:
                    rule_results.append(
                        RolloverRuleAssessment(
                            rule_id=rule.rule_id,
                            table_name=rule.table_name,
                            column_name=rule.column_name,
                            operation=rule.operation,
                            source_value=rule.source_value,
                            target_value=rule.target_value,
                            assignments=rule.assignments,
                            conditions=rule.conditions,
                            status="skipped",
                            message="Rule is disabled.",
                        )
                    )
                    continue
                self._validate_rule(rule)
                source_matches = self._count_matches(cursor, rule, "source")
                target_matches = self._count_matches(cursor, rule, "target")
                samples = self._sample_values(cursor, rule)
                status = (
                    "requires_change"
                    if source_matches > 0
                    else "aligned"
                    if target_matches > 0
                    else "no_match"
                )
                message = (
                    "Live-source values are still present."
                    if status == "requires_change"
                    else "Target values are present."
                    if status == "aligned"
                    else "Neither source nor target values were found."
                )
                rule_results.append(
                    RolloverRuleAssessment(
                        rule_id=rule.rule_id,
                        table_name=rule.table_name,
                        column_name=rule.column_name,
                        operation=rule.operation,
                        source_value=rule.source_value,
                        target_value=rule.target_value,
                        assignments=rule.assignments,
                        conditions=rule.conditions,
                        status=status,
                        source_matches=source_matches,
                        target_matches=target_matches,
                        sample_values=samples,
                        generated_sql=self._update_sql(rule),
                        message=message,
                    )
                )
        finally:
            self._close_quietly(cursor)

        enabled_results = [item for item in rule_results if item.status != "skipped"]
        requiring_change = [item for item in enabled_results if item.status == "requires_change"]
        aligned = [item for item in enabled_results if item.status == "aligned"]
        no_match = [item for item in enabled_results if item.status == "no_match"]
        status = (
            "requires_rollover"
            if requiring_change
            else "aligned"
            if enabled_results and len(aligned) == len(enabled_results)
            else "drift"
            if no_match
            else "unknown"
        )
        message = (
            "One or more live configuration markers remain and require rollover."
            if status == "requires_rollover"
            else "Configured markers already match the selected environment."
            if status == "aligned"
            else "Some configured markers were not found; review rules or connected schema."
        )
        return RolloverAssessment(
            assessment_id=f"roll-assess-{uuid4()}",
            environment_id=environment.environment_id,
            environment_name=environment.environment_name,
            status=status,
            assessed_at=datetime.utcnow(),
            assessed_by=assessed_by,
            connected=True,
            rules_checked=len(enabled_results),
            rules_requiring_change=len(requiring_change),
            rules_aligned=len(aligned),
            rules_with_no_match=len(no_match),
            rule_results=rule_results,
            message=message,
        )

    def _connect(self, environment: RolloverEnvironment, *, password: str | None) -> object:
        if not environment.connection.username:
            raise ValueError("Oracle username is required for rollover assessment.")
        if password is None:
            raise ValueError("Oracle password is required for rollover assessment.")
        try:
            import oracledb  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("The optional 'oracledb' package is required for Oracle rollover execution.") from exc
        connect_kwargs = {
            "user": environment.connection.username,
            "password": password,
            "dsn": self._dsn(environment),
        }
        config_dir = self._config_dir(environment)
        if config_dir:
            connect_kwargs["config_dir"] = config_dir
        try:
            return oracledb.connect(**connect_kwargs)
        except Exception as exc:
            message = str(exc)
            if "DPY-4027" in message:
                raise ValueError(
                    "Oracle DSN was treated as a TNS alias, but no Oracle config directory was provided. "
                    "Enter Host, Port, and Service Name so Nexus can use easy-connect, or set Oracle Config Directory "
                    "to the folder containing tnsnames.ora."
                ) from exc
            raise

    def _dsn(self, environment: RolloverEnvironment) -> str:
        return oracle_dsn_from_datagrip(environment.connection)

    def _config_dir(self, environment: RolloverEnvironment) -> str | None:
        return oracle_config_dir_from_datagrip(environment.connection)

    def _apply_session_schema(self, connection: object, environment: RolloverEnvironment) -> None:
        schema = (environment.connection.schema_name or "").strip()
        if not schema:
            return
        if not IDENTIFIER_RE.match(schema):
            raise ValueError(f"Unsafe Oracle schema identifier: {schema}")
        cursor = connection.cursor()
        try:
            cursor.execute(f"ALTER SESSION SET CURRENT_SCHEMA = {schema}")
        finally:
            self._close_quietly(cursor)

    def _count_matches(self, cursor: object, rule: RolloverReplacementRule, mode: str) -> int:
        binds = self._base_binds(rule)
        where = self._where_clause(rule, binds, mode=mode)
        sql = f"SELECT COUNT(*) FROM {self._table_identifier(rule.table_name)}{where}"
        cursor.execute(sql, self._binds_for_sql(sql, binds))
        row = cursor.fetchone()
        return int(self._first_value(row) or 0)

    def _sample_values(self, cursor: object, rule: RolloverReplacementRule) -> list[str]:
        binds = self._base_binds(rule)
        where = self._where_clause(rule, binds, mode="sample")
        sql = (
            f"SELECT {self._column_identifier(rule.column_name)} "
            f"FROM {self._table_identifier(rule.table_name)}{where} "
            "FETCH FIRST 5 ROWS ONLY"
        )
        cursor.execute(sql, self._binds_for_sql(sql, binds))
        rows = cursor.fetchall()
        return [str(self._first_value(row)) for row in rows if self._first_value(row) is not None]

    def _update_sql(self, rule: RolloverReplacementRule, binds: dict[str, object] | None = None) -> str:
        table = self._table_identifier(rule.table_name)
        column = self._column_identifier(rule.column_name)
        binds = binds if binds is not None else self._base_binds(rule)
        where = self._where_clause(rule, binds, mode="update")
        if rule.operation == "replace":
            assignment = f"{column} = REPLACE({column}, :source_value, :target_value)"
        else:
            assignment = ", ".join(
                f"{self._column_identifier(item.column_name)} = :assignment_{index}_target"
                for index, item in enumerate(self._assignment_specs(rule))
            )
        return f"UPDATE {table} SET {assignment}{where}"

    def _update_binds(self, rule: RolloverReplacementRule) -> dict[str, object]:
        binds = self._base_binds(rule)
        sql = self._update_sql(rule, binds)
        return self._binds_for_sql(sql, binds)

    def _validate_rule(self, rule: RolloverReplacementRule) -> None:
        self._table_identifier(rule.table_name)
        self._column_identifier(rule.column_name)
        for condition in rule.conditions:
            self._validate_condition(condition)
        for assignment in rule.assignments:
            self._validate_assignment(assignment)
        if rule.operation == "replace" and rule.assignments:
            raise ValueError(f"Rollover rule {rule.rule_id} cannot use extra assignments with REPLACE.")
        if rule.operation == "replace" and not rule.source_value:
            raise ValueError(f"Rollover rule {rule.rule_id} has an empty source value.")
        if not rule.target_value:
            raise ValueError(f"Rollover rule {rule.rule_id} has an empty target value.")
        has_assignment_source = any(item.source_value for item in self._assignment_specs(rule))
        if rule.operation == "set" and not has_assignment_source and not rule.conditions and not rule.allow_unscoped:
            raise ValueError(
                f"Rollover rule {rule.rule_id} is an unscoped SET. "
                "Add conditions or explicitly enable allow_unscoped."
            )

    def _base_binds(self, rule: RolloverReplacementRule) -> dict[str, object]:
        binds: dict[str, object] = {
            "source_value": rule.source_value,
            "target_value": rule.target_value,
            "source_like": f"%{rule.source_value}%",
            "target_like": f"%{rule.target_value}%",
        }
        for index, assignment in enumerate(self._assignment_specs(rule)):
            binds[f"assignment_{index}_source"] = assignment.source_value
            binds[f"assignment_{index}_target"] = assignment.target_value
        return binds

    def _where_clause(self, rule: RolloverReplacementRule, binds: dict[str, object], *, mode: str) -> str:
        column = self._column_identifier(rule.column_name)
        fragments: list[str] = []
        if rule.operation == "replace":
            if mode in {"source", "update"}:
                fragments.append(f"{column} LIKE :source_like")
            elif mode == "target":
                fragments.append(f"{column} LIKE :target_like")
            elif mode == "sample":
                fragments.append(f"({column} LIKE :source_like OR {column} LIKE :target_like)")
        else:
            assignments = self._assignment_specs(rule)
            if mode in {"source", "update"}:
                if any(item.source_value for item in assignments):
                    fragments.extend(
                        f"{self._column_identifier(item.column_name)} = :assignment_{index}_source"
                        for index, item in enumerate(assignments)
                        if item.source_value
                    )
                else:
                    fragments.append(
                        "("
                        + " OR ".join(
                            f"{self._column_identifier(item.column_name)} IS NULL "
                            f"OR {self._column_identifier(item.column_name)} <> :assignment_{index}_target"
                            for index, item in enumerate(assignments)
                        )
                        + ")"
                    )
            elif mode == "target":
                fragments.extend(
                    f"{self._column_identifier(item.column_name)} = :assignment_{index}_target"
                    for index, item in enumerate(assignments)
                )
            elif mode == "sample" and any(item.source_value for item in assignments):
                source_tuple = " AND ".join(
                    f"{self._column_identifier(item.column_name)} = :assignment_{index}_source"
                    for index, item in enumerate(assignments)
                    if item.source_value
                )
                target_tuple = " AND ".join(
                    f"{self._column_identifier(item.column_name)} = :assignment_{index}_target"
                    for index, item in enumerate(assignments)
                )
                fragments.append(f"(({source_tuple}) OR ({target_tuple}))")
        fragments.extend(self._condition_fragments(rule.conditions, binds))
        if not fragments:
            if rule.operation == "set" and rule.allow_unscoped:
                return ""
            raise ValueError(f"Rollover rule {rule.rule_id} has no safe WHERE scope.")
        return " WHERE " + " AND ".join(fragments)

    def _assignment_specs(self, rule: RolloverReplacementRule) -> list[RolloverRuleAssignment]:
        primary = RolloverRuleAssignment(
            column_name=rule.column_name,
            source_value=rule.source_value,
            target_value=rule.target_value,
        )
        return [primary, *rule.assignments]

    def _condition_fragments(
        self,
        conditions: list[RolloverRuleCondition],
        binds: dict[str, object],
    ) -> list[str]:
        fragments: list[str] = []
        for condition_index, condition in enumerate(conditions):
            column = self._column_identifier(condition.column_name)
            values = [str(item).strip() for item in condition.values if str(item).strip()]
            if not values:
                raise ValueError(f"Rollover condition on {condition.column_name} has no values.")
            operator = condition.operator
            if operator == "equals":
                bind_name = f"condition_{condition_index}_0"
                binds[bind_name] = self._condition_value(values[0])
                fragments.append(f"{column} = :{bind_name}")
            elif operator == "like":
                bind_name = f"condition_{condition_index}_0"
                binds[bind_name] = f"%{values[0]}%"
                fragments.append(f"{column} LIKE :{bind_name}")
            elif operator == "in":
                placeholders: list[str] = []
                for value_index, value in enumerate(values):
                    bind_name = f"condition_{condition_index}_{value_index}"
                    binds[bind_name] = self._condition_value(value)
                    placeholders.append(f":{bind_name}")
                fragments.append(f"{column} IN ({', '.join(placeholders)})")
            else:
                raise ValueError(f"Unsupported rollover condition operator: {operator}")
        return fragments

    def _validate_condition(self, condition: RolloverRuleCondition) -> None:
        self._column_identifier(condition.column_name)
        if condition.operator not in {"equals", "in", "like"}:
            raise ValueError(f"Unsupported rollover condition operator: {condition.operator}")
        if not [str(item).strip() for item in condition.values if str(item).strip()]:
            raise ValueError(f"Rollover condition on {condition.column_name} has no values.")

    def _validate_assignment(self, assignment: RolloverRuleAssignment) -> None:
        self._column_identifier(assignment.column_name)
        if not assignment.target_value:
            raise ValueError(f"Rollover assignment on {assignment.column_name} has an empty target value.")

    @staticmethod
    def _condition_value(value: str) -> object:
        stripped = value.strip()
        if re.fullmatch(r"-?\d+", stripped):
            return int(stripped)
        return stripped

    @staticmethod
    def _binds_for_sql(sql: str, binds: dict[str, object]) -> dict[str, object]:
        return {name: value for name, value in binds.items() if f":{name}" in sql}

    def _enabled_rules(self, environment: RolloverEnvironment) -> list[RolloverReplacementRule]:
        return [rule for rule in sorted(environment.rules, key=lambda item: (item.sequence, item.rule_id)) if rule.enabled]

    def _table_identifier(self, value: str) -> str:
        parts = [part.strip() for part in value.split(".") if part.strip()]
        if not parts or any(not IDENTIFIER_RE.match(part) for part in parts):
            raise ValueError(f"Unsafe Oracle table identifier: {value}")
        return ".".join(parts)

    def _column_identifier(self, value: str) -> str:
        if not IDENTIFIER_RE.match(value.strip()):
            raise ValueError(f"Unsafe Oracle column identifier: {value}")
        return value.strip()

    @staticmethod
    def _first_value(row: object) -> object | None:
        if row is None:
            return None
        if isinstance(row, dict):
            return next(iter(row.values()), None)
        return row[0] if row else None  # type: ignore[index]

    @staticmethod
    def _close_quietly(resource: object) -> None:
        close = getattr(resource, "close", None)
        if callable(close):
            close()
