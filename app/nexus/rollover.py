"""Database-environment rollover execution helpers for Sentinel Nexus."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import uuid4

from app.nexus.database_connections import oracle_config_dir_from_datagrip, oracle_dsn_from_datagrip
from app.nexus.models import (
    RolloverAssessment,
    RolloverConnectionProfile,
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
        password: object | None,
        assessed_by: str | None = None,
    ) -> RolloverAssessment:
        self._validate_environment_schemas(environment)
        if self._uses_schema_credentials(environment):
            return self._assess_with_schema_credentials(environment, password, assessed_by=assessed_by)
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
        password: object | None,
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
        self._validate_environment_schemas(environment)
        if self._uses_schema_credentials(environment):
            return self._execute_with_schema_credentials(
                environment,
                password,
                execution=execution,
                requested_by=requested_by,
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
                    sql: str | None = None
                    schema_id: str | None = rule.schema_id
                    schema_name: str | None = None
                    try:
                        schema_id, schema_name = self._rule_schema(environment, rule)
                        self._apply_cursor_schema(cursor, schema_name)
                        sql = self._update_sql(rule)
                        cursor.execute(sql, self._update_binds(rule))
                        rows_affected = int(getattr(cursor, "rowcount", 0) or 0)
                    except Exception as exc:
                        raise self._rule_error(
                            environment,
                            rule,
                            phase="execution:update",
                            exc=exc,
                            schema_id=schema_id,
                            schema_name=schema_name,
                            sql=sql,
                        ) from exc
                    rule_results.append(
                        pre_result.model_copy(
                            update={
                                "schema_id": schema_id,
                                "schema_name": schema_name,
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
                            schema_id=rule.schema_id,
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
                schema_id: str | None = rule.schema_id
                schema_name: str | None = None
                generated_sql: str | None = None
                try:
                    phase = "validation"
                    self._validate_rule(rule)
                    phase = "schema-resolution"
                    schema_id, schema_name = self._rule_schema(environment, rule)
                    phase = "schema-switch"
                    self._apply_cursor_schema(cursor, schema_name)
                    phase = "source-count"
                    source_matches = self._count_matches(cursor, rule, "source")
                    phase = "target-count"
                    target_matches = self._count_matches(cursor, rule, "target")
                    phase = "sample"
                    samples = self._sample_values(cursor, rule)
                    phase = "sql-generation"
                    generated_sql = self._update_sql(rule)
                except Exception as exc:
                    raise self._rule_error(
                        environment,
                        rule,
                        phase=f"assessment:{phase}",
                        exc=exc,
                        schema_id=schema_id,
                        schema_name=schema_name,
                        sql=generated_sql,
                    ) from exc
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
                        schema_id=schema_id,
                        schema_name=schema_name,
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
                        generated_sql=generated_sql,
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

    def _assess_with_schema_credentials(
        self,
        environment: RolloverEnvironment,
        password: object | None,
        *,
        assessed_by: str | None,
    ) -> RolloverAssessment:
        connections = self._connect_schema_profiles(environment, password)
        try:
            return self._assess_with_schema_connections(environment, connections, assessed_by=assessed_by)
        finally:
            for connection in connections.values():
                self._close_quietly(connection)

    def _assess_with_schema_connections(
        self,
        environment: RolloverEnvironment,
        connections: dict[str, object],
        *,
        assessed_by: str | None,
    ) -> RolloverAssessment:
        rule_results: list[RolloverRuleAssessment] = []
        for rule in sorted(environment.rules, key=lambda item: (item.sequence, item.rule_id)):
            if not rule.enabled:
                rule_results.append(
                    RolloverRuleAssessment(
                        rule_id=rule.rule_id,
                        schema_id=rule.schema_id,
                        schema_name=None,
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
            schema_id: str | None = rule.schema_id
            schema_name: str | None = None
            generated_sql: str | None = None
            try:
                phase = "validation"
                self._validate_rule(rule)
                phase = "schema-resolution"
                schema_id, schema_name = self._rule_schema(environment, rule)
                phase = "connection-select"
                connection = connections[self._schema_connection_key(environment, rule)]
            except Exception as exc:
                raise self._rule_error(
                    environment,
                    rule,
                    phase=f"assessment:{phase}",
                    exc=exc,
                    schema_id=schema_id,
                    schema_name=schema_name,
                    sql=generated_sql,
                ) from exc
            cursor = connection.cursor()
            try:
                try:
                    phase = "schema-switch"
                    self._apply_cursor_schema(cursor, schema_name)
                    phase = "source-count"
                    source_matches = self._count_matches(cursor, rule, "source")
                    phase = "target-count"
                    target_matches = self._count_matches(cursor, rule, "target")
                    phase = "sample"
                    samples = self._sample_values(cursor, rule)
                    phase = "sql-generation"
                    generated_sql = self._update_sql(rule)
                except Exception as exc:
                    raise self._rule_error(
                        environment,
                        rule,
                        phase=f"assessment:{phase}",
                        exc=exc,
                        schema_id=schema_id,
                        schema_name=schema_name,
                        sql=generated_sql,
                    ) from exc
            finally:
                self._close_quietly(cursor)
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
                    schema_id=schema_id,
                    schema_name=schema_name,
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
                    generated_sql=generated_sql,
                    message=message,
                )
            )
        return self._assessment_from_rule_results(environment, rule_results, assessed_by=assessed_by)

    def _execute_with_schema_credentials(
        self,
        environment: RolloverEnvironment,
        password: object | None,
        *,
        execution: RolloverExecution,
        requested_by: str,
    ) -> RolloverExecution:
        connections = self._connect_schema_profiles(environment, password)
        try:
            pre_assessment = self._assess_with_schema_connections(environment, connections, assessed_by=requested_by)
            execution.pre_assessment = pre_assessment
            if pre_assessment.status != "requires_rollover":
                execution.status = "NOOP"
                execution.completed_at = datetime.utcnow()
                execution.result_summary = "No live-source values matched the configured rollover rules."
                execution.post_assessment = pre_assessment
                return execution

            rule_results: list[RolloverRuleAssessment] = []
            pre_results = {item.rule_id: item for item in pre_assessment.rule_results}
            for rule in self._enabled_rules(environment):
                pre_result = pre_results.get(rule.rule_id)
                if not pre_result or pre_result.source_matches <= 0:
                    continue
                sql: str | None = None
                schema_id: str | None = rule.schema_id
                schema_name: str | None = None
                try:
                    schema_id, schema_name = self._rule_schema(environment, rule)
                    connection = connections[self._schema_connection_key(environment, rule)]
                except Exception as exc:
                    raise self._rule_error(
                        environment,
                        rule,
                        phase="execution:schema-resolution",
                        exc=exc,
                        schema_id=schema_id,
                        schema_name=schema_name,
                        sql=sql,
                    ) from exc
                cursor = connection.cursor()
                try:
                    try:
                        self._apply_cursor_schema(cursor, schema_name)
                        sql = self._update_sql(rule)
                        cursor.execute(sql, self._update_binds(rule))
                        rows_affected = int(getattr(cursor, "rowcount", 0) or 0)
                    except Exception as exc:
                        raise self._rule_error(
                            environment,
                            rule,
                            phase="execution:update",
                            exc=exc,
                            schema_id=schema_id,
                            schema_name=schema_name,
                            sql=sql,
                        ) from exc
                finally:
                    self._close_quietly(cursor)
                rule_results.append(
                    pre_result.model_copy(
                        update={
                            "schema_id": schema_id,
                            "schema_name": schema_name,
                            "rows_affected": rows_affected,
                            "generated_sql": sql,
                            "message": f"{rows_affected} row(s) updated.",
                        }
                    )
                )
            for connection in connections.values():
                connection.commit()
            execution.committed = True
            execution.rule_results = rule_results
            execution.post_assessment = self._assess_with_schema_connections(environment, connections, assessed_by=requested_by)
            execution.status = "COMPLETED"
            execution.completed_at = datetime.utcnow()
            execution.result_summary = (
                f"Rollover committed for {environment.environment_name}; "
                f"{sum(item.rows_affected for item in rule_results)} row(s) updated."
            )
            return execution
        except Exception:
            for connection in connections.values():
                if hasattr(connection, "rollback"):
                    connection.rollback()
            raise
        finally:
            for connection in connections.values():
                self._close_quietly(connection)

    def _assessment_from_rule_results(
        self,
        environment: RolloverEnvironment,
        rule_results: list[RolloverRuleAssessment],
        *,
        assessed_by: str | None,
    ) -> RolloverAssessment:
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

    def _connect(self, environment: RolloverEnvironment, *, password: object | None) -> object:
        return self._connect_profile(
            environment.connection,
            password=self._default_password(password),
            label="rollover assessment",
        )

    def _connect_profile(
        self,
        connection_profile: RolloverConnectionProfile,
        *,
        password: object | None,
        label: str,
    ) -> object:
        if not connection_profile.username:
            raise ValueError("Oracle username is required for rollover assessment.")
        if password is None:
            raise ValueError(f"Oracle password is required for {label}.")
        try:
            import oracledb  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("The optional 'oracledb' package is required for Oracle rollover execution.") from exc
        connect_kwargs = {
            "user": connection_profile.username,
            "password": str(password),
            "dsn": self._dsn(connection_profile),
        }
        config_dir = self._config_dir(connection_profile)
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

    def _dsn(self, source: RolloverEnvironment | RolloverConnectionProfile) -> str:
        connection = source.connection if isinstance(source, RolloverEnvironment) else source
        return oracle_dsn_from_datagrip(connection)

    def _config_dir(self, source: RolloverEnvironment | RolloverConnectionProfile) -> str | None:
        connection = source.connection if isinstance(source, RolloverEnvironment) else source
        return oracle_config_dir_from_datagrip(connection)

    def _apply_session_schema(self, connection: object, environment: RolloverEnvironment) -> None:
        if environment.schema_profiles:
            return
        schema = (environment.connection.schema_name or "").strip()
        if not schema:
            return
        cursor = connection.cursor()
        try:
            self._apply_cursor_schema(cursor, schema)
        finally:
            self._close_quietly(cursor)

    def _apply_rule_schema(
        self,
        cursor: object,
        environment: RolloverEnvironment,
        rule: RolloverReplacementRule,
    ) -> None:
        _, schema_name = self._rule_schema(environment, rule)
        self._apply_cursor_schema(cursor, schema_name)

    def _apply_cursor_schema(self, cursor: object, schema_name: str | None) -> None:
        schema = (schema_name or "").strip()
        if not schema:
            return
        self._schema_identifier(schema)
        cursor.execute(f"ALTER SESSION SET CURRENT_SCHEMA = {schema}")

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

    def _validate_environment_schemas(self, environment: RolloverEnvironment) -> None:
        profiles = [profile for profile in environment.schema_profiles if profile.enabled]
        if environment.schema_profiles and not profiles:
            raise ValueError("At least one rollover schema profile must be enabled.")
        seen_ids: set[str] = set()
        for profile in profiles:
            schema_id = profile.schema_id.strip()
            if not IDENTIFIER_RE.match(schema_id):
                raise ValueError(f"Unsafe rollover schema key: {profile.schema_id}")
            normalized_id = schema_id.lower()
            if normalized_id in seen_ids:
                raise ValueError(f"Duplicate rollover schema key: {schema_id}")
            seen_ids.add(normalized_id)
            self._schema_identifier(profile.schema_name)
            if profile.username:
                self._schema_identifier(profile.username)
        if profiles and any(profile.username.strip() for profile in profiles):
            missing_usernames = [
                profile.schema_id.strip()
                for profile in profiles
                if not profile.username.strip()
            ]
            if missing_usernames:
                raise ValueError(
                    "Multi-credential rollover requires every enabled schema profile to have an Oracle username. "
                    f"Missing username on: {', '.join(missing_usernames)}"
                )
        if len(profiles) > 1:
            valid_ids = {profile.schema_id.strip().lower() for profile in profiles}
            missing_rules = [
                rule.rule_id
                for rule in self._enabled_rules(environment)
                if not (rule.schema_id or "").strip()
            ]
            invalid_rules = [
                rule.rule_id
                for rule in self._enabled_rules(environment)
                if (rule.schema_id or "").strip() and (rule.schema_id or "").strip().lower() not in valid_ids
            ]
            if missing_rules:
                raise ValueError(
                    "Multi-schema rollover requires every enabled rule to select a schema. "
                    f"Missing schema on: {', '.join(missing_rules)}"
                )
            if invalid_rules:
                raise ValueError(
                    "Rollover rules reference schema keys that are not configured on this environment: "
                    f"{', '.join(invalid_rules)}"
                )

    @staticmethod
    def _uses_schema_credentials(environment: RolloverEnvironment) -> bool:
        return any(profile.enabled and profile.username.strip() for profile in environment.schema_profiles)

    def _connect_schema_profiles(
        self,
        environment: RolloverEnvironment,
        password: object | None,
    ) -> dict[str, object]:
        connections: dict[str, object] = {}
        try:
            for schema_id in self._schema_connection_keys_for_rules(environment):
                profile = self._schema_profile(environment, schema_id)
                profile_connection = environment.connection.model_copy(deep=True)
                profile_connection.username = profile.username.strip() or profile_connection.username
                profile_connection.schema_name = profile.schema_name.strip()
                connections[schema_id] = self._connect_profile(
                    profile_connection,
                    password=self._schema_password(environment, profile, password),
                    label=f"rollover schema {schema_id}",
                )
            return connections
        except Exception:
            for connection in connections.values():
                self._close_quietly(connection)
            raise

    def _schema_connection_keys_for_rules(self, environment: RolloverEnvironment) -> list[str]:
        keys: list[str] = []
        for rule in self._enabled_rules(environment):
            key = self._schema_connection_key(environment, rule)
            if key not in keys:
                keys.append(key)
        return keys

    def _schema_connection_key(self, environment: RolloverEnvironment, rule: RolloverReplacementRule) -> str:
        schema_id, _ = self._rule_schema(environment, rule)
        if not schema_id:
            raise ValueError(f"Rollover rule {rule.rule_id} does not resolve to a schema profile.")
        return schema_id.strip().upper()

    def _schema_profile(self, environment: RolloverEnvironment, schema_id: str):
        normalized_schema_id = schema_id.strip().upper()
        for profile in environment.schema_profiles:
            if profile.enabled and profile.schema_id.strip().upper() == normalized_schema_id:
                return profile
        raise ValueError(f"Unknown rollover schema profile: {schema_id}")

    def _schema_password(self, environment: RolloverEnvironment, profile: object, password: object | None) -> str | None:
        bundle = self._password_bundle(password)
        schema_id = getattr(profile, "schema_id").strip().upper()
        schema_password = bundle.get("schemas", {}).get(schema_id)
        if schema_password:
            return str(schema_password)
        default_password = str(bundle.get("default") or "") or None
        profile_username = getattr(profile, "username", "").strip()
        if not profile_username or profile_username.lower() == environment.connection.username.lower():
            return default_password
        raise ValueError(f"Oracle password is required for rollover schema {schema_id}.")

    @staticmethod
    def _default_password(password: object | None) -> str | None:
        bundle = RolloverOracleGateway._password_bundle(password)
        return str(bundle.get("default") or "") or None

    @staticmethod
    def _password_bundle(password: object | None) -> dict[str, object]:
        if not password:
            return {"default": None, "schemas": {}}
        if isinstance(password, dict):
            return {
                "default": str(password.get("default") or "") or None,
                "schemas": {
                    str(key).strip().upper(): str(value)
                    for key, value in (password.get("schemas") or {}).items()
                    if str(key).strip() and str(value)
                },
            }
        return {"default": str(password), "schemas": {}}

    def _rule_schema(
        self,
        environment: RolloverEnvironment,
        rule: RolloverReplacementRule,
    ) -> tuple[str | None, str | None]:
        profiles = [profile for profile in environment.schema_profiles if profile.enabled]
        schema_id = (rule.schema_id or "").strip()
        if not profiles:
            if schema_id:
                raise ValueError(
                    f"Rollover rule {rule.rule_id} selects schema '{schema_id}', "
                    "but the environment has no schema profiles configured."
                )
            schema_name = (environment.connection.schema_name or "").strip() or None
            return None, schema_name

        profile_by_id = {profile.schema_id.strip().lower(): profile for profile in profiles}
        if len(profiles) == 1 and not schema_id:
            profile = profiles[0]
            return profile.schema_id.strip(), profile.schema_name.strip()
        profile = profile_by_id.get(schema_id.lower())
        if not profile:
            raise ValueError(f"Unknown rollover schema '{schema_id}' on rule {rule.rule_id}.")
        return profile.schema_id.strip(), profile.schema_name.strip()

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

    def _rule_error(
        self,
        environment: RolloverEnvironment,
        rule: RolloverReplacementRule,
        *,
        phase: str,
        exc: Exception,
        schema_id: str | None = None,
        schema_name: str | None = None,
        sql: str | None = None,
    ) -> RuntimeError:
        assignment_columns = [assignment.column_name for assignment in rule.assignments]
        condition_columns = [condition.column_name for condition in rule.conditions]
        context = [
            f"environment={environment.environment_id}",
            f"phase={phase}",
            f"rule_id={rule.rule_id}",
            f"sequence={rule.sequence}",
            f"schema_id={schema_id or '-'}",
            f"schema_name={schema_name or '-'}",
            f"table={rule.table_name}",
            f"column={rule.column_name}",
            f"operation={rule.operation}",
        ]
        if assignment_columns:
            context.append(f"assignment_columns={','.join(assignment_columns)}")
        if condition_columns:
            context.append(f"condition_columns={','.join(condition_columns)}")
        if sql:
            context.append(f"sql={sql}")
        context.append(f"cause={exc.__class__.__name__}: {exc}")
        return RuntimeError("Nexus rollover rule failed: " + "; ".join(context))

    def _table_identifier(self, value: str) -> str:
        parts = [part.strip() for part in value.split(".") if part.strip()]
        if not parts or any(not IDENTIFIER_RE.match(part) for part in parts):
            raise ValueError(f"Unsafe Oracle table identifier: {value}")
        return ".".join(parts)

    def _column_identifier(self, value: str) -> str:
        if not IDENTIFIER_RE.match(value.strip()):
            raise ValueError(f"Unsafe Oracle column identifier: {value}")
        return value.strip()

    def _schema_identifier(self, value: str) -> str:
        if not IDENTIFIER_RE.match(value.strip()):
            raise ValueError(f"Unsafe Oracle schema identifier: {value}")
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
