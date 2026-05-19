"""Persistence and shared-database access for Sentinel Nexus."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import psycopg
from psycopg.rows import dict_row

from app.config.settings import settings
from app.nexus.models import ManagedSop, NexusIncident, NexusState, TaskHandoff
from app.utils.logging import get_logger


logger = get_logger(__name__)


class NexusRepository:
    """Persist Nexus state to the SentinelOps database."""

    SIGNAL_RETENTION = 1500
    CHANGE_RETENTION = 500
    HEARTBEAT_RETENTION = 200
    REQUIRED_TABLES = (
        "nexus_meta",
        "service_catalog",
        "dependency_cluster",
        "business_flow",
        "business_flow_step",
        "service_health_snapshot",
        "dependency_edge",
        "signal_event",
        "change_event",
        "incident",
        "incident_service",
        "task_handoff",
        "operator_feedback",
        "diagnostic_bundle",
        "action_execution",
        "agent_heartbeat",
    )

    def __init__(self) -> None:
        self.file_path = settings.DATA_DIR / "nexus_state.json"
        self._dsn = settings.nexus_database_dsn
        self._use_postgres = bool(self._dsn)
        self._allow_local_state = settings.NEXUS_ALLOW_LOCAL_STATE

    def load_state(self) -> NexusState:
        if self._use_postgres:
            self._verify_schema()
            return self._load_from_postgres()

        if settings.NEXUS_REQUIRE_DATABASE and not self._allow_local_state:
            raise RuntimeError(
                "Sentinel Nexus requires DATABASE_URL to use the SentinelOps database. "
                "Set DATABASE_URL and apply the Nexus migration, or set NEXUS_ALLOW_LOCAL_STATE=true only for tests."
            )

        if not self.file_path.exists():
            return NexusState()

        with open(self.file_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return self._state_from_payload(payload, persist_on_migrate=True)

    def persist_state(self, state: NexusState) -> None:
        if self._use_postgres:
            self._persist_to_postgres(state)
            return

        if settings.NEXUS_REQUIRE_DATABASE and not self._allow_local_state:
            raise RuntimeError("Refusing to persist Sentinel Nexus state without the SentinelOps database.")

        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.file_path, "w", encoding="utf-8") as handle:
            json.dump(state.model_dump(mode="json"), handle, indent=2, ensure_ascii=False)

    def delete_service(self, service_id: str) -> None:
        if not self._use_postgres:
            state = self.load_state()
            state.services = [item for item in state.services if item.service_id != service_id]
            state.clusters = [
                cluster.model_copy(update={"service_ids": [item for item in cluster.service_ids if item != service_id]})
                for cluster in state.clusters
            ]
            state.dependency_edges = [
                edge
                for edge in state.dependency_edges
                if edge.from_service_id != service_id and edge.to_service_id != service_id
            ]
            self.persist_state(state)
            return

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM service_catalog WHERE service_id = %s", (service_id,))
            conn.commit()

    def delete_cluster(self, cluster_id: str) -> None:
        if not self._use_postgres:
            state = self.load_state()
            state.clusters = [item for item in state.clusters if item.cluster_id != cluster_id]
            state.dependency_edges = [edge for edge in state.dependency_edges if edge.cluster_id != cluster_id]
            for service in state.services:
                if cluster_id in service.cluster_ids:
                    service.cluster_ids = [item for item in service.cluster_ids if item != cluster_id]
                if service.cluster == cluster_id:
                    service.cluster = service.cluster_ids[0] if service.cluster_ids else None
            self.persist_state(state)
            return

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM dependency_edge WHERE cluster_id = %s", (cluster_id,))
                cur.execute("DELETE FROM dependency_cluster WHERE cluster_id = %s", (cluster_id,))
            conn.commit()

    def delete_edge(self, edge_id: str) -> None:
        if not self._use_postgres:
            state = self.load_state()
            state.dependency_edges = [edge for edge in state.dependency_edges if (edge.edge_id or "") != edge_id]
            self.persist_state(state)
            return

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM dependency_edge WHERE edge_id = %s", (edge_id,))
            conn.commit()

    def resolve_user_ref(self, identifier: str | None) -> dict[str, object] | None:
        if not identifier or not self._use_postgres:
            return None
        query = """
        SELECT
            id::text AS id,
            username,
            email,
            department_id,
            section_id::text AS section_id
        FROM users
        WHERE lower(username) = lower(%s)
           OR lower(email) = lower(%s)
           OR id::text = %s
        LIMIT 1
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                row = cur.execute(query, (identifier, identifier, identifier)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row.get("username") or "",
            "email": row.get("email") or "",
            "department_id": row.get("department_id"),
            "section_id": row.get("section_id"),
        }

    def create_task_record(
        self,
        incident: NexusIncident,
        requested_by: str,
        assignee: str | None = None,
        due_at=None,
        notes: str | None = None,
    ) -> TaskHandoff:
        if not self._use_postgres:
            task_id = str(uuid4())
            return TaskHandoff(
                task_id=task_id,
                incident_id=incident.incident_id,
                title=f"[Nexus] {incident.risk_level} {incident.title}",
                description=self._task_description(incident, notes),
                created_at=incident.start_time,
                created_by=requested_by,
                route_hint=f"/tasks?task={task_id}",
                status="created",
                tags=["nexus", f"incident:{incident.incident_id}", *(f"service:{item}" for item in incident.affected_services)],
                external_task_id=task_id,
                assigned_to=assignee or requested_by,
                task_status="ACTIVE",
            )

        actor = self.resolve_user_ref(requested_by)
        if actor is None:
            raise KeyError(f"Unable to resolve SentinelOps user '{requested_by}' for Task Center handoff.")
        assignee_ref = self.resolve_user_ref(assignee or requested_by) or actor
        title = f"[Nexus] {incident.risk_level} {incident.title}"
        description = self._task_description(incident, notes)
        tags = ["nexus", f"incident:{incident.incident_id}", *(f"service:{item}" for item in incident.affected_services)]
        section_id = str(actor.get("section_id") or assignee_ref.get("section_id") or "").strip()
        if not section_id and settings.NEXUS_ALLOWED_SECTION_IDS:
            section_id = settings.NEXUS_ALLOWED_SECTION_IDS[0]
        department_id = actor.get("department_id") or assignee_ref.get("department_id")
        collaborator_ids = list(dict.fromkeys([actor["id"], assignee_ref["id"]]))

        with self._connect() as conn:
            with conn.cursor() as cur:
                task_row = cur.execute(
                    """
                    INSERT INTO tasks (
                        title, description, task_type, priority, status,
                        assigned_to_id, assigned_by_id, department_id, section_id,
                        due_date, tags, is_recurring
                    ) VALUES (
                        %s, %s, 'DEPARTMENT', %s, 'ACTIVE',
                        %s::uuid, %s::uuid, %s, %s::uuid,
                        %s, %s, FALSE
                    )
                    RETURNING id::text AS id, created_at
                    """,
                    (
                        title,
                        description,
                        self._task_priority_for_risk(incident.risk_level),
                        assignee_ref["id"],
                        actor["id"],
                        department_id,
                        section_id or None,
                        due_at,
                        tags,
                    ),
                ).fetchone()
                if task_row is None:
                    raise RuntimeError("Task insertion returned no row.")

                for collaborator_id in collaborator_ids:
                    cur.execute(
                        """
                        INSERT INTO task_assignees (task_id, user_id, assigned_by_id)
                        VALUES (%s::uuid, %s::uuid, %s::uuid)
                        ON CONFLICT (task_id, user_id)
                        DO UPDATE SET assigned_by_id = EXCLUDED.assigned_by_id, assigned_at = now()
                        """,
                        (task_row["id"], collaborator_id, actor["id"]),
                    )

                cur.execute(
                    """
                    INSERT INTO notifications (
                        id, user_id, role_id, title, message,
                        related_entity, related_id, is_read, created_at
                    ) VALUES (
                        %s::uuid, %s::uuid, NULL, %s, %s,
                        'task', %s::uuid, FALSE, now()
                    )
                    """,
                    (
                        str(uuid4()),
                        assignee_ref["id"],
                        "Nexus response task created",
                        f'{actor["username"] or actor["email"] or "Nexus"} opened "{title}" for incident response.',
                        task_row["id"],
                    ),
                )
            conn.commit()

        return TaskHandoff(
            task_id=task_row["id"],
            incident_id=incident.incident_id,
            title=title,
            description=description,
            created_at=task_row["created_at"],
            created_by=actor["username"] or actor["email"] or requested_by,
            route_hint=f"/tasks?task={task_row['id']}",
            status="created",
            tags=tags,
            external_task_id=task_row["id"],
            assigned_to=assignee_ref["username"] or assignee_ref["email"] or assignee or requested_by,
            task_status="ACTIVE",
        )

    def fetch_network_sentinel_evidence(self, service_map: dict[str, str]) -> dict[str, object]:
        if not self._use_postgres or not service_map:
            return {"snapshots": [], "events": []}

        uuid_values = [UUID(value) for value in service_map.values()]
        snapshot_query = """
        WITH active_outage AS (
            SELECT DISTINCT ON (service_id)
                id::text AS outage_id,
                service_id,
                started_at,
                COALESCE(duration_seconds, EXTRACT(EPOCH FROM (now() - started_at))::int) AS duration_seconds,
                cause::text AS cause,
                details
            FROM network_service_outages
            WHERE ended_at IS NULL
            ORDER BY service_id, started_at DESC
        )
        SELECT
            s.id::text AS network_service_id,
            s.name,
            s.address,
            s.port,
            s.environment,
            s.group_name,
            s.owner_team,
            s.tags,
            st.last_checked_at,
            COALESCE(st.overall_status::text, 'UNKNOWN') AS overall_status,
            st.reason,
            st.consecutive_failures,
            st.icmp_latency_ms,
            st.tcp_latency_ms,
            ao.outage_id,
            ao.started_at AS outage_started_at,
            ao.duration_seconds AS outage_duration_seconds,
            ao.cause AS outage_cause,
            ao.details AS outage_details
        FROM network_services s
        LEFT JOIN network_service_status st ON st.service_id = s.id
        LEFT JOIN active_outage ao ON ao.service_id = s.id
        WHERE s.id = ANY(%s::uuid[])
          AND s.deleted_at IS NULL
        """
        event_query = """
        SELECT
            e.id::text AS event_id,
            e.service_id::text AS network_service_id,
            COALESCE(e.service_name, s.name) AS service_name,
            e.category,
            e.event_type,
            e.severity,
            e.title,
            e.summary,
            e.details,
            e.created_at
        FROM network_service_events e
        LEFT JOIN network_services s ON s.id = e.service_id
        WHERE e.service_id = ANY(%s::uuid[])
          AND e.created_at >= now() - interval '8 hours'
        ORDER BY e.created_at DESC
        LIMIT 500
        """

        with self._connect() as conn:
            with conn.cursor() as cur:
                snapshots = list(cur.execute(snapshot_query, (uuid_values,)).fetchall())
                events = list(cur.execute(event_query, (uuid_values,)).fetchall())

        inverse_map = {external_id: service_id for service_id, external_id in service_map.items()}
        for item in snapshots:
            item["service_id"] = inverse_map.get(item["network_service_id"])
        for item in events:
            item["service_id"] = inverse_map.get(item["network_service_id"])

        return {"snapshots": snapshots, "events": events}

    def list_managed_sops(self, *, include_deprecated: bool = True) -> list[ManagedSop]:
        if not self._use_postgres:
            return []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    rows = cur.execute(
                        """
                        SELECT payload
                        FROM nexus_sop_registry
                        WHERE deleted_at IS NULL
                          AND (%s OR status <> 'deprecated')
                        ORDER BY updated_at DESC, sop_id ASC
                        """,
                        (include_deprecated,),
                    ).fetchall()
        except psycopg.errors.UndefinedTable:
            logger.warning("nexus_sop_registry is missing. Apply 2026_05_add_nexus_sop_registry.sql.")
            return []
        return [ManagedSop.model_validate(row["payload"]) for row in rows]

    def get_managed_sop(self, sop_id: str) -> ManagedSop | None:
        if not self._use_postgres:
            return None
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    row = cur.execute(
                        """
                        SELECT payload
                        FROM nexus_sop_registry
                        WHERE sop_id = %s
                          AND deleted_at IS NULL
                        """,
                        (sop_id,),
                    ).fetchone()
        except psycopg.errors.UndefinedTable:
            logger.warning("nexus_sop_registry is missing. Apply 2026_05_add_nexus_sop_registry.sql.")
            return None
        return ManagedSop.model_validate(row["payload"]) if row else None

    def upsert_managed_sop(self, sop: ManagedSop) -> ManagedSop:
        if not self._use_postgres:
            raise RuntimeError("DATABASE_URL is required for managed Nexus SOPs.")
        payload = sop.model_dump(mode="json")
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO nexus_sop_registry (
                            sop_id, title, class_code, severity, status, version, updated_at, payload
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (sop_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            class_code = EXCLUDED.class_code,
                            severity = EXCLUDED.severity,
                            status = EXCLUDED.status,
                            version = EXCLUDED.version,
                            updated_at = EXCLUDED.updated_at,
                            payload = EXCLUDED.payload,
                            deleted_at = NULL
                        """,
                        (
                            sop.sop_id,
                            sop.title,
                            sop.class_code,
                            sop.severity,
                            sop.status,
                            sop.version,
                            sop.updated_at,
                            json.dumps(payload),
                        ),
                    )
                conn.commit()
        except psycopg.errors.UndefinedTable as exc:
            raise RuntimeError("Nexus SOP registry migration is missing. Apply 2026_05_add_nexus_sop_registry.sql.") from exc
        return sop

    def delete_managed_sop(self, sop_id: str, deleted_by: str) -> None:
        if not self._use_postgres:
            raise RuntimeError("DATABASE_URL is required for managed Nexus SOPs.")
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE nexus_sop_registry
                        SET deleted_at = now(),
                            payload = jsonb_set(
                                jsonb_set(payload, '{status}', '"deprecated"'::jsonb, true),
                                '{updated_by}', to_jsonb(%s::text), true
                            )
                        WHERE sop_id = %s
                        """,
                        (deleted_by, sop_id),
                    )
                    if cur.rowcount == 0:
                        raise KeyError(f"Unknown Nexus SOP {sop_id}")
                conn.commit()
        except psycopg.errors.UndefinedTable as exc:
            raise RuntimeError("Nexus SOP registry migration is missing. Apply 2026_05_add_nexus_sop_registry.sql.") from exc

    def _connect(self):
        if not self._dsn:
            raise RuntimeError("DATABASE_URL is required for Sentinel Nexus database access.")
        return psycopg.connect(self._dsn, row_factory=dict_row)

    def schema_status(self) -> dict[str, object]:
        if not self._use_postgres:
            return {
                "database_required": settings.NEXUS_REQUIRE_DATABASE,
                "database_connected": False,
                "schema_ready": False,
                "missing_tables": list(self.REQUIRED_TABLES),
                "local_state_enabled": self._allow_local_state,
            }
        try:
            missing = self._missing_schema_tables()
            return {
                "database_required": settings.NEXUS_REQUIRE_DATABASE,
                "database_connected": True,
                "schema_ready": not missing,
                "missing_tables": missing,
                "local_state_enabled": self._allow_local_state,
            }
        except Exception as exc:
            return {
                "database_required": settings.NEXUS_REQUIRE_DATABASE,
                "database_connected": False,
                "schema_ready": False,
                "missing_tables": list(self.REQUIRED_TABLES),
                "local_state_enabled": self._allow_local_state,
                "error": str(exc),
            }

    def _verify_schema(self) -> None:
        missing = self._missing_schema_tables()
        if missing:
            raise RuntimeError(
                "Sentinel Nexus database schema is missing tables: "
                f"{', '.join(missing)}. Apply SentinelOps-beta/app/db/migrations/2026_04_add_sentinel_nexus.sql "
                "and SentinelOps-beta/app/db/migrations/2026_05_add_nexus_business_flows.sql."
            )

    def _missing_schema_tables(self) -> list[str]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                rows = cur.execute(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                      AND table_name = ANY(%s::text[])
                    """,
                    (list(self.REQUIRED_TABLES),),
                ).fetchall()
        present = {row["table_name"] for row in rows}
        return [table for table in self.REQUIRED_TABLES if table not in present]

    def _load_from_postgres(self) -> NexusState:
        with self._connect() as conn:
            with conn.cursor() as cur:
                services = [row["payload"] for row in cur.execute("SELECT payload FROM service_catalog ORDER BY service_name")]
                clusters = [row["payload"] for row in cur.execute("SELECT payload FROM dependency_cluster ORDER BY cluster_name")]
                flows = [row["payload"] for row in cur.execute("SELECT payload FROM business_flow ORDER BY flow_name")]
                edges = [row["payload"] for row in cur.execute("SELECT payload FROM dependency_edge ORDER BY edge_id")]
                signals = [
                    row["payload"]
                    for row in cur.execute(
                        "SELECT payload FROM signal_event ORDER BY timestamp DESC LIMIT %s",
                        (self.SIGNAL_RETENTION,),
                    )
                ]
                changes = [
                    row["payload"]
                    for row in cur.execute(
                        "SELECT payload FROM change_event ORDER BY timestamp DESC LIMIT %s",
                        (self.CHANGE_RETENTION,),
                    )
                ]
                incidents = [row["payload"] for row in cur.execute("SELECT payload FROM incident ORDER BY start_time DESC")]
                diagnostics = [row["payload"] for row in cur.execute("SELECT payload FROM diagnostic_bundle ORDER BY requested_at DESC")]
                actions = [row["payload"] for row in cur.execute("SELECT payload FROM action_execution ORDER BY requested_at DESC")]
                feedback = [row["payload"] for row in cur.execute("SELECT payload FROM operator_feedback ORDER BY created_at DESC")]
                tasks = [row["payload"] for row in cur.execute("SELECT payload FROM task_handoff ORDER BY created_at DESC")]
                heartbeats = [
                    row["payload"]
                    for row in cur.execute(
                        "SELECT payload FROM agent_heartbeat ORDER BY timestamp DESC LIMIT %s",
                        (self.HEARTBEAT_RETENTION,),
                    )
                ]
                meta_row = cur.execute(
                    "SELECT payload FROM nexus_meta WHERE meta_key = 'fabric_summary'"
                ).fetchone()

        return self._state_from_payload(
            {
                "services": services,
                "clusters": clusters,
                "business_flows": flows,
                "dependency_edges": edges,
                "signals": list(reversed(signals)),
                "change_events": list(reversed(changes)),
                "incidents": incidents,
                "diagnostics": diagnostics,
                "action_executions": actions,
                "operator_feedback": feedback,
                "task_handoffs": tasks,
                "agent_heartbeats": heartbeats,
                "fabric_summary": meta_row["payload"] if meta_row else {},
            },
            persist_on_migrate=True,
        )

    def _state_from_payload(self, payload: dict[str, object], *, persist_on_migrate: bool) -> NexusState:
        normalized_payload, changed = self._normalize_state_payload(payload)
        state = NexusState.model_validate(normalized_payload)
        if changed and persist_on_migrate:
            logger.info("Migrated legacy Sentinel Nexus state into the current schema.")
            self.persist_state(state)
        return state

    def _normalize_state_payload(self, payload: dict[str, object] | None) -> tuple[dict[str, object], bool]:
        normalized = deepcopy(payload or {})
        changed = False

        incidents = normalized.get("incidents")
        if not isinstance(incidents, list):
            incidents = []
            normalized["incidents"] = incidents
            changed = True

        incident_id_map: dict[str, str] = {}
        for incident in incidents:
            if not isinstance(incident, dict):
                continue
            affected_services = [
                str(item).strip()
                for item in incident.get("affected_services", [])
                if str(item).strip()
            ]
            incident_key = str(incident.get("incident_key") or "").strip()
            if not incident_key:
                seed = "|".join(sorted(affected_services)) or str(incident.get("incident_id") or uuid4())
                incident_key = f"incident-key:{seed}"
                incident["incident_key"] = incident_key
                changed = True

            legacy_incident_id = str(incident.get("incident_id") or "").strip()
            current_incident_id = legacy_incident_id
            if not self._is_uuid_string(legacy_incident_id):
                current_incident_id = str(uuid5(NAMESPACE_URL, f"sentinel-nexus:{incident_key}"))
                incident["incident_id"] = current_incident_id
                changed = True
            if legacy_incident_id:
                incident_id_map[legacy_incident_id] = current_incident_id
            incident_id_map[current_incident_id] = current_incident_id

            incident.setdefault("cluster_ids", [])
            incident.setdefault("data_sources", [])
            incident.setdefault("correlation_version", "nexus-v2")

            for collection_name in ("linked_tasks", "diagnostics", "action_executions"):
                collection = incident.get(collection_name)
                if not isinstance(collection, list):
                    continue
                for item in collection:
                    if isinstance(item, dict) and item.get("incident_id") != current_incident_id:
                        item["incident_id"] = current_incident_id
                        changed = True

            verdict = incident.get("verdict")
            if isinstance(verdict, dict) and verdict.get("incident_id") != current_incident_id:
                verdict["incident_id"] = current_incident_id
                changed = True

        for collection_name in ("diagnostics", "action_executions", "operator_feedback", "task_handoffs"):
            collection = normalized.get(collection_name)
            if not isinstance(collection, list):
                continue
            for item in collection:
                if not isinstance(item, dict):
                    continue
                item_incident_id = str(item.get("incident_id") or "").strip()
                mapped_incident_id = incident_id_map.get(item_incident_id)
                if mapped_incident_id and mapped_incident_id != item_incident_id:
                    item["incident_id"] = mapped_incident_id
                    changed = True

        return normalized, changed

    def _is_uuid_string(self, value: str | None) -> bool:
        if not value:
            return False
        try:
            UUID(str(value))
        except (TypeError, ValueError):
            return False
        return True

    def _persist_to_postgres(self, state: NexusState) -> None:
        payload = state.model_dump(mode="json")
        service_ids = {service["service_id"] for service in payload["services"]}
        cluster_ids = {cluster["cluster_id"] for cluster in payload["clusters"]}
        flow_ids = {flow["flow_id"] for flow in payload["business_flows"]}
        edge_ids = {
            edge.get("edge_id") or self._edge_id_for(edge)
            for edge in payload["dependency_edges"]
        }

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO nexus_meta (meta_key, payload, updated_at)
                    VALUES ('fabric_summary', %s::jsonb, now())
                    ON CONFLICT (meta_key) DO UPDATE SET
                        payload = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    (json.dumps(payload["fabric_summary"]),),
                )

                for service in payload["services"]:
                    cur.execute(
                        """
                        INSERT INTO service_catalog (service_id, service_name, environment, service_type, payload, updated_at)
                        VALUES (%s, %s, %s, %s, %s::jsonb, now())
                        ON CONFLICT (service_id) DO UPDATE SET
                            service_name = EXCLUDED.service_name,
                            environment = EXCLUDED.environment,
                            service_type = EXCLUDED.service_type,
                            payload = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (
                            service["service_id"],
                            service["service_name"],
                            service["environment"],
                            service["service_type"],
                            json.dumps(service),
                        ),
                    )

                if service_ids:
                    cur.execute(
                        "DELETE FROM service_catalog WHERE service_id <> ALL(%s::text[])",
                        (list(service_ids),),
                    )
                else:
                    cur.execute("DELETE FROM service_catalog")

                for cluster in payload["clusters"]:
                    cur.execute(
                        """
                        INSERT INTO dependency_cluster (cluster_id, cluster_name, environment, payload, updated_at)
                        VALUES (%s, %s, %s, %s::jsonb, now())
                        ON CONFLICT (cluster_id) DO UPDATE SET
                            cluster_name = EXCLUDED.cluster_name,
                            environment = EXCLUDED.environment,
                            payload = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (
                            cluster["cluster_id"],
                            cluster["cluster_name"],
                            cluster["environment"],
                            json.dumps(cluster),
                        ),
                    )

                if cluster_ids:
                    cur.execute(
                        "DELETE FROM dependency_cluster WHERE cluster_id <> ALL(%s::text[])",
                        (list(cluster_ids),),
                    )
                else:
                    cur.execute("DELETE FROM dependency_cluster")

                for flow in payload["business_flows"]:
                    cur.execute(
                        """
                        INSERT INTO business_flow (flow_id, flow_name, environment, criticality, payload, updated_at)
                        VALUES (%s, %s, %s, %s, %s::jsonb, now())
                        ON CONFLICT (flow_id) DO UPDATE SET
                            flow_name = EXCLUDED.flow_name,
                            environment = EXCLUDED.environment,
                            criticality = EXCLUDED.criticality,
                            payload = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (
                            flow["flow_id"],
                            flow["flow_name"],
                            flow["environment"],
                            flow["criticality"],
                            json.dumps(flow),
                        ),
                    )
                    cur.execute("DELETE FROM business_flow_step WHERE flow_id = %s", (flow["flow_id"],))
                    for index, step in enumerate(flow.get("steps", []), start=1):
                        step_id = step.get("step_id") or f"{flow['flow_id']}:{step.get('step_order') or index}:{step['service_id']}"
                        cur.execute(
                            """
                            INSERT INTO business_flow_step (
                                step_id, flow_id, service_id, step_order, service_role, required, payload, updated_at
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, now())
                            ON CONFLICT (step_id) DO UPDATE SET
                                flow_id = EXCLUDED.flow_id,
                                service_id = EXCLUDED.service_id,
                                step_order = EXCLUDED.step_order,
                                service_role = EXCLUDED.service_role,
                                required = EXCLUDED.required,
                                payload = EXCLUDED.payload,
                                updated_at = now()
                            """,
                            (
                                step_id,
                                flow["flow_id"],
                                step["service_id"],
                                step.get("step_order") or index,
                                step["service_role"],
                                step.get("required", True),
                                json.dumps({**step, "step_id": step_id}),
                            ),
                        )

                if flow_ids:
                    cur.execute(
                        "DELETE FROM business_flow WHERE flow_id <> ALL(%s::text[])",
                        (list(flow_ids),),
                    )
                    cur.execute(
                        "DELETE FROM business_flow_step WHERE flow_id <> ALL(%s::text[])",
                        (list(flow_ids),),
                    )
                else:
                    cur.execute("DELETE FROM business_flow_step")
                    cur.execute("DELETE FROM business_flow")

                for edge in payload["dependency_edges"]:
                    edge_id = edge.get("edge_id") or self._edge_id_for(edge)
                    edge["edge_id"] = edge_id
                    cur.execute(
                        """
                        INSERT INTO dependency_edge (
                            edge_id, cluster_id, from_service_id, to_service_id, dependency_type,
                            dependency_purpose, dependency_scope, business_flow_ids,
                            valid_failure_domains, expected_evidence, payload, updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::text[], %s::text[], %s::text[], %s::jsonb, now())
                        ON CONFLICT (edge_id) DO UPDATE SET
                            cluster_id = EXCLUDED.cluster_id,
                            from_service_id = EXCLUDED.from_service_id,
                            to_service_id = EXCLUDED.to_service_id,
                            dependency_type = EXCLUDED.dependency_type,
                            dependency_purpose = EXCLUDED.dependency_purpose,
                            dependency_scope = EXCLUDED.dependency_scope,
                            business_flow_ids = EXCLUDED.business_flow_ids,
                            valid_failure_domains = EXCLUDED.valid_failure_domains,
                            expected_evidence = EXCLUDED.expected_evidence,
                            payload = EXCLUDED.payload,
                            updated_at = now()
                        """,
                        (
                            edge_id,
                            edge.get("cluster_id"),
                            edge["from_service_id"],
                            edge["to_service_id"],
                            edge["dependency_type"],
                            edge.get("dependency_purpose"),
                            edge.get("dependency_scope") or "global",
                            edge.get("business_flow_ids") or [],
                            edge.get("valid_failure_domains") or [],
                            edge.get("expected_evidence") or [],
                            json.dumps(edge),
                        ),
                    )

                if edge_ids:
                    cur.execute(
                        "DELETE FROM dependency_edge WHERE edge_id <> ALL(%s::text[])",
                        (list(edge_ids),),
                    )
                else:
                    cur.execute("DELETE FROM dependency_edge")

                for signal in payload["signals"]:
                    signal_flow_id = signal.get("business_flow_id")
                    if signal_flow_id not in flow_ids:
                        signal_flow_id = None
                    signal_payload = {**signal, "business_flow_id": signal_flow_id}
                    cur.execute(
                        """
                        INSERT INTO signal_event (
                            signal_id, service_id, signal_type, severity, timestamp,
                            vantage_point, observation_layer, failure_domain_hint, business_flow_id, payload
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (signal_id) DO UPDATE SET
                            severity = EXCLUDED.severity,
                            timestamp = EXCLUDED.timestamp,
                            vantage_point = EXCLUDED.vantage_point,
                            observation_layer = EXCLUDED.observation_layer,
                            failure_domain_hint = EXCLUDED.failure_domain_hint,
                            business_flow_id = EXCLUDED.business_flow_id,
                            payload = EXCLUDED.payload
                        """,
                        (
                            signal["signal_id"],
                            signal["service_id"],
                            signal["signal_type"],
                            signal["severity"],
                            signal["timestamp"],
                            signal.get("vantage_point"),
                            signal.get("observation_layer"),
                            signal.get("failure_domain_hint"),
                            signal_flow_id,
                            json.dumps(signal_payload),
                        ),
                    )

                cur.execute(
                    """
                    DELETE FROM signal_event
                    WHERE signal_id IN (
                        SELECT signal_id
                        FROM (
                            SELECT signal_id, row_number() OVER (ORDER BY timestamp DESC) AS rn
                            FROM signal_event
                        ) ranked
                        WHERE ranked.rn > %s
                    )
                    """,
                    (self.SIGNAL_RETENTION,),
                )

                for change in payload["change_events"]:
                    cur.execute(
                        """
                        INSERT INTO change_event (change_id, service_id, change_type, timestamp, payload)
                        VALUES (%s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (change_id) DO UPDATE SET
                            timestamp = EXCLUDED.timestamp,
                            payload = EXCLUDED.payload
                        """,
                        (
                            change["change_id"],
                            change["service_id"],
                            change["change_type"],
                            change["timestamp"],
                            json.dumps(change),
                        ),
                    )

                cur.execute(
                    """
                    DELETE FROM change_event
                    WHERE change_id IN (
                        SELECT change_id
                        FROM (
                            SELECT change_id, row_number() OVER (ORDER BY timestamp DESC) AS rn
                            FROM change_event
                        ) ranked
                        WHERE ranked.rn > %s
                    )
                    """,
                    (self.CHANGE_RETENTION,),
                )

                cur.execute("DELETE FROM incident_service")
                cur.execute("DELETE FROM incident")
                for incident in payload["incidents"]:
                    incident_flow_id = incident.get("primary_business_flow_id")
                    if incident_flow_id not in flow_ids:
                        incident_flow_id = None
                    incident_payload = {**incident, "primary_business_flow_id": incident_flow_id}
                    cur.execute(
                        """
                        INSERT INTO incident (
                            incident_id, incident_key, status, start_time,
                            primary_business_flow_id, failure_domain, payload
                        )
                        VALUES (%s::uuid, %s, %s, %s, %s, %s, %s::jsonb)
                        """,
                        (
                            incident["incident_id"],
                            incident["incident_key"],
                            incident["status"],
                            incident["start_time"],
                            incident_flow_id,
                            incident.get("failure_domain"),
                            json.dumps(incident_payload),
                        ),
                    )
                    for service_id in incident["affected_services"]:
                        role = "suspected_root" if service_id == incident.get("suspected_root_service") else "affected"
                        key = f"{incident['incident_id']}:{service_id}"
                        cur.execute(
                            """
                            INSERT INTO incident_service (incident_service_key, incident_id, service_id, role, payload)
                            VALUES (%s, %s::uuid, %s, %s, %s::jsonb)
                            """,
                            (
                                key,
                                incident["incident_id"],
                                service_id,
                                role,
                                json.dumps(
                                    {
                                        "incident_id": incident["incident_id"],
                                        "service_id": service_id,
                                        "role": role,
                                    }
                                ),
                            ),
                        )

                for task in payload["task_handoffs"]:
                    cur.execute(
                        """
                        INSERT INTO task_handoff (task_id, incident_id, created_at, payload)
                        VALUES (%s, %s::uuid, %s, %s::jsonb)
                        ON CONFLICT (task_id) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            created_at = EXCLUDED.created_at
                        """,
                        (
                            task["task_id"],
                            task["incident_id"],
                            task["created_at"],
                            json.dumps(task),
                        ),
                    )

                for feedback in payload["operator_feedback"]:
                    cur.execute(
                        """
                        INSERT INTO operator_feedback (feedback_id, incident_id, feedback_type, created_at, payload)
                        VALUES (%s, %s::uuid, %s, %s, %s::jsonb)
                        ON CONFLICT (feedback_id) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            created_at = EXCLUDED.created_at
                        """,
                        (
                            feedback["feedback_id"],
                            feedback["incident_id"],
                            feedback["feedback_type"],
                            feedback["created_at"],
                            json.dumps(feedback),
                        ),
                    )

                for bundle in payload["diagnostics"]:
                    cur.execute(
                        """
                        INSERT INTO diagnostic_bundle (bundle_id, incident_id, service_id, requested_at, payload)
                        VALUES (%s, %s::uuid, %s, %s, %s::jsonb)
                        ON CONFLICT (bundle_id) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            requested_at = EXCLUDED.requested_at
                        """,
                        (
                            bundle["bundle_id"],
                            bundle["incident_id"],
                            bundle["service_id"],
                            bundle["requested_at"],
                            json.dumps(bundle),
                        ),
                    )

                for action in payload["action_executions"]:
                    cur.execute(
                        """
                        INSERT INTO action_execution (action_execution_id, incident_id, service_id, action_type, requested_at, payload)
                        VALUES (%s, %s::uuid, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (action_execution_id) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            requested_at = EXCLUDED.requested_at
                        """,
                        (
                            action["action_execution_id"],
                            action["incident_id"],
                            action["service_id"],
                            action["action_type"],
                            action["requested_at"],
                            json.dumps(action),
                        ),
                    )

                for heartbeat in payload["agent_heartbeats"]:
                    key = f"{heartbeat['agent_id']}:{heartbeat['timestamp']}"
                    cur.execute(
                        """
                        INSERT INTO agent_heartbeat (heartbeat_key, agent_id, service_id, timestamp, payload)
                        VALUES (%s, %s, %s, %s, %s::jsonb)
                        ON CONFLICT (heartbeat_key) DO UPDATE SET
                            payload = EXCLUDED.payload,
                            timestamp = EXCLUDED.timestamp
                        """,
                        (
                            key,
                            heartbeat["agent_id"],
                            heartbeat["service_id"],
                            heartbeat["timestamp"],
                            json.dumps(heartbeat),
                        ),
                    )

                cur.execute(
                    """
                    DELETE FROM agent_heartbeat
                    WHERE heartbeat_key IN (
                        SELECT heartbeat_key
                        FROM (
                            SELECT heartbeat_key, row_number() OVER (ORDER BY timestamp DESC) AS rn
                            FROM agent_heartbeat
                        ) ranked
                        WHERE ranked.rn > %s
                    )
                    """,
                    (self.HEARTBEAT_RETENTION,),
                )
            conn.commit()

        logger.info("Persisted Sentinel Nexus state to PostgreSQL.")

    def _edge_id_for(self, edge: dict[str, object]) -> str:
        cluster_id = edge.get("cluster_id") or "global"
        return f"{cluster_id}:{edge['from_service_id']}->{edge['to_service_id']}:{edge['dependency_type']}"

    def _task_priority_for_risk(self, risk_level: str) -> str:
        return {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }.get(risk_level.upper(), "MEDIUM")

    def _task_description(self, incident: NexusIncident, notes: str | None) -> str:
        affected = ", ".join(incident.affected_services) or "No affected services recorded"
        sources = ", ".join(incident.data_sources) or "nexus"
        root_cause = incident.suspected_root_service_name or incident.suspected_root_service or "Pending"
        flow = incident.primary_business_flow_name or incident.primary_business_flow_id or "Unassigned"
        evidence = incident.evidence_timeline[:3]
        evidence_lines = "\n".join(
            f"- {item.evidence_class}: {item.summary}"
            for item in evidence
            if item.summary
        ) or "- No evidence timeline has been attached yet."
        recommendations = incident.recommendations[:3]
        recommendation_lines = "\n".join(
            f"- {item.action_type.replace('_', ' ').title()}: {item.justification}"
            for item in recommendations
            if item.justification
        ) or "- Review the Nexus incident command view and request diagnostics if needed."
        return (
            "Sentinel Nexus opened this response task from a correlated incident.\n\n"
            f"Situation:\n{incident.summary}\n\n"
            f"Incident key: {incident.incident_key}\n"
            f"Risk level: {incident.risk_level}\n"
            f"Business flow: {flow}\n"
            f"Root cause candidate: {root_cause}\n"
            f"Confidence: {incident.predicted_confidence:.2f}\n"
            f"Affected services: {affected}\n"
            f"Data sources: {sources}\n\n"
            f"Evidence snapshot:\n{evidence_lines}\n\n"
            f"Recommended response path:\n{recommendation_lines}\n\n"
            f"Operator notes: {notes or 'No additional notes.'}\n\n"
            "Use this task as the shared response thread. Join the task before taking action so comments, "
            "attachments, and status changes are attributed to the active responders."
        )
