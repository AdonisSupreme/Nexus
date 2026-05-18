"""Migrate legacy Sentinel Nexus JSON state into SentinelOps Postgres."""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config.settings import settings  # noqa: E402
from app.nexus.models import NexusState  # noqa: E402
from app.nexus.repository import NexusRepository  # noqa: E402


def _counts(state: NexusState) -> dict[str, int]:
    return {
        "services": len(state.services),
        "clusters": len(state.clusters),
        "business_flows": len(state.business_flows),
        "dependency_edges": len(state.dependency_edges),
        "signals": len(state.signals),
        "change_events": len(state.change_events),
        "incidents": len(state.incidents),
        "diagnostics": len(state.diagnostics),
        "action_executions": len(state.action_executions),
        "operator_feedback": len(state.operator_feedback),
        "task_handoffs": len(state.task_handoffs),
        "agent_heartbeats": len(state.agent_heartbeats),
    }


def _load_source(repository: NexusRepository, source: Path) -> NexusState:
    if not source.exists():
        raise FileNotFoundError(f"Nexus state file not found: {source}")
    import json

    with source.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return repository._state_from_payload(payload, persist_on_migrate=False)


def _merge_by_key(existing_items, incoming_items, key_name: str):
    def item_key(item):
        key = getattr(item, key_name)
        if key or key_name != "edge_id":
            return key
        cluster_id = item.cluster_id or "global"
        return f"{cluster_id}:{item.from_service_id}->{item.to_service_id}:{item.dependency_type}"

    merged = {item_key(item): item for item in existing_items}
    for item in incoming_items:
        merged[item_key(item)] = item
    return list(merged.values())


def _merge_services(existing_state: NexusState, incoming_state: NexusState):
    merged = {service.service_id: service for service in existing_state.services}
    for service in incoming_state.services:
        existing = merged.get(service.service_id)
        if existing and service.metadata.get("catalog_seed_policy") == "fill_if_missing":
            existing.cluster_ids = sorted(set(existing.cluster_ids).union(service.cluster_ids))
            existing.tags = sorted(set(existing.tags).union(service.tags))
            existing.metadata = {**service.metadata, **existing.metadata}
            if not existing.cluster:
                existing.cluster = service.cluster
            merged[service.service_id] = existing
            continue
        merged[service.service_id] = service
    return list(merged.values())


def _merge_states(existing_state: NexusState, incoming_state: NexusState) -> NexusState:
    """Merge catalog/bootstrap data without deleting existing SentinelOps state."""
    return NexusState(
        services=_merge_services(existing_state, incoming_state),
        clusters=_merge_by_key(existing_state.clusters, incoming_state.clusters, "cluster_id"),
        business_flows=_merge_by_key(existing_state.business_flows, incoming_state.business_flows, "flow_id"),
        dependency_edges=_merge_by_key(existing_state.dependency_edges, incoming_state.dependency_edges, "edge_id"),
        signals=_merge_by_key(existing_state.signals, incoming_state.signals, "signal_id"),
        change_events=_merge_by_key(existing_state.change_events, incoming_state.change_events, "change_id"),
        incidents=_merge_by_key(existing_state.incidents, incoming_state.incidents, "incident_id"),
        diagnostics=_merge_by_key(existing_state.diagnostics, incoming_state.diagnostics, "bundle_id"),
        action_executions=_merge_by_key(
            existing_state.action_executions,
            incoming_state.action_executions,
            "action_execution_id",
        ),
        operator_feedback=_merge_by_key(existing_state.operator_feedback, incoming_state.operator_feedback, "feedback_id"),
        task_handoffs=_merge_by_key(existing_state.task_handoffs, incoming_state.task_handoffs, "task_id"),
        agent_heartbeats=_merge_by_key(existing_state.agent_heartbeats, incoming_state.agent_heartbeats, "agent_id"),
        fabric_summary=existing_state.fabric_summary,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=settings.DATA_DIR / "nexus_state.json")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print counts without writing.")
    parser.add_argument("--apply", action="store_true", help="Write validated JSON state into SentinelOps Postgres.")
    parser.add_argument("--verify", action="store_true", help="Load state back from Postgres and print counts.")
    parser.add_argument("--merge", action="store_true", help="Merge source into existing Postgres state instead of replacing it.")
    args = parser.parse_args()

    if not args.dry_run and not args.apply and not args.verify:
        parser.error("Choose one of --dry-run, --apply, or --verify.")

    if not settings.nexus_database_dsn:
        raise RuntimeError("DATABASE_URL is required. Point sentinelops-ai at the SentinelOps database first.")

    repository = NexusRepository()
    repository._verify_schema()

    if args.verify and not args.apply and not args.dry_run:
        state = repository.load_state()
        print("Verified Sentinel Nexus Postgres state:")
        for key, value in _counts(state).items():
            print(f"  {key}: {value}")
        return 0

    incoming_state = _load_source(repository, args.source)
    state = _merge_states(repository.load_state(), incoming_state) if args.merge else incoming_state
    print("Validated legacy Sentinel Nexus state:")
    for key, value in _counts(state).items():
        print(f"  {key}: {value}")

    if args.dry_run:
        print("Dry run complete. No database writes were performed.")
        return 0

    repository._persist_to_postgres(state)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup = args.source.with_name(f"{args.source.stem}.migrated-{timestamp}{args.source.suffix}")
    shutil.copy2(args.source, backup)
    print(f"Migrated Nexus state into SentinelOps Postgres. Backup created at: {backup}")

    if args.verify:
        loaded = repository.load_state()
        print("Post-migration verification:")
        for key, value in _counts(loaded).items():
            print(f"  {key}: {value}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
