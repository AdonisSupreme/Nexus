"""Connection-test gateway for Nexus database contracts."""

from __future__ import annotations

from datetime import datetime
from time import perf_counter
from uuid import uuid4

from app.nexus.database_connections import (
    oracle_config_dir_from_datagrip,
    oracle_dsn_from_datagrip,
    postgres_dsn_from_datagrip,
)
from app.nexus.models import DatabaseConnectionTestResult


class NexusDatabaseConnectionTester:
    """Runs non-mutating database connection probes for fabric and rollover contracts."""

    def test_connection(
        self,
        source: object,
        *,
        scope: str,
        target_id: str,
        target_name: str,
        password: str | None,
        tested_by: str | None = None,
    ) -> DatabaseConnectionTestResult:
        platform = self._platform(source)
        started = perf_counter()
        try:
            if platform == "oracle":
                self._test_oracle(source, password=password)
                driver = "python-oracledb"
            elif platform == "postgres":
                self._test_postgres(source, password=password)
                driver = "psycopg"
            else:
                raise ValueError("Database connection test supports Oracle and PostgreSQL profiles.")
            return self._result(
                scope=scope,
                target_id=target_id,
                target_name=target_name,
                platform=platform,
                status="success",
                connected=True,
                tested_by=tested_by,
                latency_ms=self._elapsed_ms(started),
                driver=driver,
                connection_type=self._value(source, "connection_type"),
                message=f"{self._display_platform(platform)} connection succeeded.",
                metadata=self._metadata(source),
            )
        except Exception as exc:
            return self._result(
                scope=scope,
                target_id=target_id,
                target_name=target_name,
                platform=platform or "unknown",
                status="failed",
                connected=False,
                tested_by=tested_by,
                latency_ms=self._elapsed_ms(started),
                driver="python-oracledb" if platform == "oracle" else "psycopg" if platform == "postgres" else None,
                connection_type=self._value(source, "connection_type"),
                message=self._friendly_error(exc),
                metadata=self._metadata(source),
            )

    def _test_oracle(self, source: object, *, password: str | None) -> None:
        username = self._value(source, "username", "user")
        if not username:
            raise ValueError("Oracle username is required for connection test.")
        if password is None:
            raise ValueError("Oracle password is required for connection test.")
        try:
            import oracledb  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("The optional 'oracledb' package is required for Oracle connection tests.") from exc

        connect_kwargs = {
            "user": username,
            "password": password,
            "dsn": oracle_dsn_from_datagrip(source),
        }
        config_dir = oracle_config_dir_from_datagrip(source)
        if config_dir:
            connect_kwargs["config_dir"] = config_dir

        connection = oracledb.connect(**connect_kwargs)
        try:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1 FROM DUAL")
                cursor.fetchone()
            finally:
                self._close_quietly(cursor)
        finally:
            self._close_quietly(connection)

    def _test_postgres(self, source: object, *, password: str | None) -> None:
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("The optional 'psycopg' package is required for PostgreSQL connection tests.") from exc

        connect_kwargs: dict[str, object] = {
            "conninfo": postgres_dsn_from_datagrip(source),
            "connect_timeout": 5,
        }
        if password is not None:
            connect_kwargs["password"] = password
        connection = psycopg.connect(**connect_kwargs)
        try:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            finally:
                self._close_quietly(cursor)
        finally:
            self._close_quietly(connection)

    def _platform(self, source: object) -> str:
        platform = self._value(source, "platform").lower()
        if "oracle" in platform:
            return "oracle"
        if "postgres" in platform:
            return "postgres"
        jdbc_url = self._value(source, "jdbc_url", "url", "connection_url").lower()
        if jdbc_url.startswith("jdbc:oracle:"):
            return "oracle"
        if jdbc_url.startswith(("jdbc:postgresql:", "postgresql://", "postgres://")):
            return "postgres"
        return platform

    def _metadata(self, source: object) -> dict[str, object]:
        metadata = getattr(source, "metadata", None)
        if not isinstance(metadata, dict):
            metadata = {}
        safe_metadata = {
            "connection_shape": self._connection_shape(source),
            "source_service_id": self._value(source, "source_service_id") or None,
        }
        inherited = metadata.get("database_fabric_inherited")
        if inherited is not None:
            safe_metadata["database_fabric_inherited"] = inherited
        return {key: value for key, value in safe_metadata.items() if value not in (None, "")}

    def _connection_shape(self, source: object) -> str:
        if self._value(source, "jdbc_url", "url", "connection_url"):
            return "jdbc_url"
        if self._value(source, "host", "hostname", "server"):
            if self._value(source, "service_name", "oracle_service_name"):
                return "host_service"
            if self._value(source, "sid", "instance_name", "database_name"):
                return "host_sid_or_database"
            return "host"
        if self._value(source, "dsn", "tns_alias"):
            return "tns_alias_or_dsn"
        return "unspecified"

    @staticmethod
    def _value(source: object, *names: str) -> str:
        metadata = getattr(source, "metadata", None)
        metadata = metadata if isinstance(metadata, dict) else {}
        for name in names:
            value = getattr(source, name, None)
            if value not in (None, ""):
                return str(value).strip()
            value = metadata.get(name)
            if value not in (None, ""):
                return str(value).strip()
        return ""

    @staticmethod
    def _display_platform(platform: str) -> str:
        return "PostgreSQL" if platform == "postgres" else "Oracle" if platform == "oracle" else platform or "Database"

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((perf_counter() - started) * 1000))

    @staticmethod
    def _friendly_error(exc: Exception) -> str:
        message = str(exc)
        if "DPY-4027" in message:
            return (
                "Oracle DSN was treated as a TNS alias, but no Oracle config directory was provided. "
                "Use Host, Port, and Service Name/SID, or set Oracle Config Directory to the folder containing tnsnames.ora."
            )
        return message or exc.__class__.__name__

    @staticmethod
    def _result(
        *,
        scope: str,
        target_id: str,
        target_name: str,
        platform: str,
        status: str,
        connected: bool,
        tested_by: str | None,
        latency_ms: int | None,
        driver: str | None,
        connection_type: str | None,
        message: str,
        metadata: dict[str, object],
    ) -> DatabaseConnectionTestResult:
        return DatabaseConnectionTestResult(
            test_id=f"db-test-{uuid4()}",
            scope=scope,  # type: ignore[arg-type]
            target_id=target_id,
            target_name=target_name,
            platform=platform,
            status=status,  # type: ignore[arg-type]
            connected=connected,
            tested_at=datetime.utcnow(),
            tested_by=tested_by,
            latency_ms=latency_ms,
            driver=driver,
            connection_type=connection_type or None,
            message=message,
            metadata=metadata,
        )

    @staticmethod
    def _close_quietly(resource: object) -> None:
        close = getattr(resource, "close", None)
        if callable(close):
            close()
