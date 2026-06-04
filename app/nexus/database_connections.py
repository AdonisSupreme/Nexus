"""Connection-string helpers for Nexus database fabric and rollover workflows."""

from __future__ import annotations

import re
from urllib.parse import urlparse


SID_STYLE_RE = re.compile(r"^(?P<host>[^:/]+):(?P<port>\d+):(?P<sid>[^/]+)$")


def _metadata(source: object) -> dict[str, object]:
    value = getattr(source, "metadata", None)
    return value if isinstance(value, dict) else {}


def _value(source: object, *names: str) -> str:
    metadata = _metadata(source)
    for name in names:
        value = getattr(source, name, None)
        if value not in (None, ""):
            return str(value).strip()
        value = metadata.get(name)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _int_value(source: object, *names: str, default: int) -> int:
    raw = _value(source, *names)
    if not raw:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def oracle_config_dir_from_datagrip(source: object) -> str | None:
    value = _value(source, "config_dir", "tns_admin", "oracle_config_dir")
    return value or None


def oracle_dsn_from_datagrip(source: object) -> str:
    """Resolve Oracle DataGrip-style fields into a python-oracledb DSN.

    Supported shapes:
    - JDBC URL: jdbc:oracle:thin:@//host:port/service
    - JDBC SID URL: jdbc:oracle:thin:@host:port:SID
    - Host + Port + Service Name
    - Host + Port + SID/Instance/Database Name
    - TNS alias / full connect descriptor from DSN
    """

    jdbc_url = _value(source, "jdbc_url", "url", "connection_url")
    if jdbc_url:
        return _oracle_jdbc_to_oracledb_dsn(jdbc_url)

    host = _value(source, "host", "hostname", "server")
    port = _int_value(source, "port", default=1521)
    service_name = _value(source, "service_name", "oracle_service_name")
    if host and service_name:
        return f"{host}:{port}/{service_name}"

    sid = _value(source, "sid", "instance_name", "database_name")
    if host and sid:
        return oracle_sid_descriptor(host, port, sid)

    dsn = _value(source, "dsn", "tns_alias")
    if dsn:
        return _oracle_jdbc_to_oracledb_dsn(dsn)

    raise ValueError(
        "Oracle connection requires DataGrip Host + Port + SID/Service, a JDBC URL, "
        "or a TNS alias with an Oracle config directory."
    )


def postgres_dsn_from_datagrip(source: object) -> str:
    """Resolve PostgreSQL DataGrip-style fields into a libpq connection string."""

    jdbc_url = _value(source, "jdbc_url", "url", "connection_url")
    if jdbc_url:
        return _postgres_jdbc_to_libpq_dsn(jdbc_url)
    host = _value(source, "host", "hostname", "server", "host_group")
    port = _int_value(source, "port", default=5432)
    database = _value(source, "database_name", "database", "service_name")
    username = _value(source, "username", "user")
    if not host or not database:
        raise ValueError("PostgreSQL connection requires DataGrip Host, Port, and Database fields.")
    parts = [f"host={host}", f"port={port}", f"dbname={database}"]
    if username:
        parts.append(f"user={username}")
    return " ".join(parts)


def oracle_sid_descriptor(host: str, port: int, sid: str) -> str:
    return (
        "(DESCRIPTION="
        f"(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port}))"
        f"(CONNECT_DATA=(SID={sid}))"
        ")"
    )


def _oracle_jdbc_to_oracledb_dsn(value: str) -> str:
    dsn = value.strip()
    prefix = "jdbc:oracle:thin:@"
    if dsn.lower().startswith(prefix):
        dsn = dsn[len(prefix) :]
    if dsn.startswith("//"):
        dsn = dsn[2:]
    match = SID_STYLE_RE.match(dsn)
    if match:
        return oracle_sid_descriptor(match.group("host"), int(match.group("port")), match.group("sid"))
    return dsn


def _postgres_jdbc_to_libpq_dsn(value: str) -> str:
    dsn = value.strip()
    prefix = "jdbc:postgresql://"
    if dsn.lower().startswith(prefix):
        dsn = "postgresql://" + dsn[len(prefix) :]
    parsed = urlparse(dsn)
    if parsed.scheme in {"postgresql", "postgres"} and parsed.hostname and parsed.path.strip("/"):
        parts = [
            f"host={parsed.hostname}",
            f"port={parsed.port or 5432}",
            f"dbname={parsed.path.strip('/')}",
        ]
        if parsed.username:
            parts.append(f"user={parsed.username}")
        return " ".join(parts)
    return dsn
