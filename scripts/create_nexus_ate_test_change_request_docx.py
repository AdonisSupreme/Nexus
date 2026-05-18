from __future__ import annotations

import html
import zipfile
from datetime import datetime, timezone
from pathlib import Path


OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "change_requests" / "Sentinel_Nexus_ATE_Test_Agent_Change_Request.docx"

NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def r(text: str, *, bold: bool = False, color: str | None = None, size: int = 22) -> str:
    props = []
    if bold:
        props.append("<w:b/>")
    if color:
        props.append(f'<w:color w:val="{color}"/>')
    props.append(f'<w:sz w:val="{size}"/>')
    props.append(f'<w:szCs w:val="{size}"/>')
    return f"<w:r><w:rPr>{''.join(props)}</w:rPr><w:t xml:space=\"preserve\">{esc(text)}</w:t></w:r>"


def p(
    text: str = "",
    *,
    style: str | None = None,
    bold: bool = False,
    color: str | None = None,
    size: int = 22,
    before: int = 0,
    after: int = 120,
    spacing: int = 276,
    keep_next: bool = False,
) -> str:
    ppr = []
    if style:
        ppr.append(f'<w:pStyle w:val="{style}"/>')
    ppr.append(f'<w:spacing w:before="{before}" w:after="{after}" w:line="{spacing}" w:lineRule="auto"/>')
    if keep_next:
        ppr.append("<w:keepNext/>")
    return f"<w:p><w:pPr>{''.join(ppr)}</w:pPr>{r(text, bold=bold, color=color, size=size) if text else ''}</w:p>"


def p_runs(runs: list[str], *, style: str | None = None, before: int = 0, after: int = 120, keep_next: bool = False) -> str:
    ppr = []
    if style:
        ppr.append(f'<w:pStyle w:val="{style}"/>')
    ppr.append(f'<w:spacing w:before="{before}" w:after="{after}" w:line="276" w:lineRule="auto"/>')
    if keep_next:
        ppr.append("<w:keepNext/>")
    return f"<w:p><w:pPr>{''.join(ppr)}</w:pPr>{''.join(runs)}</w:p>"


def cell(content: str, *, width: int, fill: str | None = None, color: str = "1F2937") -> str:
    shd = f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>' if fill else ""
    return (
        "<w:tc>"
        f'<w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{shd}'
        '<w:tcMar><w:top w:w="120" w:type="dxa"/><w:left w:w="140" w:type="dxa"/>'
        '<w:bottom w:w="120" w:type="dxa"/><w:right w:w="140" w:type="dxa"/></w:tcMar>'
        "</w:tcPr>"
        f"{content}"
        "</w:tc>"
    )


def table(rows: list[list[str]], widths: list[int], *, header: bool = False) -> str:
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for width in widths)
    body = []
    for idx, row in enumerate(rows):
        fill = "E6F6F4" if header and idx == 0 else None
        cells = [
            cell(
                p(value, bold=header and idx == 0, color="0B3D4A" if header and idx == 0 else "1F2937", after=0),
                width=widths[col],
                fill=fill,
            )
            for col, value in enumerate(row)
        ]
        body.append(f"<w:tr>{''.join(cells)}</w:tr>")
    return (
        "<w:tbl>"
        "<w:tblPr>"
        '<w:tblW w:w="0" w:type="auto"/>'
        '<w:tblBorders><w:top w:val="single" w:sz="4" w:color="B6D9DC"/>'
        '<w:left w:val="single" w:sz="4" w:color="B6D9DC"/>'
        '<w:bottom w:val="single" w:sz="4" w:color="B6D9DC"/>'
        '<w:right w:val="single" w:sz="4" w:color="B6D9DC"/>'
        '<w:insideH w:val="single" w:sz="4" w:color="D8E7EA"/>'
        '<w:insideV w:val="single" w:sz="4" w:color="D8E7EA"/></w:tblBorders>'
        '<w:tblCellMar><w:top w:w="80" w:type="dxa"/><w:left w:w="80" w:type="dxa"/>'
        '<w:bottom w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar>'
        "</w:tblPr>"
        f"<w:tblGrid>{grid}</w:tblGrid>"
        f"{''.join(body)}"
        "</w:tbl>"
    )


def document_xml() -> str:
    today = "14 May 2026"
    body: list[str] = []

    body.append(
        table(
            [
                [
                    "SentinelOps Change Request",
                    f"Environment: ATE-test\nDate: {today}\nRequest type: Controlled pilot deployment",
                ]
            ],
            [5600, 3300],
        ).replace("<w:tblPr>", '<w:tblPr><w:shd w:fill="07111F"/>', 1)
    )
    body.append(p("Deploy Sentinel Nexus Light Agent in ATE-Test", style="Title", color="07111F", size=38, bold=True, before=260, after=80))
    body.append(
        p(
            "Request approval to deploy the Sentinel Nexus light agent on the ATE-test application server for an initial Mobile Banking service pilot. The deployment is low-resource and token-protected. It collects runtime evidence, supports allowlisted diagnostics, and can support human-approved safe restart only after the service is explicitly certified in Nexus. This request also includes read-only MB PostgreSQL observability access so Nexus can distinguish service runtime issues from database dependency pressure without changing application data.",
            size=23,
            after=180,
        )
    )

    body.append(table(
        [
            ["Requested change", "Install and run the Sentinel Nexus light agent in ATE-test."],
            ["Initial monitored service", "txn-mobile-ussd, using its known Java process marker and service log file."],
            ["Restart policy", "The agent supports guarded restart execution, but only after Nexus marks the service restart_ready, restart policy allows it, the service is stateless, cooldown and maintenance gates are clear, and an operator approves the action."],
            ["MB Postgres DB access", "Request read-only monitoring access to the MB PostgreSQL database hosted on the ATE-test server. Nexus uses this only for dependency health and correlation evidence such as connectivity, sessions, locks, pool pressure, slow queries, storage pressure, and SQLSTATE/error patterns."],
            ["Out of scope", "No production deployment, no autonomous restart, no database/cache/queue/auth/shared-dependency restart, no arbitrary shell execution, no application data writes, no DDL/DML changes, and no application configuration change."],
            ["Approval requested", "Permission to install, validate, run one controlled collection cycle, enable diagnostics, grant read-only MB PostgreSQL observability access, and prepare guarded restart capability subject to service certification."],
        ],
        [2500, 6400],
        header=False,
    ))

    body.append(p("1. Why This Change Is Needed", style="Heading1", keep_next=True, before=260))
    body.append(p(
        "Network Sentinel confirms whether a service endpoint is reachable from the monitoring vantage point. That is valuable, but it cannot always tell whether an issue is caused by the service runtime, the host, a database dependency, a downstream integration, or the network path. Sentinel Nexus is the intelligence layer that correlates those perspectives."
    ))
    body.append(p(
        "Database evidence is required because many Mobile Banking symptoms can be caused by PostgreSQL dependency pressure even when the Java process and external network checks look healthy. Nexus needs safe DB-side context to distinguish application failure, database contention, connection-pool exhaustion, lock or blocking issues, slow queries, storage pressure, and dependency latency."
    ))
    body.append(p(
        "The ATE-test environment is the correct place to validate this safely because it mirrors the production setup closely enough to prove the deployment model, resource profile, evidence quality, and Nexus integration before any production request is made."
    ))

    body.append(p("2. What Sentinel Nexus Does", style="Heading1", keep_next=True, before=220))
    body.append(table(
        [
            ["Capability", "Description"],
            ["Incident correlation", "Combines Network Sentinel observations, local runtime evidence, logs, dependency graph context, database signals, and operator actions into one incident view."],
            ["Dependency intelligence", "Understands service clusters, business flows, upstream and downstream services, shared databases, authentication services, and integration paths."],
            ["Database dependency awareness", "Uses read-only database evidence to correlate service symptoms with DB health, locks, session pressure, SQLSTATE errors, slow queries, and storage indicators."],
            ["Root-cause ranking", "Ranks likely causes using timing, topology, evidence diversity, dependency direction, blast radius, and known change context."],
            ["Operator guidance", "Shows evidence, recommended next actions, diagnostic options, task handoff, and verdict capture so decisions are auditable."],
        ],
        [2300, 6600],
        header=True,
    ))

    body.append(p("3. What The Light Agent Does", style="Heading1", keep_next=True, before=220))
    body.append(table(
        [
            ["Function", "How it works"],
            ["Process visibility", "Reads /proc to confirm whether the configured Java service process is running and to capture light CPU, memory, thread, and command-marker evidence."],
            ["Log evidence", "Reads only bounded increments of the exact configured service log. It extracts signatures such as Hikari connection leaks, SQLSTATE errors, Oracle/TNS errors, timeouts, connectivity failures, exceptions, and out-of-memory symptoms."],
            ["Database evidence", "Uses a least-privilege read-only DB role to collect safe PostgreSQL health indicators such as connectivity, active sessions, lock waits, blocking sessions, pool-related pressure, slow-query counters when available, database size/storage signals, and recent SQLSTATE/error patterns."],
            ["Local health evidence", "Optionally calls a configured local health URL if one exists. If no health URL is configured, this step is skipped."],
            ["Nexus reporting", "Sends heartbeat and probe reports to Sentinel Nexus over HTTP using a dedicated agent token. It does not use a frontend user session."],
            ["Guarded restart support", "Accepts restart dispatch only from Nexus, only with the agent token, and only when local service configuration plus Nexus certification and restart policy allow it."],
            ["Failure handling", "If Nexus is temporarily unreachable, it stores only a small bounded local spool and retries later."],
        ],
        [2300, 6600],
        header=True,
    ))

    body.append(p("4. Safety And Security Controls", style="Heading1", keep_next=True, before=220))
    body.append(table(
        [
            ["Control", "Implementation"],
            ["Read-only operation", "The agent observes process metadata, selected log lines, host pressure indicators, and optional local health status. It does not write to or modify the application."],
            ["Human-approved restart only", "The agent can restart only a preconfigured certified service after Nexus policy checks and operator approval. Restart requests cannot provide arbitrary commands."],
            ["No arbitrary shell", "The agent does not execute arbitrary shell commands. Diagnostics and restart use fixed allowlisted command arrays; runtime checks use direct /proc reads and bounded file reads."],
            ["Read-only DB access", "The requested MB Postgres role must be read-only and monitoring-scoped. It must not own schemas, write data, run DDL/DML, restart PostgreSQL, terminate sessions, alter settings, or access sensitive application payloads beyond approved metadata/views."],
            ["DB query limits", "Nexus DB probes use short timeouts, minimal polling, one or few connections, and bounded result sets. Credentials can be revoked independently of application credentials."],
            ["Resource limits", "Recommended systemd limits: Nice=10, CPUQuota=2%, MemoryMax=128M, 30 second poll interval, bounded log bytes and line counts."],
            ["Exact scope", "The first config points only to txn-mobile-ussd process and log path. Additional services require explicit config review."],
            ["Authentication", "Agent API calls require X-Nexus-Agent-Id and X-Nexus-Agent-Token. The token is stored in a root-controlled environment file."],
            ["Restart exclusions", "The policy excludes databases, caches, queues, authentication tiers, infrastructure services, shared dependencies, failovers, and configuration changes."],
            ["Sensitive data control", "The agent extracts signatures and representative evidence only. It is not a bulk log shipper. If sensitive log patterns are identified, masking rules can be added before expanding scope."],
        ],
        [2400, 6500],
        header=True,
    ))

    body.append(p("5. Deployment Plan", style="Heading1", keep_next=True, before=220))
    steps = [
        "1. Confirm the Nexus Core URL reachable from ATE-test and confirm the dedicated Nexus agent token.",
        "2. Create the local agent user and directories for config, state, and logs.",
        "3. Install the Sentinel Nexus light agent package and the txn-mobile-ussd agent config.",
        "4. Run config validation without starting the daemon.",
        "5. Run one controlled collection cycle and verify heartbeat/probe evidence in Nexus.",
        "6. Create or confirm a least-privilege MB Postgres monitoring role for ATE-test.",
        "7. Provide the DB host, port, database name, SSL mode, credential delivery path, allowed source host, and approved monitoring views.",
        "8. If validation succeeds, enable the systemd service with the resource limits above.",
        "9. If restart capability is required, certify the service in Nexus and configure only the exact approved local restart command or systemd unit.",
        "10. Observe for a defined pilot window and confirm no application impact.",
    ]
    for step in steps:
        body.append(p(step, after=60))

    body.append(p("6. Required MB Postgres Details", style="Heading1", keep_next=True, before=220))
    body.append(table(
        [
            ["Item", "Required detail"],
            ["Endpoint", "ATE-test DB host/IP, port, database name, SSL mode, and allowed source host or network."],
            ["Credential", "Dedicated read-only monitoring username, secure credential handover path, expiry or rotation owner, and revocation process."],
            ["Scope", "Approved schemas or database(s), application DB user/pool names, and which MB services use the database."],
            ["Permissions", "Access to safe metadata/views such as pg_stat_activity, pg_stat_database, pg_locks, pg_stat_bgwriter or checkpointer, pg_stat_statements if already approved/available, and pg_catalog or INFORMATION_SCHEMA metadata needed for correlation."],
            ["Limits", "Maximum allowed connections, statement timeout, polling interval expectation, and any query restrictions."],
            ["Baseline", "Normal session range, known maintenance windows, backup windows, expected pool limits, and known safe thresholds."],
        ],
        [2400, 6500],
        header=True,
    ))

    body.append(p("7. Validation Criteria", style="Heading1", keep_next=True, before=220))
    body.append(table(
        [
            ["Check", "Success condition"],
            ["Agent heartbeat", "Nexus shows the ATE-test agent as healthy or degraded only when host pressure is detected."],
            ["Service evidence", "txn-mobile-ussd appears in Nexus with local runtime evidence from the ATE-test host."],
            ["Database access", "Nexus can connect with the read-only role, collect approved health metadata, and is technically blocked from DDL/DML/write operations."],
            ["Log signatures", "Only meaningful signatures or representative error evidence are attached. Normal low-value log noise is not streamed."],
            ["Resource profile", "Agent remains within CPU and memory limits and does not increase service latency or host pressure."],
            ["Security", "Missing or invalid token requests are rejected by Nexus. No frontend session token is used by the agent."],
            ["Restart policy", "No restart can be executed unless Nexus certification, stateless service policy, cooldown, maintenance, confidence, token, and local command gates all pass."],
        ],
        [2400, 6500],
        header=True,
    ))

    body.append(p("8. Rollback Plan", style="Heading1", keep_next=True, before=220))
    body.append(p(
        "Rollback requires no application restart. Stop the agent, revoke the agent token and read-only MB Postgres role, or disable the command server. Existing Nexus records remain audit evidence."
    ))

    body.append(p("9. Approval Request", style="Heading1", keep_next=True, before=220))
    body.append(p(
        "Please approve deployment of the Sentinel Nexus light agent in ATE-test for the initial txn-mobile-ussd pilot under the controls listed above, including read-only MB Postgres dependency evidence. The objective is to validate real local runtime evidence collection, safe database dependency correlation, allowlisted diagnostics, and guarded restart readiness before any production deployment is proposed."
    ))
    body.append(table(
        [
            ["Approver", "Decision", "Name / Signature", "Date"],
            ["Application owner", "Approve / Reject", "", ""],
            ["Infrastructure owner", "Approve / Reject", "", ""],
            ["Security / Risk", "Approve / Reject", "", ""],
        ],
        [2200, 1800, 3200, 1700],
        header=True,
    ))

    sect = (
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" w:header="720" w:footer="720" w:gutter="0"/>'
        "</w:sectPr>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<w:body>{''.join(body)}{sect}</w:body></w:document>"
    )


def styles_xml() -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{NS}">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:qFormat/>
    <w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="22"/><w:color w:val="1F2937"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Title">
    <w:name w:val="Title"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Aptos Display" w:hAnsi="Aptos Display"/><w:b/><w:sz w:val="38"/><w:color w:val="07111F"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr><w:keepNext/><w:spacing w:before="260" w:after="80"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Aptos Display" w:hAnsi="Aptos Display"/><w:b/><w:sz w:val="28"/><w:color w:val="0F766E"/></w:rPr>
  </w:style>
</w:styles>'''


def write_docx() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    created = datetime.now(timezone.utc).isoformat()
    files = {
        "[Content_Types].xml": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>''',
        "_rels/.rels": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>''',
        "word/_rels/document.xml.rels": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
</Relationships>''',
        "word/document.xml": document_xml(),
        "word/styles.xml": styles_xml(),
        "word/settings.xml": f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="{NS}"><w:zoom w:percent="100"/><w:defaultTabStop w:val="720"/></w:settings>''',
        "docProps/core.xml": f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Sentinel Nexus ATE-Test Agent Change Request</dc:title>
  <dc:creator>SentinelOps</dc:creator>
  <cp:lastModifiedBy>SentinelOps</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>
</cp:coreProperties>''',
        "docProps/app.xml": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>SentinelOps</Application>
  <DocSecurity>0</DocSecurity>
  <ScaleCrop>false</ScaleCrop>
</Properties>''',
    }
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as docx:
        for name, content in files.items():
            docx.writestr(name, content)
    print(OUTPUT)


if __name__ == "__main__":
    write_docx()
