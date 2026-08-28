from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "SentinelOps" / "public" / "manual" / "SentinelOps_Funds_Custody_Operating_Guide.pdf"

INK = colors.HexColor("#13242B")
DEEP = colors.HexColor("#0D1A20")
MUTED = colors.HexColor("#5B6970")
LINE = colors.HexColor("#CDD8DB")
WASH = colors.HexColor("#F1F6F5")
GREEN = colors.HexColor("#087F6F")
CYAN = colors.HexColor("#0099BD")
MAGENTA = colors.HexColor("#C72B83")
RED = colors.HexColor("#C62D43")
AMBER = colors.HexColor("#C47708")
WHITE = colors.white


def register_fonts() -> tuple[str, str, str]:
    font_dir = Path("C:/Windows/Fonts")
    regular = font_dir / "segoeui.ttf"
    bold = font_dir / "segoeuib.ttf"
    mono = font_dir / "consola.ttf"
    if regular.exists() and bold.exists() and mono.exists():
        pdfmetrics.registerFont(TTFont("SentinelSans", str(regular)))
        pdfmetrics.registerFont(TTFont("SentinelSansBold", str(bold)))
        pdfmetrics.registerFont(TTFont("SentinelMono", str(mono)))
        return "SentinelSans", "SentinelSansBold", "SentinelMono"
    return "Helvetica", "Helvetica-Bold", "Courier"


SANS, BOLD, MONO = register_fonts()


class CustodyDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=23 * mm,
            bottomMargin=18 * mm,
            title="SentinelOps Funds Custody Operating Guide",
            author="SentinelOps",
            subject="Unauthorized debit clearing operations and custody evidence",
        )
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates(PageTemplate(id="content", frames=[frame], onPage=draw_page_chrome))


def draw_page_chrome(canvas, doc):
    page = canvas.getPageNumber()
    width, height = A4
    canvas.saveState()
    if page == 1:
        canvas.restoreState()
        return
    canvas.setFillColor(DEEP)
    canvas.rect(0, height - 14 * mm, width, 14 * mm, stroke=0, fill=1)
    canvas.setFillColor(GREEN)
    canvas.rect(0, height - 14.7 * mm, width * .56, .7 * mm, stroke=0, fill=1)
    canvas.setFillColor(CYAN)
    canvas.rect(width * .56, height - 14.7 * mm, width * .24, .7 * mm, stroke=0, fill=1)
    canvas.setFillColor(MAGENTA)
    canvas.rect(width * .80, height - 14.7 * mm, width * .20, .7 * mm, stroke=0, fill=1)
    canvas.setFont(BOLD, 8)
    canvas.setFillColor(WHITE)
    canvas.drawString(18 * mm, height - 9.2 * mm, "SENTINELOPS  /  FUNDS CUSTODY")
    canvas.setFont(MONO, 7)
    canvas.setFillColor(colors.HexColor("#A9C0BE"))
    canvas.drawRightString(width - 18 * mm, height - 9.2 * mm, "UNAUTHORIZED DEBIT CLEARING")
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 12 * mm, width - 18 * mm, 12 * mm)
    canvas.setFont(SANS, 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 7.5 * mm, "Operator manual  |  Controlled evidence, approval, mutation, and reversal")
    canvas.setFont(MONO, 7)
    canvas.drawRightString(width - 18 * mm, 7.5 * mm, f"{page:02d}")
    canvas.restoreState()


styles = getSampleStyleSheet()
styles.add(ParagraphStyle("FKicker", fontName=BOLD, fontSize=7.5, leading=10, textColor=CYAN, spaceAfter=4, uppercase=True))
styles.add(ParagraphStyle("FTitle", fontName=MONO, fontSize=23, leading=27, textColor=INK, spaceAfter=9))
styles.add(ParagraphStyle("FH2", fontName=MONO, fontSize=14.5, leading=18, textColor=INK, spaceBefore=8, spaceAfter=7))
styles.add(ParagraphStyle("FH3", fontName=BOLD, fontSize=10.5, leading=14, textColor=INK, spaceBefore=5, spaceAfter=4))
styles.add(ParagraphStyle("FBody", fontName=SANS, fontSize=8.8, leading=13.2, textColor=MUTED, spaceAfter=6))
styles.add(ParagraphStyle("FBodyStrong", fontName=BOLD, fontSize=8.8, leading=13.2, textColor=INK, spaceAfter=5))
styles.add(ParagraphStyle("FTableHeader", fontName=BOLD, fontSize=8.3, leading=11, textColor=WHITE))
styles.add(ParagraphStyle("FSmall", fontName=SANS, fontSize=7.4, leading=10.5, textColor=MUTED))
styles.add(ParagraphStyle("FMono", fontName=MONO, fontSize=7.2, leading=10, textColor=INK))
styles.add(ParagraphStyle("FCenter", parent=styles["FBody"], alignment=TA_CENTER))


def section(kicker: str, title: str, intro: str):
    return [Paragraph(kicker.upper(), styles["FKicker"]), Paragraph(title, styles["FTitle"]), Paragraph(intro, styles["FBody"]), Spacer(1, 4 * mm)]


def rule(title: str, body: str, accent=CYAN):
    table = Table([[Paragraph(title, styles["FBodyStrong"]), Paragraph(body, styles["FBody"])]], colWidths=[43 * mm, 118 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WASH),
        ("BOX", (0, 0), (-1, -1), .6, LINE),
        ("LINEBEFORE", (0, 0), (0, 0), 3, accent),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return KeepTogether([table, Spacer(1, 2.3 * mm)])


def bullet_list(items: list[str], accent=GREEN):
    return ListFlowable(
        [ListItem(Paragraph(item, styles["FBody"]), leftIndent=10) for item in items],
        bulletType="bullet",
        start="circle",
        bulletColor=accent,
        bulletFontName=BOLD,
        bulletFontSize=7,
        leftIndent=15,
        bulletOffsetY=1,
        spaceAfter=5,
    )


def numbered_steps(items: list[tuple[str, str]]):
    rows = []
    for index, (title, body) in enumerate(items, start=1):
        rows.append([
            Paragraph(f"{index:02d}", ParagraphStyle("step", parent=styles["FMono"], textColor=CYAN, fontSize=10)),
            Paragraph(f"<b>{title}</b><br/>{body}", styles["FBody"]),
        ])
    table = Table(rows, colWidths=[14 * mm, 147 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), .5, LINE),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def comparison(headers: list[str], rows: list[list[str]], widths=None):
    data = [[Paragraph(item, styles["FTableHeader"]) for item in headers]]
    data.extend([[Paragraph(item, styles["FSmall"]) for item in row] for row in rows])
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DEEP),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), .45, LINE),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def cover_story():
    width, height = A4
    return [
        Spacer(1, 18 * mm),
        Table([[Paragraph("SENTINELOPS", ParagraphStyle("coverbrand", fontName=BOLD, fontSize=12, textColor=GREEN)), Paragraph("FUNDS CUSTODY", ParagraphStyle("coverlabel", fontName=MONO, fontSize=9, textColor=CYAN, alignment=TA_LEFT))]], colWidths=[58 * mm, 100 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBEFORE", (1, 0), (1, 0), 1, LINE), ("LEFTPADDING", (1, 0), (1, 0), 10)]),
        Spacer(1, 20 * mm),
        Paragraph("Unauthorized Debit<br/>Clearing", ParagraphStyle("covertitle", fontName=MONO, fontSize=34, leading=39, textColor=INK)),
        Spacer(1, 5 * mm),
        Table([["", "", ""]], colWidths=[82 * mm, 43 * mm, 33 * mm], rowHeights=[1.3 * mm], style=[("BACKGROUND", (0, 0), (0, 0), GREEN), ("BACKGROUND", (1, 0), (1, 0), CYAN), ("BACKGROUND", (2, 0), (2, 0), MAGENTA)]),
        Spacer(1, 8 * mm),
        Paragraph("Operator guide for tolerant identity intake, live Oracle verification, approval-triggered mutation, reversal, realtime handoff, and immutable custody evidence.", ParagraphStyle("coverintro", parent=styles["FBody"], fontSize=12, leading=18, textColor=MUTED, spaceAfter=0)),
        Spacer(1, 23 * mm),
        comparison(
            ["OPERATING PROMISE", "FIRST PRINCIPLE", "PROOF"],
            [["Precise debit correction without touching unrelated records.", "Intake defines what to inspect. Fresh Oracle evidence defines what may execute.", "Every authorization and mutation retains its sealed intention and before-state."]],
            [52 * mm, 58 * mm, 51 * mm],
        ),
        Spacer(1, 22 * mm),
        Paragraph("PRODUCTION OPERATING MANUAL", ParagraphStyle("covermeta", fontName=BOLD, fontSize=8, textColor=AMBER)),
        Paragraph(f"Edition 2026.08  /  {date(2026, 8, 19).strftime('%d %B %Y')}", styles["FMono"]),
        Spacer(1, 10 * mm),
        rule("Debit clearing only", "This workflow never clears unauthorized credits. Currency, physical ACNTBAL row, amount, and queue identity remain explicit boundaries.", RED),
    ]


def build_story():
    story = cover_story()
    story.append(PageBreak())

    story += section("01 / Operating map", "One custody path, five focused workspaces", "Funds Custody is independent from Nexus incident intelligence. Each workspace answers one question and hands a sealed result to the next.")
    story.append(comparison(
        ["WORKSPACE", "QUESTION", "OUTPUT"],
        [
            ["Batch Control", "Which Finance-authorized identifiers should enter custody?", "Immutable source hash and candidate debit scope"],
            ["Account Explorer", "What account, currency rows, and queue records exist now?", "Read-only evidence or a governed controlled batch"],
            ["Execution Desk", "Which sealed payload awaits authority, and what happened after approval?", "Before/after preview, decision, terminal result, rollback eligibility"],
            ["Custody Trail", "Who decided what, when, and against which records?", "Searchable year-to-day chronology and tabulated evidence"],
            ["Operating Guide", "What procedure or stop rule applies?", "In-app guidance and this downloadable PDF"],
        ],
        [34 * mm, 65 * mm, 62 * mm],
    ))
    story.append(Spacer(1, 5 * mm))
    story.append(numbered_steps([
        ("Create scope", "Import Accounts or RRNs, or create a controlled batch from Account Explorer."),
        ("Verify Oracle evidence", "Perform a fresh read of mappings, ACNTBAL currency rows, and debit queue identity."),
        ("Select safe rows", "Exclude blocked, ambiguous, stale, or no-longer-outstanding records."),
        ("Seal and authorize", "Submit an immutable payload. A checker inspects before-state and intent in Execution Desk."),
        ("Approve and execute", "Approval locks and revalidates the rows, commits atomically, and preserves before/after evidence."),
        ("Prove the outcome", "Use Execution Desk and Custody Trail; reverse only when the contract proves eligibility."),
    ]))
    story.append(Spacer(1, 4 * mm))
    story.append(rule("Intake is not authorization", "Creating a batch records what should be examined. Verification, safe classification, selection, submission, and checker approval are separate custody gates.", GREEN))
    story.append(PageBreak())

    story += section("02 / Identity intake", "The source file is intentionally one column", "Operators often receive only accounts or only RRNs. Choose the identifier type first; do not mix them and do not add transaction metadata.")
    story.append(comparison(
        ["MODE", "HEADER", "WHAT SENTINELOPS PREPARES", "STOP CONDITION"],
        [
            ["Account", "Account", "Every identifier is sealed. Positive currency rows become candidates; zero, unresolved, or deferred rows wait for verification.", "Only an invalid or duplicate source identifier stops intake."],
            ["RRN", "RRN", "One exact debit queue transaction, its internal account, currency, amount, fee, date, STAN, and row identity.", "Zero or multiple debit queue matches, credit-only evidence, or ambiguous internal account."],
        ],
        [24 * mm, 23 * mm, 66 * mm, 48 * mm],
    ))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("CSV examples", styles["FH2"]))
    story.append(comparison(["ACCOUNT FILE", "RRN FILE"], [["Account<br/><font name='SentinelMono'>100004167974</font>", "RRN<br/><font name='SentinelMono'>180001000436</font>"]], [80.5 * mm, 80.5 * mm]))
    story.append(Spacer(1, 5 * mm))
    story.append(bullet_list([
        "Keep the identifier column formatted as text in Excel so leading zeroes survive.",
        "Duplicate identifiers stop import. Correct the source and create a new batch.",
        "The original bytes are hashed; a corrected file becomes a new custody record rather than editing the old one.",
        "Account import never drops a valid identifier because the debit is currently zero or Oracle is temporarily unavailable; verification later classifies the row.",
        "Use Account Explorer when a partial or queue-specific amount is required and the administrator policy permits that mode.",
        "RRN import is transaction-specific and will not guess when more than one live debit row matches.",
    ]))
    story.append(rule("Why tolerate intake and verify later?", "Intake preserves the complete Finance source without turning a transient Oracle read into source loss. Verify Oracle evidence performs the fresh, authoritative read used for selection and approval. A later change is caught again under row lock before mutation.", CYAN))
    story.append(PageBreak())

    story += section("03 / Batch Control", "Verification turns candidate scope into current evidence", "The button reads Verify Oracle evidence because that is what the operation does. It is not a comparison against a hidden Finance transaction file.")
    story.append(numbered_steps([
        ("Open a batch", "Choose an existing batch or create one through the identity import."),
        ("Read the handoff", "The status line explains the next valid operation and why it exists."),
        ("Verify", "SentinelOps reads ACNTS or the RRN-derived internal account, ACNTBAL, and debit queue rows."),
        ("Classify", "READY is deterministic; SPECIAL REVIEW needs judgment; BLOCKED cannot mutate; NO ACTION is already resolved."),
        ("Filter and inspect", "Use account/RRN search and classification lanes. Open row evidence when boundaries are unclear."),
        ("Select", "Select only execution-safe records that match the authorized scope."),
    ]))
    story.append(Spacer(1, 5 * mm))
    story.append(comparison(
        ["VERDICT", "MEANING", "OPERATOR MOVE"],
        [
            ["READY", "One physical currency row and intended debit effect are deterministically resolved.", "Review and select."],
            ["READY WITH RESIDUAL", "The row remains positive after the approved amount.", "Confirm the residual is expected; unrelated value stays untouched."],
            ["SPECIAL REVIEW", "Potentially valid, but evidence requires a human explanation.", "Inspect the dossier and record rationale; do not treat as READY."],
            ["BLOCKED", "The system cannot prove one safe exact mutation.", "Stop. Resolve mapping, amount, row, or queue ambiguity."],
            ["NO ACTION", "The unauthorized debit is already zero or the exact effect is absent.", "Leave unselected and document if needed."],
        ],
        [35 * mm, 72 * mm, 54 * mm],
    ))
    story.append(PageBreak())

    story += section("04 / Account Explorer", "Investigate by Account or RRN without a batch", "Account Explorer is always read-only until you deliberately create a controlled batch. It can surface accounts absent from every imported source.")
    story.append(comparison(
        ["LOOKUP", "ORACLE PATH", "WHAT TO CONFIRM"],
        [
            ["Account", "FACNO to ACNTS_INTERNAL_ACNUM, then ACNTBAL and ASIBGPQNP.", "Unique mapping, account identity, every currency row, positive unauthorized debit, and debit queue context."],
            ["RRN", "ASIBGPQNP narration token to BGPQ_INT_ACCT_1, reverse ACNTS account when available, then ACNTBAL.", "One matched debit row, one internal account, surfaced external account, currency, STAN, value, fees, and row identity."],
        ],
        [27 * mm, 62 * mm, 72 * mm],
    ))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Creating a controlled batch", styles["FH2"]))
    story.append(bullet_list([
        "Choose the exact ACNTBAL currency row. Currency is a mutation boundary, not display metadata.",
        "Queue transaction mode allows an amount less than or equal to the selected transaction authority and total unauthorized debit.",
        "All unauthorized debits mode clears the complete positive amount on the chosen physical currency row and preserves queue records.",
        "Administrators may always use queue-specific clearing. The Execution Desk policy controls whether other users may use it; when disabled they can clear only the full unauthorized debit.",
        "Create Controlled Batch seals the chosen intent. It does not mutate Oracle and it does not bypass fresh verification.",
        "After creation, return to Batch Control and choose Verify Oracle evidence. This confirms the rows again before checker custody.",
    ]))
    story.append(rule("Why verification still follows CCB", "Account Explorer evidence supports the operator's choice. The verification step creates the formal batch snapshot and interpretation used by submission, approval, and the immutable execution payload.", MAGENTA))
    story.append(PageBreak())

    story += section("05 / Authorization", "The checker approves records and starts the mutation", "Submission freezes the selected transaction set, balance mutations, queue deletions, change reference, and payload hash. Operators cannot approve their own payload. Administrators may hold both roles under the explicit admin exception.")
    story.append(numbered_steps([
        ("Submit", "Maker records the approved change reference and decision context. SentinelOps creates an immutable payload hash."),
        ("Open Execution Desk", "The pending authorization queue opens the sealed account, currency, before value, authorized debit, intended after value, reason, and queue intention."),
        ("Inspect custody", "Confirm submitter, source, verification state, payload hash, and mutation intention."),
        ("Approve or return", "The checker records a note. Approval immediately runs the guarded mutation; return sends the batch back without mutation."),
    ]))
    story.append(Spacer(1, 5 * mm))
    story.append(comparison(
        ["CHECKER MUST SEE", "WHY IT MATTERS"],
        [
            ["External and internal account binding", "Prevents a correct amount from being applied to the wrong account."],
            ["Physical ACNTBAL row and currency", "Prevents cross-currency clearing and ambiguous physical-row updates."],
            ["Before, delta, intended after", "Makes the financial effect understandable before authority is granted."],
            ["Exact queue deletion list", "Shows whether a queue record will be removed or deliberately preserved."],
            ["Payload hash", "Proves the executed payload is the unchanged payload that was approved."],
        ],
        [67 * mm, 94 * mm],
    ))
    story.append(rule("Approval is the command", "There is no third manual execute step. Read every before and intended-after value before approval. When evidence or intention is unclear, return the payload to the maker with a precise note.", RED))
    story.append(PageBreak())

    story += section("06 / Execution Desk", "Authorization and mutation share one precise surface", "Approval locks the physical rows, revalidates them against the sealed before-state, applies only allowlisted changes, and records the outcome. Every connected Funds Custody workspace receives the state change immediately.")
    story.append(numbered_steps([
        ("Check both gates", "The SentinelOps write gate and approved Oracle production gate must both be open."),
        ("Confirm size window", "From 08:00 to 19:00, batches of 20 records or fewer may run; larger batches wait until after 19:00."),
        ("Approve once", "Record the checker note. The approval idempotency key prevents accidental duplicate execution."),
        ("Lock and revalidate", "Oracle rows are locked and compared with account, currency, amount, and queue identity from approval."),
        ("Commit atomically", "Every approved mutation succeeds together or the transaction rolls back."),
        ("Read terminal status", "COMMITTED, BLOCKED, FAILED, and COMMIT UNCERTAIN require different operator responses."),
    ]))
    story.append(Spacer(1, 5 * mm))
    story.append(comparison(
        ["STATUS", "RESPONSE"],
        [
            ["COMMITTED", "Inspect before/after evidence and verify the live outcome."],
            ["BLOCKED", "A guard stopped mutation. Read the mismatch and verify fresh evidence before any new attempt."],
            ["FAILED", "Preserve error and custody context; correct the external condition before retrying through the governed flow."],
            ["COMMIT UNCERTAIN", "Stop immediately. Never retry or reverse until live Oracle state proves whether commit occurred."],
        ],
        [38 * mm, 123 * mm],
    ))
    story.append(rule("Rollback is compensation, not undo", "Rollback is available only for an eligible committed execution whose current rows still match the committed after-images. It creates a new audited activity and requires a precise reason.", AMBER))
    story.append(PageBreak())

    story += section("07 / Custody Trail", "Search, navigate time, and open record-level proof", "Search by account or RRN, then move through Year, Month, Week, and Day. Within a day, mutation and authorization events surface before verification and routine custody activity.")
    story.append(comparison(
        ["VISUAL PRIORITY", "EVENTS", "WHAT OPENS"],
        [
            ["Oracle mutation", "Execution committed, failed, rollback, commit uncertainty", "Sealed payload plus Oracle records captured before and after mutation"],
            ["Authorization", "Submission, approval, rejection", "Checker custody, payload hash, before value, delta, intended after, queue intention"],
            ["Evidence verification", "Reconciliation and direct inspections", "Account snapshots, balance rows, queue rows, and interpretation"],
            ["Custody activity", "Import, selection, deletion, system events", "Source and event metadata tied to the actor and batch"],
        ],
        [36 * mm, 55 * mm, 70 * mm],
    ))
    story.append(Spacer(1, 5 * mm))
    story.append(bullet_list([
        "Search by account or RRN when investigating one customer or transaction, then expand time only as far as needed.",
        "Select an event to keep the chronology visible while its evidence opens in the inspector.",
        "For authorization, compare the sealed intention with the checker identity and decision note.",
        "For mutation, open the before-state record and confirm it matches the approved before values.",
        "For reconciliation, inspect account snapshots when a classification or mapping must be defended.",
        "Audit records are append-only. A reversal adds evidence; it never rewrites the original execution story.",
    ]))
    story.append(rule("Evidence lives in SentinelOps", "Reconciliation snapshots, sealed approval payloads, execution before/after images, actors, timestamps, and references are retained in the SentinelOps custody database and exposed through the selected audit event.", GREEN))
    story.append(PageBreak())

    story += section("08 / Controls", "Know which boundary is stopping the operation", "Disabled controls are part of the safety design. Resolve the named boundary; do not change gates merely to make a button clickable.")
    story.append(comparison(
        ["BOUNDARY", "BEHAVIOR", "OWNER"],
        [
            ["Role", "Maker, checker, administrator, and rollback permissions remain explicit.", "SentinelOps access policy"],
            ["Maker-checker", "Operators cannot approve their own payload; administrators may under the recorded exception.", "Backend custody contract"],
            ["Specific record", "Administrators control whether non-admins may clear one queue record; full-row clearing remains available.", "Funds Custody policy"],
            ["Batch-size window", "More than 20 records are blocked from verification and execution from 08:00 to 19:00.", "Configured clearing timezone"],
            ["Write gate", "Oracle mutation stays locked unless explicitly enabled for the intended environment.", "Application configuration"],
            ["Oracle evidence", "Ambiguity, stale rows, wrong currency, changed values, or missing queue identity block mutation.", "Live Oracle state"],
            ["Idempotency", "A repeated execution key returns the existing run rather than repeating mutation.", "Execution ledger"],
        ],
        [38 * mm, 85 * mm, 38 * mm],
    ))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Deployment note", styles["FH2"]))
    story.append(bullet_list([
        "Apply clearing migrations in filename order through 2026_11_refine_nexus_clearing_workflow.sql.",
        "The 2026_11 migration adds the specific-record policy and permits zero-value intake placeholders while preserving positive execution constraints.",
        "Restart Nexus after migration so API models, repository contracts, and storage agree.",
        "Verify the configured UAT or production Oracle endpoint, entity number, timezone, and both write gates before execution testing.",
    ], CYAN))
    story.append(PageBreak())

    story += section("09 / Stop rules", "Precision means knowing when not to continue", "These conditions are deliberate hard stops. Preserve the current evidence and move the investigation outside the mutation path.")
    stop_rows = [
        ["Identity ambiguity", "An account or RRN does not resolve uniquely.", "Investigate in Account Explorer; correct the source or Oracle mapping."],
        ["Currency ambiguity", "Multiple positive physical rows can satisfy the same currency effect.", "Stop and obtain formal resolver confirmation."],
        ["Amount mismatch", "Requested debit exceeds the chosen queue authority or current unauthorized debit.", "Correct the authority or choose the right physical row; never force the value."],
        ["Changed after approval", "Locked before-state differs from the approved payload.", "Execution blocks. Verify fresh evidence and submit a new payload."],
        ["Commit uncertain", "The response cannot prove Oracle commit state.", "Do not retry. Reconstruct live state and escalate."],
        ["Large batch in business hours", "More than 20 records during 08:00-19:00.", "Continue after 19:00. Small batches remain available."],
    ]
    story.append(comparison(["STOP", "SIGNAL", "SAFE RESPONSE"], stop_rows, [39 * mm, 59 * mm, 63 * mm]))
    story.append(Spacer(1, 6 * mm))
    story.append(rule("Credits are out of scope", "The UI may surface account context, but this workflow updates only ACNTBAL_AC_UNAUTH_DB_SUM for debit clearing and considers only debit queue records.", RED))
    story.append(rule("Unrelated records remain untouched", "Exact queue actions delete only the approved queue row. Full unauthorized-debit row actions preserve queue records. Every other account, currency, balance component, and queue item remains unchanged.", GREEN))
    story.append(PageBreak())

    story += section("10 / Quick runbook", "The complete operator sequence", "Use this page as the production handoff checklist after the full procedure is understood.")
    story.append(numbered_steps([
        ("Confirm authority", "Validate Finance ownership, environment, operator role, and intended debit scope."),
        ("Choose intake", "Import a one-column Account or RRN file, or investigate directly in Account Explorer."),
        ("Inspect import result", "Read source hash and every retained identifier. Zero-debit and deferred rows remain visible for verification rather than aborting intake."),
        ("Verify Oracle evidence", "Perform the fresh batch read; respect the greater-than-20 business-hour gate."),
        ("Interpret and select", "Read mapping, currency, before value, queue identity, warnings, and blockers."),
        ("Submit", "Record the change reference and context; retain the payload hash."),
        ("Checker command", "A separate operator reads before-state and intended mutation, then approves and executes or returns. An administrator may use the recorded self-approval exception."),
        ("Follow execution", "Approval is the command. Wait for the terminal result and never duplicate an uncertain mutation."),
        ("Verify outcome", "Read terminal status and Oracle before/after evidence in Execution Desk."),
        ("Close custody", "Inspect the event in the hierarchical trail and ensure actors, references, and evidence tell the complete story."),
    ]))
    story.append(Spacer(1, 7 * mm))
    story.append(comparison(
        ["DO", "DO NOT"],
        [["Use Account Explorer for partial, currency-specific, or uncertain cases.<br/>Use the trail to prove intent and before-state.<br/>Stop on ambiguity or commit uncertainty.", "Do not mix identifier types.<br/>Do not approve without reading mutation intent.<br/>Do not force business-hour or evidence gates.<br/>Do not treat rollback as an undo button."]],
        [80.5 * mm, 80.5 * mm],
    ))
    story.append(Spacer(1, 7 * mm))
    story.append(rule("Custody principle", "A sealed source defines what SentinelOps may examine. Fresh Oracle evidence proves what it may correct. Checker approval executes the exact mutation. The custody trail proves what actually happened.", MAGENTA))
    return story


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc = CustodyDocTemplate(str(OUTPUT))
    doc.build(build_story())
    print(OUTPUT)


if __name__ == "__main__":
    main()
