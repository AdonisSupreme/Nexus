"""Table-based SentinelOps email design; no remote fonts, scripts or tracking assets."""
from html import escape


def render_email(*, badge, headline, intro, metadata=(), lines=(), cta_label=None, link=None, code=None, code_hint=None, accent="#087f83"):
    def safe(value):
        return escape(str(value), quote=True)

    rows = "".join(
        f'<tr><th align="left" valign="top" width="32%" style="padding:12px 14px;border-bottom:1px solid #dbe5ec;color:#526b7d;font-size:12px;font-weight:400;">{safe(label)}</th>'
        f'<td valign="top" style="padding:12px 14px;border-bottom:1px solid #dbe5ec;color:#193449;font-size:14px;line-height:1.5;word-break:break-word;">{safe(value)}</td></tr>'
        for label, value in metadata if value is not None and str(value) != ""
    )
    paragraphs = "".join(f'<p style="margin:0 0 14px;color:#526b7d;font-size:14px;line-height:1.7;">{safe(line)}</p>' for line in lines)
    verification = ""
    if code is not None:
        verification = f'<table role="presentation" width="100%" bgcolor="#edf7f7" style="margin:20px 0;border:1px solid #b9dddd;border-radius:12px;"><tr><td align="center" style="padding:22px;"><div style="font-size:11px;letter-spacing:1px;color:#526b7d;">ONE-TIME VERIFICATION CODE</div><div style="margin:12px 0;font-size:34px;font-weight:700;letter-spacing:6px;color:#193449;">{safe(code)}</div><div style="font-size:12px;color:#526b7d;">{safe(code_hint or "")}</div></td></tr></table>'
    action = ""
    if link and cta_label:
        action = f'<table role="presentation" cellspacing="0" cellpadding="0" style="margin:24px 0 16px;"><tr><td bgcolor="#087f83" style="border-radius:8px;mso-padding-alt:14px 22px;"><a href="{safe(link)}" style="display:inline-block;padding:14px 22px;color:#ffffff;font-size:14px;font-weight:700;text-decoration:none;">{safe(cta_label)} &rarr;</a></td></tr></table><p style="margin:0;color:#526b7d;font-size:11px;line-height:1.6;word-break:break-all;">If the button does not open, use:<br><a href="{safe(link)}" style="color:#087f83;">{safe(link)}</a></p>'
    snapshot = f'<table aria-label="Operational details" width="100%" cellspacing="0" cellpadding="0" bgcolor="#f3f7fa" style="border:1px solid #dbe5ec;border-radius:10px;margin:18px 0;">{rows}</table>' if rows else ""
    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>{safe(headline)}</title></head>
<body bgcolor="#eef3f7" style="margin:0;padding:0;background-color:#eef3f7;font-family:Arial,Helvetica,sans-serif;">
<div style="display:none;font-size:1px;line-height:1px;max-height:0;overflow:hidden;mso-hide:all;">{safe(intro)}</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" bgcolor="#eef3f7"><tr><td align="center" style="padding:24px 12px;">
<!--[if mso]><table role="presentation" width="640"><tr><td><![endif]-->
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;border:1px solid #dbe5ec;border-radius:16px;" bgcolor="#ffffff">
<tr><td bgcolor="#102332" style="padding:24px 28px;border-bottom:3px solid #5ad6cf;border-radius:16px 16px 0 0;"><span style="color:#ffffff;font-size:25px;font-weight:700;letter-spacing:-1px;">Sentinel<span style="color:#5ad6cf;">Ops</span></span><div style="margin-top:7px;color:#b9ccd9;font-size:10px;letter-spacing:1.5px;">CLARITY. CONTINUITY. CONTROL.</div></td></tr>
<tr><td style="padding:28px;"><div style="color:#087f83;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;">{safe(badge)}</div><h1 style="margin:12px 0;color:#193449;font-size:26px;line-height:1.3;letter-spacing:-.5px;">{safe(headline)}</h1><p style="margin:0 0 18px;color:#526b7d;font-size:14px;line-height:1.7;">{safe(intro)}</p>{verification}{paragraphs}{snapshot}{action}</td></tr>
<tr><td bgcolor="#f3f7fa" style="padding:18px 28px;border-top:1px solid #dbe5ec;border-radius:0 0 16px 16px;color:#526b7d;font-size:11px;line-height:1.6;">SentinelOps &middot; Operational update<br>Open the workspace to review the latest state before taking action.</td></tr></table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr></table></body></html>'''
