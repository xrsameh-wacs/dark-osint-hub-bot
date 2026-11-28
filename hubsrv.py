"""Client for the Dark OSINT Hub platform server (hub-gateway).

The platform tools (Wazuh, MISP, OpenCTI, Greenbone/OpenVAS) run on the
user's own always-on server (see the free-server package). This module is
the bot's only door to them:

- Reads HUB_SERVER_URL / HUB_SERVER_TOKEN from the environment.
- When unset, configured() is False and callers keep the existing honest
  "platform needs your own server" behaviour — nothing changes.
- When set, queries the gateway's read-only summary endpoints and formats
  Egyptian in-message results, paginated 10 finding lines per message with
  a «صفحة X من Y» footer (same protocol as the workflow results).

Stdlib only. Never raises to callers: network problems come back as an
Egyptian error page so the bot answers honestly instead of crashing.
"""
import json
import os
import urllib.parse
import urllib.request

PAGE_LINES = 10


def configured():
    return bool(os.environ.get("HUB_SERVER_URL") and os.environ.get("HUB_SERVER_TOKEN"))


def _get(path, params=None, timeout=30):
    url = os.environ["HUB_SERVER_URL"].rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + os.environ["HUB_SERVER_TOKEN"])
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _pages(title, lines):
    lines = [str(x) for x in (lines or [])] or ["(لا توجد بيانات)"]
    chunks = [lines[i:i + PAGE_LINES] for i in range(0, len(lines), PAGE_LINES)]
    out = []
    for i, ch in enumerate(chunks, 1):
        head = title if i == 1 else title + " (تكملة)"
        foot = "\n📄 صفحة %d من %d" % (i, len(chunks)) if len(chunks) > 1 else ""
        out.append(head + "\n" + "\n".join(ch) + foot)
    return out


def _err(tool, why):
    return ["⚠️ سيرفر المنصات متظبط لكن %s ما ردش دلوقتي (%s). اتأكد إن السيرفر شغال وإن البوابة بترد، وجرّب تاني." % (tool, why)]


def answer(tool, query):
    """Return a list of message strings, or None when the server is not
    configured (caller then falls back to today's behaviour)."""
    if not configured():
        return None
    try:
        if tool == "MISP":
            r = _get("/misp/search", {"q": query})
        elif tool == "OpenCTI":
            r = _get("/opencti/lookup", {"q": query})
        elif tool in ("OpenVAS / Greenbone", "Greenbone"):
            r = _get("/greenbone/status")
        elif tool == "Wazuh":
            r = _get("/wazuh/summary")
        else:
            return None
    except Exception as e:
        return _err(tool, type(e).__name__)
    if not isinstance(r, dict):
        return _err(tool, "رد غير متوقع")
    return _pages("🖥 %s — من سيرفرك" % (r.get("title") or tool), r.get("lines") or [])


def status_pages():
    """For the /hub command: gateway health + Wazuh + Greenbone summaries."""
    if not configured():
        return None
    pages = []
    try:
        h = _get("/health", timeout=10)
        pages.append("🖥 سيرفر المنصات: %s" % ("متصل وبيرد ✅" if h.get("ok") else "بيرد بحالة غريبة"))
    except Exception as e:
        return ["⚠️ سيرفر المنصات متظبط في إعدادات البوت لكنه مش بيرد (%s). "
                "اتأكد إن السيرفر شغال وإن رابط البوابة (Funnel) صح." % type(e).__name__]
    for tool, q in (("Wazuh", ""), ("OpenVAS / Greenbone", "")):
        r = answer(tool, q)
        if r:
            pages.extend(r)
    return pages
