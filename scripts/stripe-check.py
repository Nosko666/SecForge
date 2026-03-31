#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def json_out(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def normalize_input_url(raw: str) -> Tuple[Optional[str], Optional[str]]:
    raw = (raw or "").strip()
    if not raw:
        return None, "Missing URL"
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        return None, f"Unsupported URL scheme: {p.scheme}"
    if not p.netloc:
        return None, "Invalid URL (missing host)"
    # Normalize away fragments
    p = p._replace(fragment="")
    return urlunparse(p), None


def host_no_port(url: str) -> str:
    p = urlparse(url)
    return (p.hostname or "").lower()


def is_ip_like(host: str) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def guess_root_suffix(host: str) -> str:
    """
    Best-effort "same-site" suffix (no Public Suffix List).
    - Handles common 2-level TLD patterns like example.co.uk.
    - Otherwise uses last 2 labels.
    """
    host = (host or "").lower().strip(".")
    if is_ip_like(host) or not host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host

    last = labels[-1]
    second_last = labels[-2]
    common_sld = {"co", "com", "net", "org", "gov", "ac", "edu"}
    if len(last) == 2 and second_last in common_sld and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_same_site(candidate_host: str, root_suffix: str) -> bool:
    candidate_host = (candidate_host or "").lower().strip(".")
    root_suffix = (root_suffix or "").lower().strip(".")
    if not candidate_host or not root_suffix:
        return False
    if candidate_host == root_suffix:
        return True
    return candidate_host.endswith("." + root_suffix)


def limit_list(items: List[Any], n: int = 25) -> List[Any]:
    return items[:n]


def safe_truncate(text: str, n: int = 800) -> str:
    t = (text or "").strip()
    if len(t) <= n:
        return t
    return t[:n] + "…"


def luhn_ok(digits: str) -> bool:
    total = 0
    alt = False
    for ch in reversed(digits):
        if not ch.isdigit():
            return False
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def mask_digits(digits: str) -> str:
    digits = re.sub(r"\D+", "", digits or "")
    if len(digits) <= 4:
        return "*" * len(digits)
    return ("*" * (len(digits) - 4)) + digits[-4:]


def find_card_like_numbers(text: str, max_hits: int = 10) -> List[str]:
    """
    Finds Luhn-valid 13–19 digit sequences in text. Returns masked values.
    """
    hits: List[str] = []
    for m in re.finditer(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text or ""):
        raw = m.group(0)
        digits = re.sub(r"\D+", "", raw)
        if not (13 <= len(digits) <= 19):
            continue
        if not luhn_ok(digits):
            continue
        hits.append(mask_digits(digits))
        if len(hits) >= max_hits:
            break
    return hits


def csp_has_unsafe_inline(csp_header: str) -> bool:
    csp = (csp_header or "").lower()
    if not csp:
        return False
    # Prefer checking script-src; fallback to default-src.
    directives = [d.strip() for d in csp.split(";") if d.strip()]
    script_src = None
    default_src = None
    for d in directives:
        parts = d.split()
        if not parts:
            continue
        name = parts[0]
        if name == "script-src":
            script_src = parts[1:]
        if name == "default-src":
            default_src = parts[1:]
    tokens = script_src if script_src is not None else default_src if default_src is not None else []
    return "'unsafe-inline'" in tokens


def csp_has_frame_ancestors(csp_header: str) -> bool:
    csp = (csp_header or "").lower()
    if not csp:
        return False
    for d in [x.strip() for x in csp.split(";") if x.strip()]:
        if d.startswith("frame-ancestors"):
            parts = d.split()
            # frame-ancestors 'none' / 'self' / specific origins
            if len(parts) < 2:
                return False
            tokens = parts[1:]
            if "*" in tokens:
                return False
            return True
    return False


def clickjacking_protected(headers_lc: Dict[str, str]) -> bool:
    xfo = (headers_lc.get("x-frame-options") or "").lower()
    if xfo in ("deny", "sameorigin"):
        return True
    csp = headers_lc.get("content-security-policy") or ""
    return csp_has_frame_ancestors(csp)


def parse_html(html: str) -> Any:
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return None
    return BeautifulSoup(html or "", "html.parser")


def extract_candidate_links(html: str, base_url: str) -> Set[str]:
    soup = parse_html(html)
    if soup is None:
        return set()
    urls: Set[str] = set()
    for a in soup.find_all("a"):
        href = a.get("href")
        if not href:
            continue
        urls.add(urljoin(base_url, href))
    for f in soup.find_all("form"):
        action = f.get("action")
        if not action:
            continue
        urls.add(urljoin(base_url, action))
    cleaned: Set[str] = set()
    for u in urls:
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            continue
        cleaned.add(urlunparse(p._replace(fragment="")))
    return cleaned


def extract_resource_urls(html: str, base_url: str) -> List[str]:
    soup = parse_html(html)
    if soup is None:
        return []
    attrs = [
        ("script", "src"),
        ("img", "src"),
        ("link", "href"),
        ("iframe", "src"),
        ("source", "src"),
        ("audio", "src"),
        ("video", "src"),
        ("track", "src"),
        ("embed", "src"),
        ("object", "data"),
        ("form", "action"),
    ]
    out: List[str] = []
    for tag_name, attr in attrs:
        for t in soup.find_all(tag_name):
            v = t.get(attr)
            if not v:
                continue
            out.append(urljoin(base_url, v))
    return out


def extract_script_info(html: str, base_url: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    soup = parse_html(html)
    if soup is None:
        return [], []
    scripts: List[Dict[str, Any]] = []
    inline_snippets: List[str] = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            full = urljoin(base_url, src)
            p = urlparse(full)
            scripts.append(
                {
                    "src": full,
                    "host": (p.hostname or "").lower(),
                    "integrity": bool(s.get("integrity")),
                }
            )
        else:
            # Keep only a tiny snippet for heuristics; never store full scripts.
            txt = s.string or ""
            if txt:
                inline_snippets.append(safe_truncate(txt, 300))
    return scripts, inline_snippets


def detect_raw_card_fields(html: str) -> List[Dict[str, str]]:
    soup = parse_html(html)
    if soup is None:
        return []
    hits: List[Dict[str, str]] = []

    card_autocomplete = {
        "cc-number",
        "cc-csc",
        "cc-exp",
        "cc-exp-month",
        "cc-exp-year",
        "cc-name",
    }
    name_re = re.compile(r"(?i)\b(card(number)?|cc(num|_?number)?|pan|cvc|cvv|expiry|exp(_?month|_?year)?)\b")

    for inp in soup.find_all("input"):
        itype = (inp.get("type") or "").lower()
        if itype in ("hidden", "submit", "button", "image", "reset", "file"):
            continue
        nm = (inp.get("name") or "")[:120]
        iid = (inp.get("id") or "")[:120]
        ac = (inp.get("autocomplete") or "").lower()
        ds = (inp.get("data-stripe") or "")[:120]

        flagged = False
        if ac in card_autocomplete:
            flagged = True
        if ds.lower() in ("number", "cvc", "exp-month", "exp-year", "exp"):
            flagged = True
        if name_re.search(nm) or name_re.search(iid):
            flagged = True

        if flagged:
            hits.append(
                {
                    "type": itype or "unknown",
                    "name": nm,
                    "id": iid,
                    "autocomplete": ac,
                    "data_stripe": ds,
                }
            )
            if len(hits) >= 25:
                break
    return hits


def suspicious_storage_refs(text: str) -> List[str]:
    """
    Best-effort: flags likely card-related localStorage/sessionStorage usage.
    Returns short redacted matches (no values).
    """
    out: List[str] = []
    for m in re.finditer(
        r"(?is)\b(localStorage|sessionStorage)\s*\.\s*(setItem|getItem)\s*\(\s*['\"]([^'\"]{0,80})['\"]",
        text or "",
    ):
        key = m.group(3)
        if re.search(r"(?i)\b(card(number)?|cc(num|_?number)?|pan|cvc|cvv)\b", key):
            out.append(f"{m.group(1)}.{m.group(2)}('{key}')")
        if len(out) >= 10:
            break
    return out


def fetch_limited(session: Any, url: str, timeout_s: int, max_bytes: int = 2_000_000) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        with session.get(url, allow_redirects=True, timeout=(min(10, timeout_s), timeout_s), stream=True) as resp:
            raw = b""
            for chunk in resp.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                raw += chunk
                if len(raw) >= max_bytes:
                    break
            enc = resp.encoding or "utf-8"
            text = raw.decode(enc, errors="replace")
            headers_lc = {k.lower(): v for k, v in resp.headers.items()}

            set_cookie_all: List[str] = []
            try:
                raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
                if raw_headers is not None:
                    if hasattr(raw_headers, "get_all"):
                        v = raw_headers.get_all("Set-Cookie") or []
                        if isinstance(v, str):
                            set_cookie_all = [v]
                        else:
                            set_cookie_all = list(v)
                    elif hasattr(raw_headers, "getlist"):
                        v = raw_headers.getlist("Set-Cookie") or []
                        if isinstance(v, str):
                            set_cookie_all = [v]
                        else:
                            set_cookie_all = list(v)
            except Exception:
                set_cookie_all = []
            if not set_cookie_all and "set-cookie" in headers_lc:
                set_cookie_all = [headers_lc.get("set-cookie", "")]
            return (
                {
                    "url": url,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                    "headers": headers_lc,
                    "set_cookie": set_cookie_all,
                    "text": text,
                },
                None,
            )
    except Exception as e:
        return None, str(e)


def http_redirects_to_https(session: Any, https_url: str, timeout_s: int) -> Dict[str, Any]:
    """
    Checks whether the HTTP variant redirects to HTTPS (best-effort).
    """
    p = urlparse(https_url)
    if not p.hostname:
        return {"tested": False}
    http_url = urlunparse(p._replace(scheme="http"))
    try:
        with session.get(http_url, allow_redirects=False, timeout=(min(10, timeout_s), timeout_s), stream=True) as r:
            try:
                status = int(r.status_code)
            except Exception:
                status = 0
            loc = r.headers.get("Location") or r.headers.get("location")
            if status in (301, 302, 303, 307, 308) and loc:
                loc_abs = urljoin(http_url, loc)
                return {
                    "tested": True,
                    "http_url": http_url,
                    "status": status,
                    "location": loc_abs,
                    "redirects_to_https": urlparse(loc_abs).scheme == "https",
                }
            if status and status < 400:
                return {"tested": True, "http_url": http_url, "status": status, "redirects_to_https": False}
            return {"tested": True, "http_url": http_url, "status": status, "redirects_to_https": True}
    except Exception as e:
        # If port 80 is closed or blocked, treat as HTTPS-only.
        return {"tested": True, "http_url": http_url, "error": str(e), "redirects_to_https": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="SecForge Stripe/payment security checker (outputs JSON).")
    parser.add_argument("url", help="Target URL (prefer https://example.com)")
    parser.add_argument("--max-pages", type=int, default=10, help="Max linked pages to fetch (default: 10)")
    parser.add_argument("--delay-ms", type=int, default=200, help="Delay between requests (default: 200)")
    parser.add_argument("--timeout-seconds", type=int, default=20, help="Per-request timeout (default: 20)")
    args = parser.parse_args()

    normalized, err = normalize_input_url(args.url)
    result: Dict[str, Any] = {
        "tool": "stripe-check",
        "version": "1.0",
        "scan_date": utc_now_iso(),
        "target": args.url,
        "normalized_target": normalized or "",
        "config": {"max_pages": args.max_pages, "delay_ms": args.delay_ms, "timeout_seconds": args.timeout_seconds},
        "status": "ok",
        "checks": {},
        "pages_scanned": [],
        "payment_pages": [],
        "errors": [],
        "notes": [],
    }

    if err or not normalized:
        result["status"] = "error"
        result["errors"].append(err or "Invalid URL")
        json_out(result)
        return 0

    try:
        import requests  # type: ignore
    except Exception:
        result["status"] = "error"
        result["errors"].append("Missing dependency: requests")
        result["notes"].append("Install SecForge compliance category (venv) so stripe-check can run.")
        json_out(result)
        return 0

    try:
        from bs4 import BeautifulSoup  # noqa: F401  # type: ignore
    except Exception:
        result["status"] = "error"
        result["errors"].append("Missing dependency: beautifulsoup4 (bs4)")
        result["notes"].append("Install SecForge compliance category (venv) and run via /opt/secforge/bin/stripe-check.")
        json_out(result)
        return 0

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "SecForge/1.0 (stripe-check; +https://github.com/Nosko666/SecForge)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    base_host = host_no_port(normalized)
    base_host_no_www = base_host[4:] if base_host.startswith("www.") else base_host
    root_suffix = guess_root_suffix(base_host_no_www) or base_host
    keywords = ("checkout", "payment", "billing", "subscribe")

    # Fetch base page.
    base_page, base_err = fetch_limited(session, normalized, args.timeout_seconds)
    if base_err or base_page is None:
        result["status"] = "error"
        result["errors"].append(f"Failed to fetch base URL: {base_err or 'unknown error'}")
        json_out(result)
        return 0

    visited: Set[str] = set()
    to_scan: List[str] = []
    to_scan.append(base_page["final_url"])
    visited.add(base_page["final_url"])

    links = extract_candidate_links(base_page.get("text", ""), base_page["final_url"])
    candidates: List[str] = []
    for u in links:
        if any(k in u.lower() for k in keywords):
            candidates.append(u)
    # Prioritize same-site links and cap.
    candidates_sorted = sorted(
        candidates,
        key=lambda u: (0 if is_same_site(host_no_port(u), root_suffix) else 1, len(u)),
    )
    for u in candidates_sorted:
        if len(to_scan) >= 1 + max(0, args.max_pages):
            break
        h = host_no_port(u)
        if not is_same_site(h, root_suffix):
            continue
        if u in visited:
            continue
        to_scan.append(u)
        visited.add(u)

    pages: List[Dict[str, Any]] = []

    # Analyze pages.
    for idx, u in enumerate(to_scan):
        if idx > 0:
            time.sleep(max(0, args.delay_ms) / 1000.0)
        page, perr = fetch_limited(session, u, args.timeout_seconds)
        if perr or page is None:
            result["errors"].append(f"Fetch failed: {u}: {perr or 'unknown error'}")
            continue

        final_url = str(page.get("final_url") or u)
        headers = page.get("headers") or {}
        html = page.get("text") or ""

        page_host = host_no_port(final_url)
        is_https = urlparse(final_url).scheme == "https"

        scripts, inline_snips = extract_script_info(html, final_url)
        script_hosts = sorted({(s.get("host") or "") for s in scripts if s.get("host")})

        # Stripe script checks
        stripe_official = [s["src"] for s in scripts if (s.get("host") == "js.stripe.com")]
        stripe_suspect = [
            s["src"]
            for s in scripts
            if ("stripe" in (s.get("src") or "").lower() or "stripe" in (s.get("host") or ""))
            and (s.get("host") != "js.stripe.com")
        ]

        # Mixed content (only meaningful on HTTPS pages)
        mixed: List[str] = []
        if is_https:
            for ru in extract_resource_urls(html, final_url):
                if ru.lower().startswith("http://"):
                    mixed.append(ru)
                    if len(mixed) >= 25:
                        break

        # SRI on external scripts (exclude first-party and js.stripe.com)
        missing_sri: List[str] = []
        for s in scripts:
            shost = (s.get("host") or "").lower()
            if not shost or shost == "js.stripe.com":
                continue
            if is_same_site(shost, root_suffix):
                continue
            if not s.get("integrity", False):
                missing_sri.append(str(s.get("src") or ""))
        missing_sri = limit_list(missing_sri, 25)

        raw_card_fields = detect_raw_card_fields(html)
        card_hits = find_card_like_numbers(html)

        cookie_names: List[str] = []
        for sc in page.get("set_cookie", []) or []:
            name = (sc.split("=", 1)[0] if isinstance(sc, str) else "").strip()
            if name:
                cookie_names.append(name)

        # Storage references (heuristic)
        storage_refs = suspicious_storage_refs(html + "\n" + "\n".join(inline_snips))

        payment_candidate = any(k in final_url.lower() for k in keywords) or bool(stripe_official) or bool(raw_card_fields)

        pages.append(
            {
                "url": u,
                "final_url": final_url,
                "host": page_host,
                "status_code": int(page.get("status_code") or 0),
                "https": is_https,
                "payment_candidate": payment_candidate,
                "headers": {
                    "content_security_policy": safe_truncate(headers.get("content-security-policy", ""), 500),
                    "x_frame_options": safe_truncate(headers.get("x-frame-options", ""), 80),
                    "strict_transport_security": safe_truncate(headers.get("strict-transport-security", ""), 120),
                    "set_cookie_names": limit_list(cookie_names, 25),
                },
                "scripts": {
                    "hosts": limit_list(script_hosts, 25),
                    "stripe_official_srcs": limit_list(stripe_official, 10),
                    "stripe_suspect_srcs": limit_list(stripe_suspect, 10),
                    "missing_sri_srcs": missing_sri,
                },
                "mixed_content_http_urls": mixed,
                "raw_card_fields": limit_list(raw_card_fields, 25),
                "card_number_like_hits_masked": limit_list(card_hits, 10),
                "suspicious_storage_refs": limit_list(storage_refs, 10),
            }
        )

    result["pages_scanned"] = [p["final_url"] for p in pages]
    payment_pages = [p for p in pages if p.get("payment_candidate")]
    result["payment_pages"] = [p["final_url"] for p in payment_pages]
    if not payment_pages:
        result["notes"].append("No payment/checkout pages detected by keyword/heuristics; checks are based on the base page only.")
        payment_pages = pages[:1]

    # Aggregations for checks.
    non_https = [p["final_url"] for p in pages if not p.get("https")]
    mixed_all: List[str] = []
    stripe_suspect_all: List[str] = []
    stripe_official_any = False
    raw_card_all: List[Dict[str, str]] = []
    card_hits_all: List[str] = []
    missing_sri_all: List[str] = []
    third_party_script_hosts: Set[str] = set()
    missing_csp: List[str] = []
    unsafe_inline: List[str] = []
    missing_clickjack: List[str] = []

    for p in payment_pages:
        mixed_all.extend(p.get("mixed_content_http_urls", []))
        stripe_suspect_all.extend(p.get("scripts", {}).get("stripe_suspect_srcs", []))
        if p.get("scripts", {}).get("stripe_official_srcs"):
            stripe_official_any = True
        raw_card_all.extend(p.get("raw_card_fields", []))
        card_hits_all.extend(p.get("card_number_like_hits_masked", []))
        missing_sri_all.extend(p.get("scripts", {}).get("missing_sri_srcs", []))

        for h in p.get("scripts", {}).get("hosts", []):
            if not h:
                continue
            if h == "js.stripe.com":
                continue
            if is_same_site(h, root_suffix):
                continue
            third_party_script_hosts.add(h)

        csp = (p.get("headers", {}).get("content_security_policy") or "").strip()
        if not csp:
            missing_csp.append(p["final_url"])
        elif csp_has_unsafe_inline(csp):
            unsafe_inline.append(p["final_url"])

        hdrs = p.get("headers", {}) or {}
        headers_lc = {
            "x-frame-options": hdrs.get("x_frame_options", "") or "",
            "content-security-policy": hdrs.get("content_security_policy", "") or "",
        }
        if not clickjacking_protected(headers_lc):
            missing_clickjack.append(p["final_url"])

    # HTTPS enforcement (probe HTTP -> HTTPS)
    http_probe = http_redirects_to_https(session, normalized, args.timeout_seconds)
    result["checks"]["https_enforced"] = {
        "pass": len(non_https) == 0 and bool(http_probe.get("redirects_to_https", True)),
        "evidence": {
            "non_https_pages": limit_list(non_https, 10),
            "http_probe": http_probe,
        },
    }

    result["checks"]["mixed_content"] = {
        "pass": len(mixed_all) == 0,
        "evidence": {"http_urls": limit_list(sorted(set(mixed_all)), 25)},
    }

    result["checks"]["stripe_js_official_only"] = {
        "pass": len(stripe_suspect_all) == 0,
        "evidence": {
            "official_detected": stripe_official_any,
            "suspect_srcs": limit_list(sorted(set(stripe_suspect_all)), 10),
        },
    }

    result["checks"]["raw_card_fields"] = {
        "pass": len(raw_card_all) == 0,
        "evidence": {"fields": limit_list(raw_card_all, 25)},
    }

    result["checks"]["csp_present"] = {
        "pass": len(missing_csp) == 0,
        "evidence": {"missing_on_pages": limit_list(missing_csp, 10)},
    }

    result["checks"]["csp_blocks_unsafe_inline"] = {
        "pass": len(missing_csp) == 0 and len(unsafe_inline) == 0,
        "evidence": {"unsafe_inline_on_pages": limit_list(unsafe_inline, 10)},
    }

    result["checks"]["no_card_number_patterns"] = {
        "pass": len(card_hits_all) == 0,
        "evidence": {"masked_hits": limit_list(sorted(set(card_hits_all)), 10)},
    }

    result["checks"]["sri_on_external_scripts"] = {
        "pass": len(missing_sri_all) == 0,
        "evidence": {"missing_integrity_srcs": limit_list(sorted(set(missing_sri_all)), 25)},
    }

    result["checks"]["clickjacking_protection"] = {
        "pass": len(missing_clickjack) == 0,
        "evidence": {"missing_on_pages": limit_list(missing_clickjack, 10)},
    }

    result["checks"]["no_third_party_scripts_on_payment_pages"] = {
        "pass": len(third_party_script_hosts) == 0,
        "evidence": {"third_party_script_hosts": limit_list(sorted(third_party_script_hosts), 25)},
    }

    json_out(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
