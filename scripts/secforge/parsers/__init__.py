"""SecForge v2 parser sub-package.

Registry-based dispatch: each parser registers which file patterns it handles.
parse_session() walks a session directory and dispatches to registered parsers.
to_v1_findings() converts v2 dicts back to v1 Finding dataclass for the shim.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Parser registry: (relative_path_pattern, parser_function)
# Pattern is matched against the relative path within the session dir.
_REGISTRY: List[Tuple[str, Callable[[Path, Dict[str, Any]], List[Dict[str, Any]]]]] = []


def register(rel_path: str):
    """Decorator to register a parser function for a specific relative path."""
    def decorator(func):
        _REGISTRY.append((rel_path, func))
        return func
    return decorator


def parse_file(rel_path: str, fpath: Path, context: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Try to parse a file using the v2 registry.

    Returns list of v2 finding dicts, or None if no parser matched.
    """
    for pattern, parser_func in _REGISTRY:
        if rel_path == pattern:
            try:
                return parser_func(fpath, context)
            except Exception:
                return None
    return None


def parse_session(session_dir: Path, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Walk a session directory and parse all known tool outputs.

    Returns a flat list of v2 finding dicts (not yet fingerprinted or deduped).
    """
    if context is None:
        context = _build_context(session_dir)

    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(session_dir, followlinks=False):
        root_path = Path(root)
        for fname in files:
            fpath = root_path / fname
            try:
                if fpath.is_symlink():
                    continue
            except Exception:
                continue

            rel = str(fpath.relative_to(session_dir)).replace("\\", "/")
            result = parse_file(rel, fpath, context)
            if result is not None:
                findings.extend(result)

    return findings


def _build_context(session_dir: Path) -> Dict[str, Any]:
    """Build context dict from preflight.json if it exists."""
    import json
    ctx: Dict[str, Any] = {
        "target_host": "",
        "target_url": "",
        "session_dir": str(session_dir),
    }
    preflight_path = session_dir / "preflight.json"
    if preflight_path.exists():
        try:
            pf = json.loads(preflight_path.read_text(encoding="utf-8"))
            if isinstance(pf, dict):
                ctx["target_host"] = str(pf.get("target_host") or "")
                ctx["target_url"] = str(pf.get("target_url") or pf.get("target_full_url") or "")
                ctx["target_input"] = str(pf.get("target_input") or "")
        except Exception:
            pass
    return ctx


def to_v1_finding(v2: Dict[str, Any]) -> Any:
    """Convert a v2 finding dict to a v1 Finding-like object.

    Returns a dict compatible with v1's Finding.to_json() output shape.
    This is used by the shim layer in merge-reports.py during migration.
    """
    try:
        from secforge.schema import to_v1_dict
        return to_v1_dict(v2)
    except ImportError:
        # Minimal fallback
        return {
            "severity": (v2.get("severity") or "INFO").upper(),
            "tool": v2.get("tool", ""),
            "category": v2.get("category", ""),
            "title": v2.get("title", ""),
            "url": "",
            "description": v2.get("description", ""),
            "evidence": v2.get("evidence", ""),
            "remediation": "",
            "cwe": "",
            "owasp": "",
            "status": "open",
            "also_found_by": [],
        }


# --- Import all parser modules so they register themselves ---
# Each parser module uses @register("relative/path") decorator.

def _import_parsers():
    """Import all parser modules. Called at module load time."""
    import importlib
    parser_modules = [
        "secforge.parsers.builtin",
        "secforge.parsers.nuclei",
        "secforge.parsers.nmap",
        "secforge.parsers.testssl",
        "secforge.parsers.wafw00f",
        # More parsers added in Step 6
    ]
    for mod_name in parser_modules:
        try:
            importlib.import_module(mod_name)
        except ImportError:
            pass


_import_parsers()
