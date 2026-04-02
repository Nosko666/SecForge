#!/usr/bin/env python3
"""Sanitize TruffleHog JSONL output: keep only safe metadata, strip raw secrets."""
import json
import sys


def sanitize_record(obj):
    if not isinstance(obj, dict):
        return None
    safe = {}
    safe["DetectorName"] = obj.get("DetectorName") or obj.get("Detector") or ""
    safe["Verified"] = bool(obj.get("Verified", False))
    # Preserve only filesystem metadata (file path + line), never raw secret values.
    source = obj.get("SourceMetadata") or {}
    if isinstance(source, dict):
        data = source.get("Data") or {}
        if isinstance(data, dict):
            fs = data.get("Filesystem") or data.get("filesystem") or {}
            if isinstance(fs, dict):
                safe["SourceMetadata"] = {
                    "Data": {
                        "Filesystem": {
                            "file": fs.get("file") or fs.get("path") or "",
                            "line": fs.get("line") or "",
                        }
                    }
                }
    return safe


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.jsonl> <output.jsonl>", file=sys.stderr)
        return 2
    in_path = sys.argv[1]
    out_path = sys.argv[2]
    with open(in_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            safe = sanitize_record(obj)
            if safe:
                fout.write(json.dumps(safe, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
