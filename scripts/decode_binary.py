#!/usr/bin/env python3
"""Decode CFGB binaries used by this repository."""

from __future__ import annotations

import argparse
import html
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class DecodeError(Exception):
    pass


@dataclass
class Reader:
    data: bytes
    off: int = 0

    def read(self, n: int) -> bytes:
        if self.off + n > len(self.data):
            raise DecodeError(f"unexpected EOF at offset {self.off}, wanted {n} bytes")
        b = self.data[self.off : self.off + n]
        self.off += n
        return b

    def read_uvarint(self) -> int:
        shift = 0
        value = 0
        while True:
            if self.off >= len(self.data):
                raise DecodeError("unexpected EOF while reading varuint")
            byte = self.data[self.off]
            self.off += 1
            value |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                return value
            shift += 7
            if shift > 63:
                raise DecodeError("varuint too large")

    def read_varstr(self) -> str:
        n = self.read_uvarint()
        raw = self.read(n)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError(f"invalid UTF-8 at offset {self.off - n}") from exc


def fnv1a32(buf: bytes) -> int:
    h = 2166136261
    for b in buf:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def decode_cfgb(path: Path, data: bytes) -> dict[str, Any]:
    r = Reader(data)
    magic = r.read(4)
    if magic != b"CFGB":
        raise DecodeError("not a CFGB binary")

    version = r.read_uvarint()
    if version != 1:
        raise DecodeError(f"unsupported CFGB version: {version} (expected 1)")

    mode_raw = r.read_uvarint()
    mode = "full" if mode_raw == 1 else "call"

    string_count = r.read_uvarint()
    strings = [r.read_varstr() for _ in range(string_count)]

    fn_count = r.read_uvarint()
    log_fn_count = r.read_uvarint()

    def s(idx: int) -> str:
        if idx < 0 or idx >= len(strings):
            raise DecodeError(f"string index out of range: {idx}")
        return strings[idx]

    functions: list[dict[str, Any]] = []
    for _ in range(fn_count):
        name_idx = r.read_uvarint()
        entry = r.read_uvarint()
        exit_ = r.read_uvarint()
        flags = r.read_uvarint()

        peer_count = r.read_uvarint()
        peers = [s(r.read_uvarint()) for _ in range(peer_count)]

        param_count = r.read_uvarint()
        param_values: list[list[str]] = []
        for _ in range(param_count):
            value_count = r.read_uvarint()
            param_values.append([s(r.read_uvarint()) for _ in range(value_count)])

        block_count = r.read_uvarint()
        blocks: list[dict[str, Any]] = []
        for _ in range(block_count):
            block_id = r.read_uvarint()
            line_count = r.read_uvarint()
            lines = [s(r.read_uvarint()) for _ in range(line_count)]
            succ_count = r.read_uvarint()
            succ = [r.read_uvarint() for _ in range(succ_count)]
            block = {
                "id": block_id,
                "lines": lines,
                "successors": succ,
            }
            blocks.append(block)

        loop_groups: list[list[int]] = []
        loop_group_count = r.read_uvarint()
        for _ in range(loop_group_count):
            member_count = r.read_uvarint()
            loop_groups.append([r.read_uvarint() for _ in range(member_count)])

        functions.append(
            {
                "name": s(name_idx),
                "entryBlockId": entry,
                "exitBlockId": exit_,
                "flags": {
                    "hasDirectRecursion": bool(flags & 0x1),
                    "hasIndirectRecursion": bool(flags & 0x2),
                    "callsStateChange": bool(flags & 0x4),
                },
                "indirectRecursionPeers": peers,
                "stateChangeParameterValues": param_values,
                "loopGroups": loop_groups,
                "blocks": blocks,
            }
        )

    checksum_offset = r.off
    checksum_stored = r.read_uvarint()
    checksum_computed = fnv1a32(data[:checksum_offset])

    if r.off != len(data):
        trailer = len(data) - r.off
    else:
        trailer = 0

    return {
        "type": "CFGB",
        "path": str(path),
        "version": version,
        "mode": mode,
        "modeRaw": mode_raw,
        "stringCount": string_count,
        "functionCount": fn_count,
        "logFunctionCount": log_fn_count,
        "checksum": {
            "stored": checksum_stored,
            "computed": checksum_computed,
            "matches": checksum_stored == checksum_computed,
        },
        "trailingBytes": trailer,
        "strings": strings,
        "functions": functions,
    }


def decode_file(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 4:
        raise DecodeError("file too small")

    magic = data[:4]
    if magic == b"CFGB":
        return decode_cfgb(path, data)
    raise DecodeError(f"unknown magic: {magic!r}")


def _render_cfgb(decoded: dict[str, Any]) -> str:
    rows = []
    for fn in decoded["functions"]:
        rows.append(
            """
            <details class="card">
                <summary><b>{name}</b> entry={entry} exit={exit} blocks={block_count}</summary>
                <div class="meta">direct-rec={dr} indirect-rec={ir} state-change={sc} loop-groups={loop_groups}</div>
                <table>
                <thead><tr><th>Block</th><th>Lines</th><th>Successors</th></tr></thead>
                <tbody>
                    {block_rows}
                </tbody>
                </table>
            </details>
            """.format(
                name=html.escape(str(fn["name"])),
                entry=fn["entryBlockId"],
                exit=fn["exitBlockId"],
                block_count=len(fn["blocks"]),
                dr=str(fn["flags"]["hasDirectRecursion"]).lower(),
                ir=str(fn["flags"]["hasIndirectRecursion"]).lower(),
                sc=str(fn["flags"]["callsStateChange"]).lower(),
                block_rows="\n".join(
                    "<tr><td>{id}</td><td>{lines}</td><td>{succ}</td></tr>".format(
                        id=block["id"],
                        lines=html.escape(" | ".join(block["lines"])) if block["lines"] else "",
                        succ=", ".join(str(s) for s in block["successors"]),
                    )
                    for block in fn["blocks"]
                ),
                loop_groups=html.escape(json.dumps(fn.get("loopGroups", []))),
            )
        )

    return "\n".join(rows)


def render_html(decoded: dict[str, Any]) -> str:
    summary = []
    if decoded["type"] == "CFGB":
        summary.append(f"version={decoded['version']}")
        summary.append(f"mode={decoded['mode']}")
        summary.append(f"functions={decoded['functionCount']}")
        summary.append(f"checksum-ok={str(decoded['checksum']['matches']).lower()}")
        content = _render_cfgb(decoded)
    else:
        raise DecodeError(f"unsupported decoded type: {decoded['type']}")

    return """<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
    <title>Binary Visualizer</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; background: #f3f6fb; color: #0f172a; }}
        .wrap {{ max-width: 1100px; margin: 24px auto; padding: 0 16px; }}
        .header {{ background: white; border: 1px solid #dbe4f0; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
        .title {{ margin: 0 0 8px 0; font-size: 22px; }}
        .sub {{ color: #334155; font-size: 14px; }}
        .card {{ background: white; border: 1px solid #dbe4f0; border-radius: 12px; padding: 10px 12px; margin: 10px 0; }}
        summary {{ cursor: pointer; }}
        .meta {{ color: #334155; margin-top: 8px; font-size: 13px; }}
        .path {{ margin-top: 8px; font-family: Consolas, monospace; font-size: 13px; overflow-wrap: anywhere; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; font-size: 13px; }}
        th {{ background: #f8fafc; }}
        pre {{ background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class=\"wrap\">
        <div class=\"header\">
            <h1 class=\"title\">{kind} Visualizer</h1>
            <div class=\"sub\">file: {path}</div>
            <div class=\"sub\">{summary}</div>
        </div>
        {content}
        <details class=\"card\">
            <summary><b>Raw JSON</b></summary>
            <pre>{raw}</pre>
        </details>
    </div>
</body>
</html>
""".format(
        kind=decoded["type"],
        path=html.escape(decoded["path"]),
        summary=html.escape(" | ".join(summary)),
        content=content,
        raw=html.escape(json.dumps(decoded, indent=2)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HTML visualizer for CFGB binaries")
    parser.add_argument("input", type=Path, help="Path to cfg.cfgb")
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        help="Output HTML file (default: <input>.html)",
    )
    args = parser.parse_args()

    try:
        decoded = decode_file(args.input)
    except (OSError, DecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output = args.output if args.output is not None else Path(str(args.input) + ".html")
    html_text = render_html(decoded)
    try:
        output.write_text(html_text, encoding="utf-8")
    except OSError as exc:
        print(f"error: failed to write HTML: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote HTML visualizer: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
