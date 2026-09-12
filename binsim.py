#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
binsim — Binary Similarity Analyzer
===================================
Compare two files (Windows EXEs, ELF binaries, firmware, documents, ...)
and report a blended similarity %, plus the readable strings they share.

Pure Python 3 standard library. No external tools or dependencies.

Usage:
    python3 binsim.py FILE_A FILE_B [options]

    --min-len N        Minimum string length to extract (default: 6)
    --html FILE        Write an HTML report to FILE
    --json FILE        Write a JSON result to FILE
    --max-strings N    Max shared strings shown in console (default: 25)
    --no-color         Disable ANSI colors/icons
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
import datetime

CHUNK_SIZE = 4096          # fixed chunk size for structural hashing
BLOCK_SIZE = 1024 * 1024   # streaming read block
CARRY = 64                 # carry bytes between blocks for string extraction

# ----------------------------------------------------------------------------
# Terminal / icons
# ----------------------------------------------------------------------------

class Theme:
    """ANSI colors + unicode icons. `plain` disables everything."""
    def __init__(self, color: bool):
        self.color = color
        if color:
            self.reset   = "\033[0m"
            self.bold    = "\033[1m"
            self.dim     = "\033[2m"
            self.red     = "\033[31m"
            self.green   = "\033[32m"
            self.yellow  = "\033[33m"
            self.blue    = "\033[34m"
            self.magenta = "\033[35m"
            self.cyan    = "\033[36m"
            self.white   = "\033[37m"
            self.bg_red    = "\033[41m"
            self.bg_green  = "\033[42m"
            self.bg_yellow = "\033[43m"
            self.bg_blue   = "\033[44m"
        else:
            for c in ("reset","bold","dim","red","green","yellow","blue",
                      "magenta","cyan","white","bg_red","bg_green",
                      "bg_yellow","bg_blue"):
                setattr(self, c, "")

        icons = {
            "search":  "🔍", "chart":   "📊", "note":   "📝", "puzzle": "🧩",
            "flame":   "🔥", "wave":    "📈", "check":  "✔️", "cross":  "✖️",
            "warn":    "⚠️", "doc":     "📄", "docA":   "🅰️", "docB":   "🅱️",
            "gear":    "⚙️", "star":    "⭐", "globe":  "🌐", "spark":  "✨",
            "ruler":   "📐", "link":    "🔗", "save":   "💾", "info":   "ℹ️",
        }
        if color:
            for k, v in icons.items():
                setattr(self, k, v)
        else:
            plain = {"search": ">", "chart": "%", "note": "T", "puzzle": "#",
                     "flame": "~", "wave": "^", "check": "+", "cross": "x",
                     "warn": "!", "doc": "o", "docA": "A", "docB": "B",
                     "gear": "*", "star": "*", "globe": "@", "spark": " ",
                     "ruler": "|", "link": "&", "save": "$", "info": "i"}
            for k, v in plain.items():
                setattr(self, k, v)

    def c(self, text, color) -> str:
        if not self.color:
            return str(text)
        return f"{getattr(self, color)}{text}{self.reset}"

    def line(self, char="─", width=62) -> str:
        return self.c(char * width, "dim")


# ----------------------------------------------------------------------------
# File type sniffing (magic bytes only — no external tools)
# ----------------------------------------------------------------------------

def sniff_type(head: bytes) -> str:
    if head.startswith(b"MZ"):
        return "Windows PE executable (EXE/DLL)"
    if head.startswith(b"\x7fELF"):
        return "Linux ELF binary"
    if head.startswith(b"\xfe\xed\xfa\xce") or head.startswith(b"\xcf\xfa\xed\xfe") \
            or head.startswith(b"\xca\xfe\xba\xbe"):
        return "Mach-O binary"
    if head.startswith(b"\xca\xfe\xd0\x0d"):
        return "Java class"
    if head.startswith(b"wOCR"):
        return "Nintendo Wii ISO"
    if head.startswith(b"NES\x1a"):
        return "NES ROM"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP archive / Office Open XML"
    if head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        return "ZIP archive (empty/spanned)"
    if head.startswith(b"\x1f\x8b"):
        return "GZip compressed"
    if head.startswith(b"BZh"):
        return "BZip2 compressed"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "XZ compressed"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip archive"
    if head.startswith(b"Rar!"):
        return "RAR archive"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "Zstandard compressed"
    if head.startswith(b"OggS"):
        return "OGG media"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "WAV audio"
    if head.startswith(b"RIFF"):
        return "RIFF container"
    if head.startswith(b"ID3") or (len(head) > 1 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return "MP3 audio"
    if head.startswith(b"FLAC"):
        return "FLAC audio"
    if head.startswith(b"\x00\x00\x00") and head[4:8] in (b"ftyp", b"moov", b"mdat"):
        return "MP4/MOV media"
    if head.startswith(b"BM"):
        return "BMP image"
    if head.startswith(b"\x89PNG"):
        return "PNG image"
    if head.startswith(b"GIF8"):
        return "GIF image"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head.startswith(b"%PDF"):
        return "PDF document"
    if head.startswith(b"SQLite format 3\x00"):
        return "SQLite database"
    if head.startswith(b"USTAR") or head[257:262] == b"ustar":
        return "TAR archive"
    if head.startswith(b"#!"):
        return "Script (shebang)"
    if head.startswith(b"<?xml") or head.startswith(b"<!DOCTYPE"):
        return "XML document"
    if head.startswith(b"firmware") or head.startswith(b"crfs"):
        return "Firmware container"
    return "Unknown / raw data"


# ----------------------------------------------------------------------------
# Core analysis primitives
# ----------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def file_entropy(path: str) -> float:
    """Streaming Shannon entropy over the whole file."""
    counts = [0] * 256
    total = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            total += len(block)
            for b in block:
                counts[b] += 1
    if not total:
        return 0.0
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def byte_histogram(path: str):
    counts = [0] * 256
    with open(path, "rb") as f:
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            for b in block:
                counts[b] += 1
    return counts


def cosine_similarity(v1, v2) -> float:
    d1 = math.sqrt(sum(x * x for x in v1))
    d2 = math.sqrt(sum(x * x for x in v2))
    if d1 == 0 or d2 == 0:
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    return dot / (d1 * d2)


def jaccard(s1: set, s2: set) -> float:
    if not s1 and not s2:
        return 0.0
    inter = len(s1 & s2)
    union = len(s1 | s2)
    return inter / union if union else 0.0


def chunk_hashes(path: str) -> set:
    """MD5 of each fixed-offset CHUNK_SIZE block (structural fingerprint)."""
    hashes = set()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hashes.add(hashlib.md5(chunk).digest())
    return hashes


def extract_strings(path: str, min_len: int = 6, cap: int = 200000):
    """Streaming printable-ASCII string extractor (like `strings`)."""
    found = set()
    n_found = 0
    tail = b""
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)

    def scan_ascii(piece: bytes):
        nonlocal n_found
        for m in pat.finditer(piece):
            s = m.group().decode("ascii", "ignore").strip()
            if len(s) >= min_len and s not in found:
                found.add(s)
                n_found += 1
                if n_found >= cap:
                    return True
        return False

    with open(path, "rb") as f:
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            piece = tail + block
            if scan_ascii(tail + block):
                break
            tail = block[-CARRY:]
    return found


def extract_utf16_strings(path: str, min_len: int = 6, cap: int = 100000):
    """UTF-16LE runs: printable char followed by 0x00 (Windows style)."""
    found = set()
    n = 0
    tail = b""
    pat = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    with open(path, "rb") as f:
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            piece = tail + block
            for m in pat.finditer(piece):
                s = m.group().decode("utf-16-le", "ignore").strip()
                if len(s) >= min_len and s not in found:
                    found.add(s)
                    n += 1
                    if n >= cap:
                        return found
            tail = piece[-CARRY:]
    return found


def file_meta(path: str) -> dict:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(512)
    return {
        "path": os.path.abspath(path),
        "name": os.path.basename(path),
        "size": size,
        "size_h": human_size(size),
        "type": sniff_type(head),
        "sha256": hashlib.sha256(head).hexdigest()[:16] + "…",
    }


def human_size(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"


# ----------------------------------------------------------------------------
# Verdict tiers
# ----------------------------------------------------------------------------

def verdict_for(score: float):
    if score >= 99.999:
        return ("IDENTICAL", "star", "green")
    if score >= 80:
        return ("NEARLY IDENTICAL", "check", "green")
    if score >= 50:
        return ("SIMILAR", "puzzle", "yellow")
    if score >= 25:
        return ("SOMEWHAT SIMILAR", "wave", "yellow")
    if score >= 5:
        return ("LOOSELY RELATED", "link", "cyan")
    return ("DIFFERENT", "cross", "red")


def color_bar(theme, score: float, width=24) -> str:
    filled = int(round(score / 100 * width))
    bar = "█" * filled + "░" * (width - filled)
    if score >= 80:
        col = "green"
    elif score >= 50:
        col = "yellow"
    else:
        col = "red"
    return theme.c(bar, col)


# ----------------------------------------------------------------------------
# Main comparison
# ----------------------------------------------------------------------------

def compare(file_a: str, file_b: str, min_len=6) -> dict:
    meta_a = file_meta(file_a)
    meta_b = file_meta(file_b)

    with open(file_a, "rb") as f:
        head_a = f.read(512)
    with open(file_b, "rb") as f:
        head_b = f.read(512)

    # Shortcut: byte-identical
    if head_a == head_b and meta_a["size"] == meta_b["size"]:
        h1 = hashlib.sha256()
        h2 = hashlib.sha256()
        with open(file_a, "rb") as f1, open(file_b, "rb") as f2:
            while True:
                a = f1.read(BLOCK_SIZE)
                b = f2.read(BLOCK_SIZE)
                if not a and not b:
                    break
                h1.update(a)
                h2.update(b)
        identical = h1.digest() == h2.digest()
    else:
        identical = False

    result = {"file_a": meta_a, "file_b": meta_b, "identical": identical}

    if identical:
        strings = extract_strings(file_a, min_len)
        strings |= extract_utf16_strings(file_a, min_len)
        result.update({
            "score": 100.0,
            "breakdown": {
                "strings": 100.0, "chunks": 100.0,
                "histogram": 100.0, "entropy": 100.0,
            },
            "shared_strings": sorted(strings, key=len, reverse=True),
            "only_a": [], "only_b": [],
            "counts": {"shared": len(strings), "only_a": 0, "only_b": 0},
            "entropy": {"a": file_entropy(file_a), "b": file_entropy(file_b)},
            "min_len": min_len,
        })
        return result

    strings_a = extract_strings(file_a, min_len)
    strings_b = extract_strings(file_b, min_len)
    strings_a |= extract_utf16_strings(file_a, min_len)
    strings_b |= extract_utf16_strings(file_b, min_len)

    shared = strings_a & strings_b
    only_a = strings_a - strings_b
    only_b = strings_b - strings_a

    chunks_a = chunk_hashes(file_a)
    chunks_b = chunk_hashes(file_b)

    hist_a = byte_histogram(file_a)
    hist_b = byte_histogram(file_b)

    ent_a = file_entropy(file_a)
    ent_b = file_entropy(file_b)

    str_sim = jaccard(strings_a, strings_b) * 100
    chunk_sim = jaccard(chunks_a, chunks_b) * 100
    hist_sim = cosine_similarity(hist_a, hist_b) * 100
    size_sim = (min(meta_a["size"], meta_b["size"]) /
                max(meta_a["size"], meta_b["size"]) * 100) if max(meta_a["size"], meta_b["size"]) else 100.0
    ent_diff = abs(ent_a - ent_b)
    ent_sim = max(0.0, 100.0 - ent_diff * 40)

    # Weighted blend — "balanced": strings + chunk structure dominate,
    # byte profile and entropy/size provide supporting evidence.
    weights = {"strings": 0.35, "chunks": 0.35, "histogram": 0.20, "entropy": 0.10}
    size_part = 0.5 * ent_sim + 0.5 * size_sim
    score = (weights["strings"] * str_sim +
             weights["chunks"] * chunk_sim +
             weights["histogram"] * hist_sim +
             weights["entropy"] * size_part)

    result.update({
        "score": round(score, 1),
        "breakdown": {
            "strings": round(str_sim, 1),
            "chunks": round(chunk_sim, 1),
            "histogram": round(hist_sim, 1),
            "entropy": round(size_part, 1),
        },
        "shared_strings": sorted(shared, key=len, reverse=True),
        "only_a": sorted(only_a, key=len, reverse=True),
        "only_b": sorted(only_b, key=len, reverse=True),
        "counts": {"shared": len(shared), "only_a": len(only_a), "only_b": len(only_b)},
        "entropy": {"a": ent_a, "b": ent_b},
        "chunk_stats": {"a": len(chunks_a), "b": len(chunks_b),
                        "shared": len(chunks_a & chunks_b)},
        "weights": weights,
        "min_len": min_len,
    })
    return result


# ----------------------------------------------------------------------------
# Console rendering
# ----------------------------------------------------------------------------

def render_console(result: dict, theme: Theme, max_strings=25):
    a, b = result["file_a"], result["file_b"]
    v, icon, col = verdict_for(result["score"])
    print()
    print(theme.c("🔍 binsim — Binary Similarity Analyzer", "bold"))
    print(theme.line())

    print(f" {theme.c(theme.docA, 'blue')} File A: {theme.c(a['name'], 'bold')} "
          f"{theme.c(f'({a['size_h']}, {a['type']})', 'dim')}")
    print(f" {theme.c(theme.docB, 'magenta')} File B: {theme.c(b['name'], 'bold')} "
          f"{theme.c(f'({b['size_h']}, {b['type']})', 'dim')}")
    print(theme.line())

    score = result["score"]
    verdict_txt = "IDENTICAL" if result["identical"] else v
    print(f" {theme.c('📊', 'bold')} Similarity: "
          f"{theme.c(theme.bold + f'{score:.1f}%', col)}  {color_bar(theme, score)}  "
          f"{theme.c(f'{verdict_txt}', col)}")
    print()

    bd = result["breakdown"]
    rows = [
        ("note",   "Common strings",  "strings"),
        ("puzzle", "Shared chunks",   "chunks"),
        ("wave",   "Byte profile",    "histogram"),
        ("flame",  "Entropy / size",  "entropy"),
    ]
    for ic, label, key in rows:
        val = bd[key]
        col2 = "green" if val >= 70 else ("yellow" if val >= 40 else "red")
        print(f"   {getattr(theme, ic)} {label:<16} "
              f"{theme.c(theme.bold + f'{val:>6.1f}%', col2)}  {color_bar(theme, val, 20)}")

    ent = result.get("entropy", {})
    print()
    print(f"   {getattr(theme, 'flame')} Entropy  "
          f"{theme.c('A', 'blue')} {theme.dim}{ent.get('a', 0):.3f}{theme.reset}  "
          f"{theme.c('B', 'magenta')} {theme.dim}{ent.get('b', 0):.3f}{theme.reset}")
    if "chunk_stats" in result:
        cs = result["chunk_stats"]
        print(f"   {getattr(theme, 'puzzle')} Chunks   "
              f"{theme.dim}A {cs['a']} | B {cs['b']} | shared {cs['shared']}{theme.reset}")
    print(theme.line())

    counts = result["counts"]
    print(f" {getattr(theme, 'note')} Strings: "
          f"{theme.c(theme.bold + str(counts['shared']), 'green')} shared, "
          f"{theme.c(str(counts['only_a']), 'blue')} only in A, "
          f"{theme.c(str(counts['only_b']), 'magenta')} only in B "
          f"{theme.c(f'(min length {result.get('min_len', 6)})', 'dim')}")

    if counts["shared"] == 0:
        print(f"   {getattr(theme, 'warn')} {theme.c('No shared strings found.', 'yellow')}")
    else:
        print(f" {theme.c('Top shared strings:', 'bold')}")
        for s in result["shared_strings"][:max_strings]:
            shown = s if len(s) <= 72 else s[:69] + "..."
            print(f"   {getattr(theme, 'spark')} {theme.c(shown, 'white')}")

    print()


# ----------------------------------------------------------------------------
# HTML report
# ----------------------------------------------------------------------------

HTML_TOP = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>binsim report — {a_name} vs {b_name}</title>
<style>
:root {{
  --bg:#0f1218; --card:#171b23; --card2:#1e242e; --text:#e8ecf2;
  --muted:#98a2b3; --accent:#4da3ff; --green:#43d17c; --yellow:#f5c542;
  --red:#f5544d; --border:#2a3140;
}}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font:15px/1.55 "Segoe UI",
  system-ui, -apple-system, sans-serif; margin:0; padding:32px 16px; }}
.wrap {{ max-width:980px; margin:0 auto; }}
h1 {{ font-size:26px; margin:0 0 4px; }}
.sub {{ color:var(--muted); margin-bottom:28px; }}
.card {{ background:var(--card); border:1px solid var(--border);
  border-radius:14px; padding:24px; margin-bottom:20px; }}
.score {{ display:flex; align-items:center; gap:24px; flex-wrap:wrap; }}
.pct {{ font-size:58px; font-weight:800; letter-spacing:-1px; }}
.verdict {{ display:inline-block; padding:5px 14px; border-radius:999px;
  font-size:13px; font-weight:700; letter-spacing:.5px; }}
.barbg {{ flex:1; min-width:260px; height:14px; background:var(--card2);
  border-radius:999px; overflow:hidden; }}
.barfg {{ height:100%; border-radius:999px; }}
.files {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
.file {{ background:var(--card2); border-radius:10px; padding:16px; }}
.file h3 {{ margin:0 0 8px; font-size:15px; }}
.file .name {{ font-weight:700; word-break:break-all; }}
.kv {{ color:var(--muted); font-size:13px; }}
.bd {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr));
  gap:14px; }}
.bditem {{ background:var(--card2); border-radius:10px; padding:16px; }}
.bditem .lbl {{ color:var(--muted); font-size:13px; }}
.bditem .val {{ font-size:28px; font-weight:800; }}
.bditem .mini {{ height:8px; background:#141922; border-radius:999px;
  overflow:hidden; margin-top:8px; }}
.bditem .minifg {{ height:100%; }}
table {{ width:100%; border-collapse:collapse; font-size:13.5px; }}
th {{ text-align:left; color:var(--muted); font-weight:600; padding:8px 10px;
  border-bottom:1px solid var(--border); }}
td {{ padding:6px 10px; border-bottom:1px solid #20262f;
  font-family:"Cascadia Code", Consolas, monospace; word-break:break-all; }}
tr:hover td {{ background:var(--card2); }}
.note {{ color:var(--muted); font-size:13px; }}
footer {{ color:var(--muted); font-size:12.5px; text-align:center;
  margin-top:26px; }}
@media (max-width:700px) {{ .files {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body><div class="wrap">
<h1>🔍 binsim — Binary Similarity Report</h1>
<div class="sub">Generated {date} · min string length {min_len}</div>
"""

HTML_BOTTOM = """<footer>binsim · pure-Python binary similarity analyzer ·
score = 35% strings + 35% shared chunks + 20% byte profile + 10% entropy/size</footer>
</div></body></html>
"""


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def score_color(score: float) -> str:
    if score >= 80: return "var(--green)"
    if score >= 50: return "var(--yellow)"
    return "var(--red)"


def render_html(result: dict, max_table=500) -> str:
    a, b = result["file_a"], result["file_b"]
    score = result["score"]
    verdict_txt = "IDENTICAL" if result["identical"] else verdict_for(score)[0]
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    min_len = result.get("min_len", 6)
    col = score_color(score)

    out = HTML_TOP.format(a_name=esc(a["name"]), b_name=esc(b["name"]),
                          date=date, min_len=min_len)

    out += f"""<div class="card score">
  <div><div class="pct" style="color:{col}">{score:.1f}%</div></div>
  <div style="flex:1;min-width:260px">
    <div class="barbg"><div class="barfg" style="width:{max(1.5, score):.1f}%;
      background:linear-gradient(90deg,{col}77,{col})"></div></div>
    <div class="note" style="margin-top:8px">Weighted similarity
      (35% strings + 35% chunks + 20% byte profile + 10% entropy/size)</div>
  </div>
  <div><span class="verdict" style="background:{col}22;color:{col};
    border:1px solid {col}55">{esc(verdict_txt)}</span></div>
</div>"""

    # Files
    def file_card(tag, label, m, hcol):
        return f"""<div class="file">
  <h3 style="color:{hcol}">File {tag} · {label}</h3>
  <div class="name">{esc(m["name"])}</div>
  <div class="kv">{esc(m["type"])}<br>{esc(m["size_h"])} ·
    SHA-256 (head): {esc(m["sha256"])}</div>
</div>"""

    out += f"""<div class="card">
  <div class="files">
    {file_card("A", a["path"], a, "var(--accent)")}
    {file_card("B", b["path"], b, "var(--accent)")}
  </div>
</div>"""

    # Breakdown
    bd = result["breakdown"]
    items = [("📝 Common strings", "strings"), ("🧩 Shared chunks", "chunks"),
             ("📈 Byte profile", "histogram"), ("🔥 Entropy / size", "entropy")]
    ent = result.get("entropy", {})
    out += """<div class="card"><h3 style="margin:0 0 16px">Score breakdown</h3>
  <div class="bd">"""
    for lbl, key in items:
        val = bd[key]
        c = score_color(val)
        out += f"""<div class="bditem">
  <div class="lbl">{lbl}</div>
  <div class="val" style="color:{c}">{val:.1f}%</div>
  <div class="mini"><div class="minifg" style="width:{max(1.5, val):.1f}%;background:{c}"></div></div>
</div>"""
    out += f"""</div>
  <p class="note" style="margin:16px 0 0">Shannon entropy — A: {ent.get('a',0):.3f} ·
  B: {ent.get('b',0):.3f}</p>
</div>"""

    # Strings
    counts = result["counts"]
    out += f"""<div class="card">
  <h3 style="margin:0 0 6px">📝 Shared readable strings</h3>
  <p class="note">{counts['shared']} shared · {counts['only_a']} only in A ·
     {counts['only_b']} only in B</p>"""
    if counts["shared"] == 0:
        out += '<p class="note" style="color:var(--yellow)">⚠️ No shared strings found.</p>'
    else:
        out += f"""<table><tr><th>#</th><th>String</th><th>Len</th></tr>"""
        for i, s in enumerate(result["shared_strings"][:max_table], 1):
            out += f"<tr><td>{i}</td><td>{esc(s)}</td><td>{len(s)}</td></tr>"
        out += "</table>"
        if counts["shared"] > max_table:
            out += f'<p class="note" style="margin-top:10px">…and '
            out += f"{counts['shared'] - max_table} more (not shown).</p>"
    out += "</div>"
    out += HTML_BOTTOM
    return out


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="binsim",
        description="Compare two files and report similarity % + shared strings "
                    "(pure Python, no external tools).")
    p.add_argument("file_a")
    p.add_argument("file_b")
    p.add_argument("--min-len", type=int, default=6, dest="min_len",
                   help="minimum string length to extract (default 6)")
    p.add_argument("--html", metavar="FILE", help="write HTML report")
    p.add_argument("--json", metavar="FILE", dest="json_file", help="write JSON result")
    p.add_argument("--max-strings", type=int, default=25, help="console string limit (default 25)")
    p.add_argument("--no-color", action="store_true", help="disable colors/icons")
    args = p.parse_args(argv)

    for path in (args.file_a, args.file_b):
        if not os.path.isfile(path):
            print(f"✖️ Error: not a file: {path}", file=sys.stderr)
            return 2

    theme = Theme(color=(not args.no_color) and sys.stdout.isatty())

    result = compare(args.file_a, args.file_b, args.min_len)
    render_console(result, theme, args.max_strings)

    if args.html:
        try:
            with open(args.html, "w", encoding="utf-8") as f:
                f.write(render_html(result))
            print(f" {getattr(theme, 'globe')} {theme.c(f'HTML report → {args.html}', 'green')}")
        except OSError as e:
            print(f" {getattr(theme, 'warn')} {theme.c(f'HTML write failed: {e}', 'red')}")
    if args.json_file:
        export = {k: v for k, v in result.items() if k in
                  ("file_a", "file_b", "score", "breakdown", "counts",
                   "shared_strings", "only_a", "only_b", "identical", "min_len")}
        try:
            with open(args.json_file, "w", encoding="utf-8") as f:
                json.dump(export, f, indent=2)
            print(f" {getattr(theme, 'save')} {theme.c(f'JSON result → {args.json_file}', 'green')}")
        except OSError as e:
            print(f" {getattr(theme, 'warn')} {theme.c(f'JSON write failed: {e}', 'red')}")

    print(theme.line())
    print(f" {getattr(theme, 'info')} Done. "
          f"{theme.dim}binsim · stdlib-only · similarity analyzer{theme.reset}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
