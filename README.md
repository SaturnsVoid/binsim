# binsim — Binary Similarity Analyzer

Compare two files — Windows EXEs, Linux ELF binaries, firmware images,
documents, anything — and get a **similarity percentage** plus a list of
the **readable strings** they have in common.

**Pure Python 3 standard library. No external tools, no dependencies.**

## Usage

```bash
python3 binsim.py FILE_A FILE_B [options]
```

Options:

| Flag              | Description                                          |
|-------------------|------------------------------------------------------|
| `--min-len N`     | Minimum string length to extract (default: 6)        |
| `--html FILE`     | Write a styled HTML report to FILE                   |
| `--json FILE`     | Write a machine-readable JSON result to FILE         |
| `--max-strings N` | Max shared strings shown in console (default: 25)    |
| `--no-color`      | Disable colors / icons (also auto-off when piped)    |

Examples:

```bash
# Quick compare
python3 binsim.py old.exe new.exe

# Full report
python3 binsim.py firmware_v1.bin firmware_v2.bin --html report.html
```

## How the score works

The similarity % is a weighted blend of four independent signals:

| Signal              | Weight | Method                                        |
|---------------------|--------|-----------------------------------------------|
| Common strings      | 35%    | Jaccard overlap of extracted readable strings |
| Shared chunks       | 35%    | Jaccard overlap of 4 KiB block MD5 fingerprints |
| Byte profile        | 20%    | Cosine similarity of 256-bin byte histograms  |
| Entropy / size      | 10%    | Shannon entropy closeness + size ratio        |

Verdict tiers: `IDENTICAL` ≥ 100 · `NEARLY IDENTICAL` ≥ 80 ·
`SIMILAR` ≥ 50 · `SOMEWHAT SIMILAR` ≥ 25 · `LOOSELY RELATED` ≥ 5 ·
`DIFFERENT` < 5.

String extraction supports printable ASCII and UTF-16LE (Windows-style),
extracted with a streaming block reader so large files don't need to fit
in RAM. File type detection uses magic bytes only (PE/EXE, ELF, Mach-O,
ZIP, GZip, PDF, PNG, JPEG, MP4, SQLite, TAR, …).

## Requirements

Python 3.8+ (developed/tested on 3.14). Works offline.
