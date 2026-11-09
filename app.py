"""File Inspector - lightweight static file analysis service.

Endpoints
  GET  /              UI
  GET  /api/health    liveness + version
  POST /api/analyze   multipart file -> hashes, entropy, type, strings
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

VERSION = "1.0.0"
MAX_BYTES = 20 * 1024 * 1024  # 20 MiB

app = FastAPI(title="File Inspector", version=VERSION)
app.mount("/static", StaticFiles(directory="static"), name="static")

MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (zip/jar/docx/apk)"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"\xfd7zXZ\x00", "xz archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat / Java class"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"#!", "script (shebang)"),
    (b"<?xml", "XML document"),
    (b"{", "JSON (probable)"),
    (b"\xef\xbb\xbf", "UTF-8 text with BOM"),
]


def detect_type(data: bytes) -> str:
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    if not data:
        return "empty"
    sample = data[:4096]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return "text (probable)" if printable / len(sample) > 0.95 else "unknown binary"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def entropy_blocks(data: bytes, block: int = 4096, limit: int = 64) -> list[float]:
    out = []
    for i in range(0, min(len(data), block * limit), block):
        out.append(shannon_entropy(data[i : i + block]))
    return out


STR_RE = re.compile(rb"[\x20-\x7e]{6,}")


def extract_strings(data: bytes, limit: int = 50) -> list[str]:
    seen, out = set(), []
    for m in STR_RE.finditer(data):
        s = m.group().decode("ascii")
        if s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
    return out


def elf_info(data: bytes) -> dict | None:
    if not data.startswith(b"\x7fELF") or len(data) < 20:
        return None
    bits = {1: 32, 2: 64}.get(data[4], "?")
    endian = {1: "little", 2: "big"}.get(data[5], "?")
    fmt = "<" if data[5] == 1 else ">"
    e_type, e_machine = struct.unpack_from(fmt + "HH", data, 16)
    types = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
    machines = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 243: "RISC-V"}
    return {
        "class": bits,
        "endian": endian,
        "type": types.get(e_type, str(e_type)),
        "machine": machines.get(e_machine, str(e_machine)),
    }


def analyze(data: bytes, filename: str) -> dict:
    ent = shannon_entropy(data)
    return {
        "version": VERSION,
        "filename": filename,
        "size": len(data),
        "type": detect_type(data),
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "entropy": ent,
        "entropy_hint": (
            "likely packed/encrypted/compressed" if ent > 7.2
            else "mixed/binary" if ent > 5.0
            else "low entropy (text/structured)"
        ),
        "entropy_blocks": entropy_blocks(data),
        "elf": elf_info(data),
        "strings": extract_strings(data),
    }


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.post("/api/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"file too large (> {MAX_BYTES} bytes)")
    return analyze(data, file.filename or "upload")
