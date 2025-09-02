#!/usr/bin/env python3

"""
rarADSExtractor.py
Pure-Python RAR5 ADS extractor (no unrar.exe, no WinRAR).

What it does
------------
- Parses RAR5 headers (CRC32 -> varint HEAD_SIZE -> HEAD_TYPE -> HEAD_FLAGS).
- For each header, collects header body, extra area, and data area.
- Heuristically detects ADS markers like ":<streamname>" embedded by WinRAR.
- Carves the ADS payload and writes it to disk.
- If the payload looks like plain text (UTF-8 or UTF-16LE), also writes a .decoded.txt.

Notes
-----
- Works with RAR5 archives where WinRAR stored ADS metadata.
- If the ADS was compressed/encrypted in the archive, the raw payload will likely
  not be directly readable; the script still saves the exact bytes.

Usage
-----
python rarADSExtractor.py <archive.rar> [output_dir]
"""

import os, re, sys, gzip, zlib, bz2, lzma

RAR5_MAGIC = b'Rar!\x1a\x07\x01\x00'

def read_varint_with_len(f):
    result = 0
    shift = 0
    n = 0
    while True:
        b = f.read(1)
        if not b:
            raise EOFError("Unexpected EOF reading varint")
        n += 1
        byte = b[0]
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, n

def parse_headers(path):
    headers = []
    with open(path, "rb") as f:
        if f.read(8) != RAR5_MAGIC:
            raise ValueError("Not a RAR5 file")
        while True:
            crc = f.read(4)
            if len(crc) < 4:
                break
            try:
                head_size, _ = read_varint_with_len(f)
            except EOFError:
                break
            pos_after_size = f.tell()
            t = f.read(1)
            if not t:
                break
            head_type = t[0]
            flags, _ = read_varint_with_len(f)
            extra_size = data_size = 0
            if flags & 0x01:
                extra_size, _ = read_varint_with_len(f)
            if flags & 0x02:
                data_size, _ = read_varint_with_len(f)
            header_end = pos_after_size + head_size
            remaining = header_end - f.tell()
            body = f.read(remaining) if remaining > 0 else b""
            extra = f.read(extra_size) if extra_size else b""
            data = f.read(data_size) if data_size else b""
            headers.append({"type": head_type, "flags": flags, "body": body, "extra": extra, "data": data})
    return headers

def guess_main_filename(blob_before_stream):
    m = None
    for m in re.finditer(rb'([A-Za-z0-9_\-\.]+\.[A-Za-z0-9]{1,16})', blob_before_stream):
        pass
    return m.group(1).decode("ascii", "ignore") if m else "unknown"

def printable_ratio(text):
    if not text:
        return 0.0
    printable = sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in text)
    return printable / len(text)

def try_text_codecs(data):
    codecs = ["utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be", "latin-1"]
    for enc in codecs:
        try:
            txt = data.decode(enc)
            if printable_ratio(txt) >= 0.8:
                return ("text:"+enc, txt)
        except Exception:
            continue
    return None

def try_generic_decompress_then_text(data):
    # common compressors
    for label, fn in (("gzip", gzip.decompress),
                      ("zlib", zlib.decompress),
                      ("bz2", bz2.decompress),
                      ("lzma", lzma.decompress)):
        try:
            decomp = fn(data)
            dec = try_text_codecs(decomp)
            if dec:
                enc, txt = dec
                return (f"{label}+{enc}", txt)
        except Exception:
            continue
    return None

def extract_ads_from_headers(headers, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for h in headers:
        blob = h["body"] + h["extra"] + h["data"]
        m = re.search(rb':([A-Za-z0-9_\-\.]+)', blob)
        if not m:
            continue
        stream_name = m.group(1).decode("ascii", "ignore")
        base_name = guess_main_filename(blob[:m.start()])
        payload = blob[m.end():]
        if not payload:
            continue
        raw_name = f"{base_name.replace('.', '_')}__{stream_name}"
        raw_path = os.path.join(out_dir, raw_name)
        with open(raw_path, "wb") as f:
            f.write(payload)

        decoded = try_text_codecs(payload)
        if not decoded:
            decoded = try_generic_decompress_then_text(payload)

        decoded_path = None
        decoded_preview = None
        method = None
        if decoded:
            method, text = decoded
            decoded_path = raw_path + ".decoded.txt"
            with open(decoded_path, "w", encoding="utf-8") as f:
                f.write(text)
            decoded_preview = text[:200]

        results.append({
            "base": base_name,
            "stream": stream_name,
            "raw_path": raw_path,
            "raw_size": len(payload),
            "decoded_path": decoded_path,
            "decoded_method": method,
            "decoded_preview": decoded_preview
        })
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python rarADSExtractor.py <archive.rar> [output_dir]")
        sys.exit(1)
    rar_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "ADS_DUMP"
    headers = parse_headers(rar_path)
    results = extract_ads_from_headers(headers, out_dir)
    if not results:
        print("No ADS-like streams found.")
        sys.exit(2)
    for r in results:
        print(f"[+] {r['base']} :: {r['stream']} -> {r['raw_path']} ({r['raw_size']} bytes)")
        if r['decoded_path']:
            print(f"    [decoded via {r['decoded_method']}] {r['decoded_path']}")
            if r['decoded_preview']:
                prev = r['decoded_preview'].replace('\\n','\\n')
                print(f"    [preview] {prev}")

if __name__ == "__main__":
    main()
