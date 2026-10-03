"""
Bale E2EE crypto helpers.

Text wire formats:
- Legacy: ENC:<base64(12-byte nonce || AES-GCM ciphertext+tag)>
- Compact v2 single: E2:<remainder>:<base4096 payload>
- Compact v2 chunk:  E2C:<message-id>:<index>/<total>:<remainder>:<base4096 payload>

Compact text opportunistically DEFLATE-compresses plaintext, then uses AES-256-GCM
and a CJK base-4096 transport alphabet. Three bytes are encoded as two Unicode
code points, so natural-language responses are usually far shorter than base64.
Chunk headers are bound into AES-GCM AAD so index/total/message-id cannot be modified
undetected. Legacy uncompressed E2/E2C remains readable.

Binary media remains BEE3FILE v1 for compatibility with extension v3+.
"""

import base64
import hashlib
import json
import os
import re
import struct
import math
import zlib
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TEXT_PREFIX = "ENC:"
# Legacy/compat Base64 v2 envelope. Canonical v9 traffic uses the shorter
# E2/E2C base4096 format below; ENC/ENC2 remain readable for migration.
TEXT_V2_PREFIX = "ENC2:"
TEXT_V2_AAD = b"BEE2TEXT"
TEXT_CHUNK_PREFIX = "BEE2CHUNK:"
TEXT_WIRE_SAFE_LIMIT = 3900
MAX_TEXT_DECOMPRESSED_BYTES = 512 * 1024
TEXT2_PREFIX = "E2:"
TEXT2_CHUNK_PREFIX = "E2C:"
TEXT2_AAD = b"BEE2TEXT"
TEXT2_ALPHABET_BASE = 0x4E00
TEXT2_ALPHABET_SIZE = 4096
TEXT2_SAFE_MESSAGE_CHARS = 3850
# 5000 plaintext UTF-8 bytes -> about 3352 base4096 chars including GCM overhead.
TEXT2_PLAIN_CHUNK_BYTES = 5000
# Binary marker is impossible at the start of valid UTF-8 plaintext (0x89 is a continuation byte),
# so legacy E2 ciphertext can be distinguished losslessly after AES-GCM decryption.
TEXT2_FRAME_MAGIC = b"\x89BEE2"
TEXT2_FLAG_RAW = 0
TEXT2_FLAG_DEFLATE = 1

LEGACY_MAGIC = b"BENC"
MEDIA_MAGIC = b"BENC"
BEE3_MAGIC = b"BEE3FILE"

_CHUNK_RE = re.compile(r"^E2C:([0-9a-f]{8,32}):(\d+)/(\d+):([012]):(.+)$", re.S)
_SINGLE_RE = re.compile(r"^E2:([012]):(.+)$", re.S)


def derive_key(passphrase_or_key: str) -> bytes:
    raw = passphrase_or_key.strip().encode("utf-8")
    return hashlib.sha256(raw).digest()

def _text_v2_payload(plain_text: str) -> bytes:
    """One authenticated flags byte plus raw or zlib-compressed UTF-8."""
    raw = plain_text.encode("utf-8")
    compressed = zlib.compress(raw, 9)
    if len(compressed) + 4 < len(raw):
        return b"\x01" + compressed
    return b"\x00" + raw


def _safe_zlib_decompress(body: bytes) -> bytes:
    dec = zlib.decompressobj()
    out = dec.decompress(body, MAX_TEXT_DECOMPRESSED_BYTES + 1)
    if len(out) > MAX_TEXT_DECOMPRESSED_BYTES or dec.unconsumed_tail:
        raise ValueError("ENC2 decompressed text exceeds safety limit")
    out += dec.flush()
    if len(out) > MAX_TEXT_DECOMPRESSED_BYTES:
        raise ValueError("ENC2 decompressed text exceeds safety limit")
    return out


def text_wire_length_v2(plain_text: str) -> int:
    payload_len = len(_text_v2_payload(plain_text))
    binary_len = 12 + payload_len + 16
    return len(TEXT_V2_PREFIX) + 4 * math.ceil(binary_len / 3)


def encrypt_text_v2(plain_text: str, key: bytes) -> str:
    """ENC2 = optional DEFLATE -> AES-256-GCM -> Base64 ASCII."""
    nonce = os.urandom(12)
    body = AESGCM(key).encrypt(nonce, _text_v2_payload(plain_text), TEXT_V2_AAD)
    return TEXT_V2_PREFIX + base64.b64encode(nonce + body).decode("ascii")


def _best_v2_plain_split(text: str, max_wire_chars: int) -> Tuple[str, str]:
    if text_wire_length_v2(text) <= max_wire_chars:
        return text, ""
    lo, hi, best = 1, len(text), 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if text_wire_length_v2(text[:mid]) <= max_wire_chars:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    floor = max(1, int(best * 0.70))
    prefix = text[:best]
    candidates = [prefix.rfind("\n\n"), prefix.rfind("\n"), prefix.rfind(" ")]
    valid = [i for i in candidates if i >= floor]
    cut = max(valid) if valid else best
    if cut < best and prefix[cut:cut + 2] == "\n\n":
        cut += 2
    elif cut < best:
        cut += 1
    cut = max(1, min(cut, best))
    return text[:cut], text[cut:]


def encrypt_text_v2_chunks(plain_text: str, key: bytes, max_wire_chars: int = TEXT_WIRE_SAFE_LIMIT) -> List[str]:
    """Encrypt one logical bot response into Bale-safe ENC2 wire bubbles."""
    if not plain_text:
        return [encrypt_text_v2("", key)]
    out: List[str] = []
    rest = plain_text
    while rest:
        piece, rest = _best_v2_plain_split(rest, max_wire_chars)
        wire = encrypt_text_v2(piece, key)
        if len(wire) > max_wire_chars:
            raise ValueError(f"ENC2 wire chunk exceeds safe limit: {len(wire)}")
        out.append(wire)
    return out


def _b4096_encode(data: bytes) -> Tuple[int, str]:
    rem = len(data) % 3
    chars: List[str] = []
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        value = int.from_bytes(chunk.ljust(3, b"\x00"), "big")
        chars.append(chr(TEXT2_ALPHABET_BASE + ((value >> 12) & 0xFFF)))
        chars.append(chr(TEXT2_ALPHABET_BASE + (value & 0xFFF)))
    return rem, "".join(chars)


def _b4096_decode(text: str, rem: int) -> bytes:
    if rem not in (0, 1, 2) or len(text) % 2:
        raise ValueError("invalid base4096 length")
    out = bytearray()
    for i in range(0, len(text), 2):
        a = ord(text[i]) - TEXT2_ALPHABET_BASE
        b = ord(text[i + 1]) - TEXT2_ALPHABET_BASE
        if not (0 <= a < 4096 and 0 <= b < 4096):
            raise ValueError("invalid base4096 character")
        value = (a << 12) | b
        out.extend(value.to_bytes(3, "big"))
    if rem:
        if not out:
            raise ValueError("invalid base4096 remainder")
        trim = 3 - rem
        if trim:
            del out[-trim:]
    return bytes(out)


def _encode_text2_frame(plain_text: str) -> bytes:
    """Frame UTF-8 with an authenticated compression flag before AES-GCM.

    Compression is opportunistic: incompressible text stays raw.  The marker is
    encrypted, so Bale learns only the final ciphertext length, not the flag.
    """
    raw = plain_text.encode("utf-8")
    compressed = zlib.compress(raw, 9)
    if len(compressed) + len(TEXT2_FRAME_MAGIC) + 1 + 4 < len(raw):
        return TEXT2_FRAME_MAGIC + bytes([TEXT2_FLAG_DEFLATE]) + compressed
    return TEXT2_FRAME_MAGIC + bytes([TEXT2_FLAG_RAW]) + raw


def _decode_text2_frame(payload: bytes) -> str:
    # Backward compatibility: pre-v1.4 E2 encrypted raw UTF-8 directly.
    if not payload.startswith(TEXT2_FRAME_MAGIC):
        return payload.decode("utf-8")
    pos = len(TEXT2_FRAME_MAGIC)
    if len(payload) <= pos:
        raise ValueError("truncated E2 text frame")
    flag = payload[pos]
    body = payload[pos + 1:]
    if flag == TEXT2_FLAG_DEFLATE:
        body = _safe_zlib_decompress(body)
    elif flag != TEXT2_FLAG_RAW:
        raise ValueError("unsupported E2 text frame flag")
    return body.decode("utf-8")


def _encrypt_text_payload(plain_text: str, key: bytes, aad: bytes) -> Tuple[int, str]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, _encode_text2_frame(plain_text), aad)
    return _b4096_encode(nonce + ct)


def _decrypt_text_payload(encoded: str, rem: int, key: bytes, aad: bytes) -> str:
    payload = _b4096_decode(encoded, rem)
    if len(payload) < 28:
        raise ValueError("ciphertext too short")
    nonce, body = payload[:12], payload[12:]
    plain = AESGCM(key).decrypt(nonce, body, aad)
    return _decode_text2_frame(plain)


def encrypt_text(plain_text: str, key: bytes) -> str:
    """Legacy ENC encoder. New callers should use encrypt_text_v2()."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    return TEXT_PREFIX + base64.b64encode(nonce + ct_with_tag).decode("ascii")


def encrypt_text_compact(plain_text: str, key: bytes) -> str:
    rem, body = _encrypt_text_payload(plain_text, key, TEXT2_AAD)
    return f"{TEXT2_PREFIX}{rem}:{body}"


def _split_utf8(text: str, max_bytes: int) -> List[str]:
    if len(text.encode("utf-8")) <= max_bytes:
        return [text]
    parts: List[str] = []
    current: List[str] = []
    current_bytes = 0
    last_break = -1
    for ch in text:
        b = len(ch.encode("utf-8"))
        if current_bytes + b > max_bytes and current:
            # Prefer a recent whitespace/newline boundary, but never make a tiny chunk.
            cut = last_break + 1 if last_break >= max(1, len(current) // 2) else len(current)
            parts.append("".join(current[:cut]))
            current = current[cut:]
            current_bytes = len("".join(current).encode("utf-8"))
            last_break = max((i for i, c in enumerate(current) if c.isspace()), default=-1)
        current.append(ch)
        current_bytes += b
        if ch.isspace():
            last_break = len(current) - 1
    if current:
        parts.append("".join(current))
    return parts


def encrypt_text_chunks(plain_text: str, key: bytes, max_chars: int = TEXT2_SAFE_MESSAGE_CHARS) -> List[str]:
    """Return one or more compact authenticated Bale-safe text messages."""
    single = encrypt_text_compact(plain_text, key)
    if len(single) <= max_chars:
        return [single]

    # Start with a conservative byte split then reduce any unusual chunk that still
    # exceeds the transport limit (e.g. a larger-than-expected header/id).
    pieces = _split_utf8(plain_text, TEXT2_PLAIN_CHUNK_BYTES)
    while True:
        msg_id = os.urandom(6).hex()
        total = len(pieces)
        encoded: List[str] = []
        too_large = False
        for idx, piece in enumerate(pieces, start=1):
            aad = f"BEE2TEXT:{msg_id}:{idx}:{total}".encode("ascii")
            rem, body = _encrypt_text_payload(piece, key, aad)
            wire = f"{TEXT2_CHUNK_PREFIX}{msg_id}:{idx}/{total}:{rem}:{body}"
            if len(wire) > max_chars:
                too_large = True
                break
            encoded.append(wire)
        if not too_large:
            return encoded
        # Split each piece in half by UTF-8 bytes and retry with a new authenticated total.
        new_pieces: List[str] = []
        for piece in pieces:
            raw_len = len(piece.encode("utf-8"))
            if raw_len <= 256:
                raise ValueError("unable to fit encrypted text into Bale message limit")
            new_pieces.extend(_split_utf8(piece, max(128, raw_len // 2)))
        pieces = new_pieces


def parse_text_chunk_header(cipher_payload: str) -> Optional[Tuple[str, int, int]]:
    m = _CHUNK_RE.match(cipher_payload or "")
    if not m:
        return None
    return m.group(1), int(m.group(2)), int(m.group(3))


def decrypt_text(cipher_payload: str, key: bytes) -> Tuple[bool, str]:
    """Decrypt legacy ENC:, compact E2:, or one E2C: chunk.

    For E2C this returns the authenticated plaintext *piece*.  Reassembly is the
    adapter's responsibility because it has chat/message context.
    """
    if not cipher_payload:
        return False, cipher_payload
    try:
        if cipher_payload.startswith(TEXT_V2_PREFIX):
            raw_b64 = cipher_payload[len(TEXT_V2_PREFIX):].strip()
            data = base64.b64decode(raw_b64, validate=True)
            if len(data) < 29:
                return False, "Error: Ciphertext too short"
            payload = AESGCM(key).decrypt(data[:12], data[12:], TEXT_V2_AAD)
            if not payload or (payload[0] & ~0x01):
                return False, "Error: Unsupported ENC2 flags"
            body = payload[1:]
            if payload[0] & 0x01:
                body = _safe_zlib_decompress(body)
            return True, body.decode("utf-8")

        if cipher_payload.startswith(TEXT_PREFIX):
            raw_b64 = cipher_payload[len(TEXT_PREFIX):].strip()
            data = base64.b64decode(raw_b64)
            if len(data) < 28:
                return False, "Error: Ciphertext too short"
            plain = AESGCM(key).decrypt(data[:12], data[12:], None)
            return True, plain.decode("utf-8")

        m = _SINGLE_RE.match(cipher_payload)
        if m:
            rem = int(m.group(1))
            return True, _decrypt_text_payload(m.group(2), rem, key, TEXT2_AAD)

        m = _CHUNK_RE.match(cipher_payload)
        if m:
            msg_id, idx, total, rem, body = m.groups()
            idx_i, total_i, rem_i = int(idx), int(total), int(rem)
            if total_i < 1 or total_i > 1000 or idx_i < 1 or idx_i > total_i:
                return False, "invalid encrypted chunk header"
            aad = f"BEE2TEXT:{msg_id}:{idx_i}:{total_i}".encode("ascii")
            return True, _decrypt_text_payload(body, rem_i, key, aad)
    except Exception as e:
        return False, f"Decryption failed: {e}"
    return False, cipher_payload


def is_encrypted_text(value: str) -> bool:
    return bool(value) and value.startswith((TEXT_V2_PREFIX, TEXT_PREFIX, TEXT2_PREFIX, TEXT2_CHUNK_PREFIX))


def encrypt_bytes_bee3(data: bytes, filename: str, mime_type: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    chunk_size = 1048576
    total_size = len(data)
    total_chunks = max(1, (total_size + chunk_size - 1) // chunk_size)
    meta: Dict[str, Any] = {
        "v": 1,
        "name": filename or "file",
        "type": mime_type or "application/octet-stream",
        "size": total_size,
        "lastModified": 1700000000000,
        "chunkSize": chunk_size,
        "chunks": total_chunks,
    }
    header_plain = json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    header_iv = os.urandom(12)
    header_cipher = aesgcm.encrypt(header_iv, header_plain, BEE3_MAGIC)
    out = bytearray(BEE3_MAGIC)
    out.extend(header_iv)
    out.extend(struct.pack("<I", len(header_cipher)))
    out.extend(header_cipher)
    for i in range(total_chunks):
        chunk_plain = data[i * chunk_size:min(total_size, (i + 1) * chunk_size)]
        chunk_iv = os.urandom(12)
        aad = f"BEE3FILE:chunk:{i}:{total_chunks}".encode("utf-8")
        chunk_cipher = aesgcm.encrypt(chunk_iv, chunk_plain, aad)
        out.extend(chunk_iv)
        out.extend(struct.pack("<I", len(chunk_cipher)))
        out.extend(chunk_cipher)
    return bytes(out)


def decrypt_bytes_bee3(data: bytes, key: bytes) -> Tuple[bool, bytes, Dict[str, Any]]:
    if not data.startswith(BEE3_MAGIC):
        return False, b"", {}
    try:
        aesgcm = AESGCM(key)
        offset = len(BEE3_MAGIC)
        if offset + 16 > len(data):
            return False, b"", {}
        header_iv = data[offset:offset + 12]
        offset += 12
        (header_len,) = struct.unpack("<I", data[offset:offset + 4])
        offset += 4
        if header_len < 16 or offset + header_len > len(data):
            return False, b"", {}
        header_cipher = data[offset:offset + header_len]
        offset += header_len
        meta = json.loads(aesgcm.decrypt(header_iv, header_cipher, BEE3_MAGIC).decode("utf-8"))
        if meta.get("v") != 1 or "chunks" not in meta or "size" not in meta:
            return False, b"", {}
        total_chunks = int(meta["chunks"])
        expected_size = int(meta["size"])
        if total_chunks < 1 or total_chunks > 100000 or expected_size < 0:
            return False, b"", {}
        decrypted_parts = bytearray()
        for i in range(total_chunks):
            if offset + 16 > len(data):
                return False, b"", {}
            chunk_iv = data[offset:offset + 12]
            offset += 12
            (chunk_len,) = struct.unpack("<I", data[offset:offset + 4])
            offset += 4
            if chunk_len < 16 or offset + chunk_len > len(data):
                return False, b"", {}
            chunk_cipher = data[offset:offset + chunk_len]
            offset += chunk_len
            aad = f"BEE3FILE:chunk:{i}:{total_chunks}".encode("utf-8")
            decrypted_parts.extend(aesgcm.decrypt(chunk_iv, chunk_cipher, aad))
        if len(decrypted_parts) != expected_size or offset != len(data):
            return False, b"", {}
        return True, bytes(decrypted_parts), meta
    except Exception:
        return False, b"", {}


def encrypt_bytes(data: bytes, key: bytes, filename: str = "file", mime_type: str = "application/octet-stream") -> bytes:
    return encrypt_bytes_bee3(data, filename, mime_type, key)


def decrypt_bytes(encrypted_data: bytes, key: bytes) -> Tuple[bool, bytes, Dict[str, Any]]:
    if encrypted_data.startswith(BEE3_MAGIC):
        return decrypt_bytes_bee3(encrypted_data, key)
    if encrypted_data.startswith(LEGACY_MAGIC):
        try:
            data = encrypted_data[len(LEGACY_MAGIC):]
            if len(data) < 28:
                return False, b"", {}
            plain = AESGCM(key).decrypt(data[:12], data[12:], None)
            return True, plain, {"name": "decrypted_file", "type": "application/octet-stream"}
        except Exception:
            return False, b"", {}
    return False, encrypted_data, {}
