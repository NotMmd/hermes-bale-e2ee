# BEE3FILE v1 binary format (extension v3-v7)

All integers below are unsigned 32-bit little-endian. AES-GCM tags are 128 bits. IVs are 96 bits (12 bytes). The key is `SHA-256(UTF-8(passphrase))` imported directly as an AES-GCM key.

## v7 outer transport metadata

The encrypted container is transported as a generic document. The outer `File` MUST NOT expose the original metadata.

Recommended/current v7 outer values:

```
filename: attachment-<16 lowercase hex chars>.bin
MIME:     application/octet-stream
```

The original filename, extension, MIME and mtime exist only in the authenticated encrypted header below. Receivers must ignore the generic outer filename after successful decryption and restore `meta.name` / `meta.type`.

## Container

```
offset  size   field
0       8      ASCII magic: BEE3FILE
8       12     header_iv
20      4      header_cipher_len (u32le)
24      N      header_cipher || 16-byte GCM tag (WebCrypto output)
...     repeat body chunks
```

Header AES-GCM:
- plaintext: UTF-8 JSON metadata
- IV: `header_iv`
- AAD: ASCII bytes `BEE3FILE`
- tag length: 128

Metadata JSON:

```json
{
  "v": 1,
  "name": "original.ext",
  "type": "original/mime",
  "size": 12345,
  "lastModified": 1700000000000,
  "chunkSize": 1048576,
  "chunks": 1
}
```

## Body chunk record

For each chunk index `i` from `0` to `meta.chunks - 1`:

```
12 bytes   chunk_iv
4 bytes    chunk_cipher_len (u32le)
N bytes    chunk_cipher || 16-byte GCM tag
```

Chunk AES-GCM:
- plaintext: original file bytes for that chunk
- IV: fresh random 12-byte IV
- AAD: UTF-8 bytes of exactly `BEE3FILE:chunk:<i>:<totalChunks>`
- tag length: 128

`totalChunks = max(1, ceil(original_size / 1048576))`.
A zero-byte file therefore still contains one authenticated empty plaintext chunk (cipher length 16, only the GCM tag).

## Validation / fail-closed rules for Hermes

1. Require exact 8-byte magic `BEE3FILE`.
2. Reject truncated header, `header_cipher_len < 16`, or unreasonable header length.
3. AES-GCM authenticate the header with AAD `BEE3FILE`; never parse unauthenticated metadata.
4. Require `meta.v == 1`, integer `chunks >= 1`, safe non-negative `size`.
5. For each chunk, reject lengths `< 16` or truncation, then authenticate with the exact per-index AAD.
6. Reject trailing bytes after the final expected chunk.
7. Verify total decrypted byte count equals `meta.size`.
8. On any failure, reject the media. Do NOT treat it as plaintext fallback in E2EE mode.
9. After successful decryption, restore filename from `meta.name` and MIME from `meta.type`; do not trust the generic outer `.bin` metadata.

## v8 compatibility note
The BEE3FILE v1 wire format is unchanged. v8 may infer a display MIME type from the authenticated
decrypted bytes only when older senders stored a generic `application/octet-stream` type. This inference
does not bypass AES-GCM authentication and is not written back into the encrypted wire format.

---
<sub>vibecoded with ai</sub>
