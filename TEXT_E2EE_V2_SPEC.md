# Bale E2EE compact text transport (v12)

## Goals

The legacy `ENC:` format uses Base64, which expands encrypted bytes by roughly 4/3 and can reach
Bale's text limit quickly. the current transport therefore uses an authenticated compact text envelope that compresses
before encryption and packs 24 bits into two Unicode code points.

## Key derivation

`key = SHA-256(UTF-8(trim(passphrase)))`

The resulting 32 bytes are used as the AES-256-GCM key. This intentionally matches BEE3FILE v1 and
the legacy text implementation for passphrase compatibility.

## Single-message format

```
E2:<rem>:<base4096>
```

- `rem`: `0`, `1`, or `2`, the original binary byte count modulo 3.
- binary encrypted payload: `12-byte random nonce || AES-GCM(ciphertext || 16-byte tag)`.
- AES-GCM AAD: ASCII `BEE2TEXT`.
- plaintext encrypted frame:
  - magic bytes: `89 42 45 45 32` (`\x89BEE2`)
  - one flag byte: `0` = raw UTF-8, `1` = zlib/DEFLATE UTF-8
  - body.
- Compression is used only when it makes the framed payload smaller.

The frame marker/flag are themselves encrypted and authenticated.

## Base-4096 packing

Alphabet: code points U+4E00..U+5DFF (4096 symbols).

For each group of up to 3 input bytes:

1. pad to a 24-bit integer;
2. output high 12 bits as one alphabet character;
3. output low 12 bits as another alphabet character;
4. use `rem` to remove padding on decode.

Thus 3 binary bytes use 2 Bale text characters, versus 4 ASCII characters in Base64.

## Long-message format

```
E2C:<message-id>:<index>/<total>:<rem>:<base4096>
```

- `message-id`: random 12-hex identifier in the current encoder.
- `index`: 1-based chunk index.
- `total`: total chunk count.
- AES-GCM AAD for chunk `i`:

```
BEE2TEXT:<message-id>:<index>:<total>
```

Because message id/index/total are AAD, moving, renumbering or changing a chunk invalidates its tag.

## Wire budgets

- Browser extension outbound target: <= 3850 characters per ciphertext Bale message.
- Hermes plugin outbound target: <= 3900 characters per ciphertext Bale message.
- Encrypted media captions use a stricter 900-character target; if the logical caption cannot fit in
  one encrypted caption, the media is sent without a caption and the caption follows as normal
  encrypted text messages.

Limits are applied to the FINAL ciphertext envelope, not to plaintext length.

## Reassembly

User -> Hermes:
- each E2C chunk is independently authenticated/decrypted;
- the adapter buffers chunks by chat/message-id;
- only after every chunk is present is one logical plaintext turn dispatched to Hermes;
- incomplete chunk sets expire.

Hermes -> user:
- each transport chunk is a separate Bale message so it cannot exceed the platform limit;
- The extension decrypts/renders each bubble locally.

## Compatibility

Readers accept:
- `ENC:` legacy Base64 AES-GCM;
- `ENC2:` compatibility Base64 compressed envelope from development builds;
- `E2:` compact single-message format;
- `E2C:` compact chunked format.

Canonical writers use `E2:` / `E2C:`.


## Browser decompression compatibility

`TEXT2_FLAG_DEFLATE = 1` contains an RFC 1950 zlib-wrapped DEFLATE stream, matching Python
`zlib.compress()`. Standards-compliant `DecompressionStream("deflate")` consumes this form. v12
also provides a compatibility fallback that strips the zlib wrapper, tries `deflate-raw`, and
verifies the original Adler-32 checksum.

The `rem` field in `E2:<rem>:` is unrelated to compression. It only records the original encrypted
binary length modulo 3 for Base4096 packing.

---
<sub>vibecoded with ai</sub>
