(() => {
  "use strict";

  const CHANNEL = "__BALE_E2EE_V12__";
  const STORAGE_KEY = "bale_e2ee_passphrase";
  const PREFIX = "ENC:"; // legacy
  const TEXT_V2_PREFIX = "ENC2:"; // legacy compact Base64 v2
  const TEXT2_PREFIX = "E2:";
  const TEXT2_CHUNK_PREFIX = "E2C:";
  const TEXT2_AAD = new TextEncoder().encode("BEE2TEXT");
  const B4096_BASE = 0x4E00;
  const SAFE_WIRE_CHARS = 3850;
  const PLAIN_CHUNK_BYTES = 5000;
  // New v9 E2 frame: compressed-or-raw UTF-8 is marked *inside* AES-GCM.
  // 0x89 cannot begin valid UTF-8, so old unframed E2 remains losslessly readable.
  const TEXT2_FRAME_MAGIC = new Uint8Array([0x89, 0x42, 0x45, 0x45, 0x32]);
  const TEXT2_FLAG_RAW = 0;
  const TEXT2_FLAG_DEFLATE = 1;
  const WIRE_RE = /(?:ENC2:[A-Za-z0-9+/=]+|ENC:[A-Za-z0-9+/=]+|E2:[012]:[\u4E00-\u5DFF]+|E2C:[0-9a-f]{8,32}:\d+\/\d+:[012]:[\u4E00-\u5DFF]+)/g;
  const WIRE_HINT_RE = /(?:ENC2:|ENC:|E2C:|E2:)/;
  const WIRE_IGNORED_CHAR_RE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/u;
  const FILE_MAGIC_TEXT = "BEE3FILE";
  const FILE_MAGIC = new TextEncoder().encode(FILE_MAGIC_TEXT);
  const FILE_CHUNK_SIZE = 1024 * 1024;
  const MAX_HEADER_SIZE = 128 * 1024;
  const ext = globalThis.browser ?? globalThis.chrome;

  let activeKey = null;
  let configured = false;
  // Positive-result cache only. Never cache decryption failures: a transient
  // key/storage/DOM race must not permanently poison a message.
  const decryptedCache = new Map();
  const decryptInflight = new Map();
  const decryptRetry = new Map();
  const unresolvedWireHosts = new Set();
  let keyEpoch = 0;
  const outgoingPlain = new Map();

  function post(type, payload = {}) {
    window.postMessage({ channel: CHANNEL, type, ...payload }, location.origin);
  }

  function debugEnabled() {
    try { return localStorage.getItem("bale_e2ee_debug") === "1"; } catch (_) { return false; }
  }

  function debugWarn(message, details = {}) {
    if (!debugEnabled()) return;
    try { console.warn("[Bale E2EE]", message, details); } catch (_) {}
  }

  function storageGet(keys) {
    if (globalThis.browser?.storage?.local) return globalThis.browser.storage.local.get(keys);
    return new Promise((resolve, reject) => {
      ext.storage.local.get(keys, (result) => {
        const err = globalThis.chrome?.runtime?.lastError;
        if (err) reject(err);
        else resolve(result || {});
      });
    });
  }

  async function readPassphrase() {
    try {
      const data = await storageGet([STORAGE_KEY]);
      const pass = data?.[STORAGE_KEY];
      if (typeof pass === "string" && pass.trim()) return pass.trim();
    } catch (_) {}
    const local = localStorage.getItem("bale_e2ee_passphrase") || localStorage.getItem(STORAGE_KEY);
    if (typeof local === "string" && local.trim()) return local.trim();
    return "Parand-Simorgh-Blue-739!";
  }

  async function deriveKey() {
    if (activeKey) return activeKey;
    const pass = await readPassphrase();
    configured = Boolean(pass);
    if (!pass) throw new Error("No passphrase configured");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pass));
    activeKey = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    return activeKey;
  }

  function bytesToB64(bytes) {
    let binary = "";
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
    return btoa(binary);
  }

  function b4096Encode(bytes) {
    const rem = bytes.length % 3;
    let text = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const b0 = bytes[i] ?? 0;
      const b1 = bytes[i + 1] ?? 0;
      const b2 = bytes[i + 2] ?? 0;
      const value = (b0 << 16) | (b1 << 8) | b2;
      text += String.fromCharCode(B4096_BASE + ((value >>> 12) & 0xfff));
      text += String.fromCharCode(B4096_BASE + (value & 0xfff));
    }
    return { rem, text };
  }

  function b4096Decode(text, rem) {
    if (![0, 1, 2].includes(rem) || text.length % 2) throw new Error("invalid base4096 payload");
    const out = new Uint8Array((text.length / 2) * 3);
    let o = 0;
    for (let i = 0; i < text.length; i += 2) {
      const a = text.charCodeAt(i) - B4096_BASE;
      const b = text.charCodeAt(i + 1) - B4096_BASE;
      if (a < 0 || a >= 4096 || b < 0 || b >= 4096) throw new Error("invalid base4096 character");
      const value = (a << 12) | b;
      out[o++] = (value >>> 16) & 0xff;
      out[o++] = (value >>> 8) & 0xff;
      out[o++] = value & 0xff;
    }
    const trim = rem ? 3 - rem : 0;
    return trim ? out.slice(0, out.length - trim) : out;
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }

  async function streamTransform(bytes, kind, format = "deflate") {
    const Ctor = kind === "compress" ? globalThis.CompressionStream : globalThis.DecompressionStream;
    if (!Ctor) throw new Error(`${kind}ion stream unavailable`);
    const stream = new Blob([bytes]).stream().pipeThrough(new Ctor(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  function zlibRawPayload(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 6) throw new Error("truncated zlib stream");
    const cmf = bytes[0];
    const flg = bytes[1];
    if ((cmf & 0x0f) !== 8 || (((cmf << 8) | flg) % 31) !== 0) throw new Error("invalid zlib header");
    if (flg & 0x20) throw new Error("zlib preset dictionary unsupported");
    return bytes.slice(2, -4);
  }

  function adler32(bytes) {
    let a = 1;
    let b = 0;
    const MOD = 65521;
    for (let i = 0; i < bytes.length; i += 1) {
      a = (a + bytes[i]) % MOD;
      b = (b + a) % MOD;
    }
    return (((b << 16) | a) >>> 0);
  }

  function zlibExpectedAdler(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) throw new Error("truncated zlib checksum");
    const n = bytes.length;
    return (((bytes[n - 4] << 24) | (bytes[n - 3] << 16) | (bytes[n - 2] << 8) | bytes[n - 1]) >>> 0);
  }

  async function decompressDeflateCompat(bytes) {
    const errors = [];
    if (globalThis.DecompressionStream) {
      try {
        return await streamTransform(bytes, "decompress", "deflate");
      } catch (err) {
        errors.push(err);
      }

      // Python zlib.compress() emits RFC 1950 (zlib-wrapped) DEFLATE. Standards-
      // compliant browsers accept that as "deflate". Some embedded Chromium
      // builds have had stream quirks, so as a compatibility fallback strip the
      // zlib wrapper and try raw DEFLATE, then verify the original Adler-32.
      try {
        const raw = zlibRawPayload(bytes);
        const out = await streamTransform(raw, "decompress", "deflate-raw");
        if (adler32(out) !== zlibExpectedAdler(bytes)) throw new Error("zlib Adler-32 mismatch");
        return out;
      } catch (err) {
        errors.push(err);
      }
    }
    const lastError = errors.length ? errors[errors.length - 1] : null;
    throw new Error(`deflate decompression failed${lastError ? `: ${String(lastError?.message || lastError)}` : ""}`);
  }

  function startsWithBytes(bytes, prefix) {
    if (!(bytes instanceof Uint8Array) || bytes.length < prefix.length) return false;
    for (let i = 0; i < prefix.length; i += 1) if (bytes[i] !== prefix[i]) return false;
    return true;
  }

  async function encodeText2Frame(plain) {
    const raw = new TextEncoder().encode(String(plain ?? ""));
    let body = raw;
    let flag = TEXT2_FLAG_RAW;
    if (globalThis.CompressionStream && raw.length >= 32) {
      try {
        const compressed = await streamTransform(raw, "compress");
        if (compressed.length + TEXT2_FRAME_MAGIC.length + 1 + 4 < raw.length) {
          body = compressed;
          flag = TEXT2_FLAG_DEFLATE;
        }
      } catch (_) {}
    }
    const framed = new Uint8Array(TEXT2_FRAME_MAGIC.length + 1 + body.length);
    framed.set(TEXT2_FRAME_MAGIC, 0);
    framed[TEXT2_FRAME_MAGIC.length] = flag;
    framed.set(body, TEXT2_FRAME_MAGIC.length + 1);
    return framed;
  }

  async function decodeText2Frame(bytes) {
    // Legacy E2/E2C encrypted raw UTF-8 directly.
    if (!startsWithBytes(bytes, TEXT2_FRAME_MAGIC)) return new TextDecoder().decode(bytes);
    const pos = TEXT2_FRAME_MAGIC.length;
    if (bytes.length <= pos) throw new Error("truncated E2 text frame");
    const flag = bytes[pos];
    let body = bytes.slice(pos + 1);
    if (flag === TEXT2_FLAG_DEFLATE) {
      body = await decompressDeflateCompat(body);
      if (body.length > 512 * 1024) throw new Error("decompressed E2 text exceeds safety limit");
    } else if (flag !== TEXT2_FLAG_RAW) {
      throw new Error("unsupported E2 text frame flag");
    }
    return new TextDecoder().decode(body);
  }

  async function encryptCompactPiece(plain, aadBytes) {
    const key = await deriveKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = await encodeText2Frame(plain);
    const body = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 },
      key,
      payload
    ));
    return b4096Encode(concatBytes(iv, body));
  }


  function splitUtf8(text, maxBytes) {
    if (new TextEncoder().encode(text).length <= maxBytes) return [text];
    const parts = [];
    let current = "";
    let currentBytes = 0;
    let lastBreak = -1;
    const byteLen = (value) => new TextEncoder().encode(value).length;
    for (const ch of text) {
      const b = byteLen(ch);
      if (current && currentBytes + b > maxBytes) {
        let cut = current.length;
        if (lastBreak >= Math.max(1, Math.floor(current.length / 2))) cut = lastBreak + 1;
        parts.push(current.slice(0, cut));
        current = current.slice(cut);
        currentBytes = byteLen(current);
        lastBreak = -1;
        for (let i = 0; i < current.length; i += 1) if (/\s/u.test(current[i])) lastBreak = i;
      }
      current += ch;
      currentBytes += b;
      if (/\s/u.test(ch)) lastBreak = current.length - 1;
    }
    if (current) parts.push(current);
    return parts;
  }

  async function encryptTextChunks(plain) {
    const single = await encryptCompactPiece(plain, TEXT2_AAD);
    const singleWire = `${TEXT2_PREFIX}${single.rem}:${single.text}`;
    if (singleWire.length <= SAFE_WIRE_CHARS) return [{ cipher: singleWire, plain }];

    let pieces = splitUtf8(plain, PLAIN_CHUNK_BYTES);
    while (true) {
      const idBytes = crypto.getRandomValues(new Uint8Array(6));
      const msgId = Array.from(idBytes, (b) => b.toString(16).padStart(2, "0")).join("");
      const total = pieces.length;
      const items = [];
      let tooLarge = false;
      for (let i = 0; i < total; i += 1) {
        const idx = i + 1;
        const aad = new TextEncoder().encode(`BEE2TEXT:${msgId}:${idx}:${total}`);
        const enc = await encryptCompactPiece(pieces[i], aad);
        const cipher = `${TEXT2_CHUNK_PREFIX}${msgId}:${idx}/${total}:${enc.rem}:${enc.text}`;
        if (cipher.length > SAFE_WIRE_CHARS) { tooLarge = true; break; }
        items.push({ cipher, plain: pieces[i] });
      }
      if (!tooLarge) return items;
      const next = [];
      for (const piece of pieces) {
        const n = new TextEncoder().encode(piece).length;
        if (n <= 256) throw new Error("Encrypted text cannot fit Bale message limit");
        next.push(...splitUtf8(piece, Math.max(128, Math.floor(n / 2))));
      }
      pieces = next;
    }
  }

  async function decryptText(cipher) {
    try {
      const key = await deriveKey();
      if (cipher.startsWith(PREFIX)) {
        const binary = atob(cipher.slice(PREFIX.length));
        const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
        if (bytes.length < 28) return null;
        const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), tagLength: 128 }, key, bytes.slice(12));
        return new TextDecoder().decode(plain);
      }
      if (cipher.startsWith(TEXT_V2_PREFIX)) {
        const binary = atob(cipher.slice(TEXT_V2_PREFIX.length));
        const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
        if (bytes.length < 29) return null;
        const plain = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: TEXT2_AAD, tagLength: 128 },
          key,
          bytes.slice(12)
        ));
        if (!plain.length || (plain[0] & ~0x01)) return null;
        let body = plain.slice(1);
        if (plain[0] & 0x01) {
          body = await decompressDeflateCompat(body);
          if (body.length > 512 * 1024) return null;
        }
        return new TextDecoder().decode(body);
      }
      let m = cipher.match(/^E2:([012]):([\u4E00-\u5DFF]+)$/u);
      let aad = TEXT2_AAD;
      if (!m) {
        m = cipher.match(/^E2C:([0-9a-f]{8,32}):(\d+)\/(\d+):([012]):([\u4E00-\u5DFF]+)$/u);
        if (!m) return null;
        const [, msgId, idx, total, rem, body] = m;
        aad = new TextEncoder().encode(`BEE2TEXT:${msgId}:${idx}:${total}`);
        const bytes = b4096Decode(body, Number(rem));
        if (bytes.length < 28) return null;
        const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: aad, tagLength: 128 }, key, bytes.slice(12)));
        return await decodeText2Frame(plain);
      }
      const [, rem, body] = m;
      const bytes = b4096Decode(body, Number(rem));
      if (bytes.length < 28) return null;
      const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: aad, tagLength: 128 }, key, bytes.slice(12)));
      return await decodeText2Frame(plain);
    } catch (err) {
      debugWarn("text decrypt attempt failed", {
        wire: String(cipher || "").split(":", 1)[0] || "unknown",
        chars: String(cipher || "").length,
        error: String(err?.message || err)
      });
      return null;
    }
  }


  function isEncryptedWire(value) {
    return typeof value === "string" && (value.startsWith(PREFIX) || value.startsWith(TEXT_V2_PREFIX) || value.startsWith(TEXT2_PREFIX) || value.startsWith(TEXT2_CHUNK_PREFIX));
  }

  function retryDelayMs(failures) {
    return Math.min(8000, 350 * (2 ** Math.max(0, failures - 1)));
  }

  function noteDecryptFailure(cipher) {
    const prev = decryptRetry.get(cipher);
    const failures = Math.min(8, (prev?.failures || 0) + 1);
    decryptRetry.set(cipher, { failures, retryAfter: Date.now() + retryDelayMs(failures) });
  }

  async function getDecryptedPlain(cipher, { force = false } = {}) {
    const outgoing = outgoingPlain.get(cipher);
    if (typeof outgoing === "string") return outgoing;

    const cached = decryptedCache.get(cipher);
    if (typeof cached === "string") return cached;

    const retry = decryptRetry.get(cipher);
    if (!force && retry && retry.retryAfter > Date.now()) return null;

    const existing = decryptInflight.get(cipher);
    if (existing) return existing;

    const epoch = keyEpoch;
    const pending = (async () => {
      const plain = await decryptText(cipher);
      if (epoch !== keyEpoch) return null;
      if (typeof plain === "string") {
        decryptedCache.set(cipher, plain);
        decryptRetry.delete(cipher);
        return plain;
      }
      noteDecryptFailure(cipher);
      const retry = decryptRetry.get(cipher);
      debugWarn("text decrypt scheduled for retry", {
        wire: String(cipher || "").split(":", 1)[0] || "unknown",
        chars: String(cipher || "").length,
        failures: retry?.failures || 1
      });
      return null;
    })().finally(() => {
      if (decryptInflight.get(cipher) === pending) decryptInflight.delete(cipher);
    });

    decryptInflight.set(cipher, pending);
    return pending;
  }

  function u32le(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value >>> 0, true);
    return out;
  }

  function readU32(bytes, offset) {
    if (offset + 4 > bytes.byteLength) throw new Error("truncated encrypted file");
    return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
  }

  function equalPrefix(bytes, prefix) {
    if (bytes.byteLength < prefix.byteLength) return false;
    for (let i = 0; i < prefix.byteLength; i += 1) if (bytes[i] !== prefix[i]) return false;
    return true;
  }

  function fileChunkAAD(index, total) {
    return new TextEncoder().encode(`${FILE_MAGIC_TEXT}:chunk:${index}:${total}`);
  }

  function asciiAt(bytes, offset, text) {
    if (offset + text.length > bytes.length) return false;
    for (let i = 0; i < text.length; i += 1) {
      if (bytes[offset + i] !== text.charCodeAt(i)) return false;
    }
    return true;
  }

  function inferMimeFromHead(head, declaredName = "") {
    if (!(head instanceof Uint8Array)) return "";
    if (head.length >= 8 && head[0] === 0x89 && asciiAt(head, 1, "PNG\r\n\x1a\n")) return "image/png";
    if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return "image/jpeg";
    if (asciiAt(head, 0, "GIF87a") || asciiAt(head, 0, "GIF89a")) return "image/gif";
    if (head.length >= 12 && asciiAt(head, 0, "RIFF") && asciiAt(head, 8, "WEBP")) return "image/webp";
    if (asciiAt(head, 0, "%PDF-")) return "application/pdf";
    if (head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && [0x03, 0x05, 0x07].includes(head[2])) {
      if (/\.apk$/i.test(declaredName)) return "application/vnd.android.package-archive";
      return "application/zip";
    }
    if (head.length >= 12 && asciiAt(head, 4, "ftyp")) return "video/mp4";
    if (head.length >= 4 && head[0] === 0x1a && head[1] === 0x45 && head[2] === 0xdf && head[3] === 0xa3) return "video/webm";
    if (asciiAt(head, 0, "OggS")) return "audio/ogg";
    if (asciiAt(head, 0, "ID3") || (head.length >= 2 && head[0] === 0xff && (head[1] & 0xe0) === 0xe0)) return "audio/mpeg";
    if (head.length >= 12 && asciiAt(head, 0, "RIFF") && asciiAt(head, 8, "WAVE")) return "audio/wav";
    if (head.length >= 4 && head[0] === 0x52 && head[1] === 0x61 && head[2] === 0x72 && head[3] === 0x21) return "application/x-rar-compressed";
    if (head.length >= 6 && head[0] === 0x37 && head[1] === 0x7a && head[2] === 0xbc && head[3] === 0xaf) return "application/x-7z-compressed";
    return "";
  }

  const EXTENSION_MAP = {
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "video/mp4": ".mp4",
    "video/quicktime": ".mov",
    "video/webm": ".webm",
    "video/x-matroska": ".mkv",
    "audio/ogg": ".ogg",
    "audio/opus": ".opus",
    "audio/mpeg": ".mp3",
    "audio/mp3": ".mp3",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/mp4": ".m4a",
    "audio/x-m4a": ".m4a",
    "application/pdf": ".pdf",
    "application/vnd.android.package-archive": ".apk",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/x-rar-compressed": ".rar",
    "application/vnd.rar": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/gzip": ".tar.gz",
    "text/plain": ".txt",
    "text/markdown": ".md",
    "application/json": ".json"
  };

  function extensionForMime(type) {
    return EXTENSION_MAP[String(type || "").toLowerCase()] || "";
  }

  async function normalizeDecryptedFileMeta(blob, rawMeta) {
    const meta = { ...(rawMeta || {}) };
    const declared = String(meta.type || "").toLowerCase();
    const currentName = String(meta.name || "").trim();
    const needsSniff = !declared || declared === "application/octet-stream" || declared === "binary/octet-stream";
    if (needsSniff) {
      const head = new Uint8Array(await blob.slice(0, 64).arrayBuffer());
      const inferred = inferMimeFromHead(head, currentName);
      if (inferred) meta.type = inferred;
    }
    if (!meta.type) meta.type = blob.type || "application/octet-stream";

    const isGenericOrBin = !currentName ||
      /^(file|decrypted_file|photo|video|audio|document)(?:\.(bin|enc|dat|octet-stream))?$/i.test(currentName) ||
      /^attachment-[0-9a-f]{4,64}\.bin$/i.test(currentName);

    const ext = extensionForMime(meta.type);

    if (isGenericOrBin) {
      const stem = String(meta.type || "").startsWith("image/") ? "photo"
        : String(meta.type || "").startsWith("video/") ? "video"
        : String(meta.type || "").startsWith("audio/") ? "audio"
        : String(meta.type || "") === "application/pdf" ? "document"
        : String(meta.type || "").includes("android") ? "app"
        : "file";
      meta.name = `${stem}${ext || (meta.type.startsWith("image/") ? ".jpg" : "")}`;
    } else if (/\.(bin|enc|dat)$/i.test(currentName)) {
      if (ext && ext !== ".bin") {
        meta.name = currentName.replace(/\.(bin|enc|dat)$/i, ext);
      }
    } else if (!currentName.includes(".") && ext) {
      meta.name = `${currentName}${ext}`;
    }
    return meta;
  }

  function makeOuterFilename() {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return `attachment-${hex}.bin`;
  }

  async function encryptFile(file) {
    if (!(file instanceof Blob)) throw new Error("Invalid file payload");
    const key = await deriveKey();
    const totalChunks = Math.max(1, Math.ceil(file.size / FILE_CHUNK_SIZE));
    const meta = {
      v: 1,
      name: typeof file.name === "string" && file.name ? file.name : "file",
      type: file.type || "application/octet-stream",
      size: file.size,
      lastModified: Number(file.lastModified || Date.now()),
      chunkSize: FILE_CHUNK_SIZE,
      chunks: totalChunks
    };

    const headerPlain = new TextEncoder().encode(JSON.stringify(meta));
    const headerIv = crypto.getRandomValues(new Uint8Array(12));
    const headerCipher = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: headerIv, additionalData: FILE_MAGIC, tagLength: 128 },
      key,
      headerPlain
    ));

    const parts = [FILE_MAGIC, headerIv, u32le(headerCipher.byteLength), headerCipher];
    for (let index = 0; index < totalChunks; index += 1) {
      const start = index * FILE_CHUNK_SIZE;
      const end = Math.min(file.size, start + FILE_CHUNK_SIZE);
      const plain = new Uint8Array(await file.slice(start, end).arrayBuffer());
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cipher = new Uint8Array(await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: fileChunkAAD(index, totalChunks),
          tagLength: 128
        },
        key,
        plain
      ));
      parts.push(iv, u32le(cipher.byteLength), cipher);
    }

    // v8 metadata privacy: Bale only receives a generic random outer name and
    // application/octet-stream. The real filename, extension, MIME and original
    // mtime exist only inside the authenticated encrypted BEE3FILE header above.
    return new File(parts, makeOuterFilename(), {
      type: "application/octet-stream",
      lastModified: Date.now()
    });
  }

  async function decryptFile(blob) {
    if (!(blob instanceof Blob)) throw new Error("Invalid encrypted file payload");
    const all = new Uint8Array(await blob.arrayBuffer());
    if (!equalPrefix(all, FILE_MAGIC)) throw new Error("Not a Bale E2EE encrypted file");
    const key = await deriveKey();
    let offset = FILE_MAGIC.byteLength;

    if (offset + 16 > all.byteLength) throw new Error("Truncated encrypted file header");
    const headerIv = all.slice(offset, offset + 12);
    offset += 12;
    const headerLen = readU32(all, offset);
    offset += 4;
    if (headerLen < 16 || headerLen > MAX_HEADER_SIZE || offset + headerLen > all.byteLength) {
      throw new Error("Invalid encrypted file header length");
    }
    const headerCipher = all.slice(offset, offset + headerLen);
    offset += headerLen;
    const headerPlain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: headerIv, additionalData: FILE_MAGIC, tagLength: 128 },
      key,
      headerCipher
    );
    const meta = JSON.parse(new TextDecoder().decode(headerPlain));
    if (!meta || meta.v !== 1 || !Number.isInteger(meta.chunks) || meta.chunks < 1 || meta.chunks > 100000) {
      throw new Error("Invalid encrypted file metadata");
    }
    if (!Number.isSafeInteger(meta.size) || meta.size < 0) throw new Error("Invalid original file size");

    const plainParts = [];
    let plainSize = 0;
    for (let index = 0; index < meta.chunks; index += 1) {
      if (offset + 16 > all.byteLength) throw new Error("Truncated encrypted file chunk");
      const iv = all.slice(offset, offset + 12);
      offset += 12;
      const cipherLen = readU32(all, offset);
      offset += 4;
      if (cipherLen < 16 || offset + cipherLen > all.byteLength) throw new Error("Invalid encrypted file chunk length");
      const cipher = all.slice(offset, offset + cipherLen);
      offset += cipherLen;
      const plain = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: fileChunkAAD(index, meta.chunks),
          tagLength: 128
        },
        key,
        cipher
      );
      const part = new Uint8Array(plain);
      plainSize += part.byteLength;
      plainParts.push(part);
    }

    if (offset !== all.byteLength) throw new Error("Unexpected trailing encrypted file data");
    if (plainSize !== meta.size) throw new Error("Original file size check failed");

    const initialBlob = new Blob(plainParts, { type: meta.type || "application/octet-stream" });
    const normalizedMeta = await normalizeDecryptedFileMeta(initialBlob, meta);
    const plainBlob = new Blob(plainParts, { type: normalizedMeta.type || "application/octet-stream" });
    return { blob: plainBlob, meta: normalizedMeta };
  }

  function isComposer(el) {
    if (!(el instanceof Element)) return false;
    return Boolean(el.closest(
      '#editable-message-text, textarea, input, [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]'
    ));
  }

  function hideParent(node) {
    return () => {};
  }

  function appendInlineMarkdown(container, text, depth = 0) {
    if (depth > 8) {
      container.appendChild(document.createTextNode(String(text ?? "")));
      return;
    }
    // This intentionally implements the formatting Hermes commonly emits plus
    // Telegram-style underline/strike/spoiler/code/link syntax. We build DOM
    // nodes instead of using innerHTML so decrypted content cannot inject HTML.
    const tokenRe = /(\[[^\]\n]{1,300}\]\((?:https?:\/\/|mailto:)[^\s)]+\)|`[^`\n]+`|\*\*\*[^*\n]+\*\*\*|___[^_\n]+___|\*\*[^*\n]+\*\*|__[^_\n]+__|~~[^~\n]+~~|~[^~\n]+~|\|\|[^|\n]+\|\||\*[^*\n]+\*|_[^_\n]+_)/g;
    let pos = 0;
    for (const match of String(text ?? "").matchAll(tokenRe)) {
      if (match.index > pos) container.appendChild(document.createTextNode(text.slice(pos, match.index)));
      const token = match[0];
      let el = null;
      let inner = null;
      if (token.startsWith("***") && token.endsWith("***")) {
        el = document.createElement("strong");
        const em = document.createElement("em");
        appendInlineMarkdown(em, token.slice(3, -3), depth + 1);
        el.appendChild(em);
      } else if (token.startsWith("___") && token.endsWith("___")) {
        el = document.createElement("u");
        const em = document.createElement("em");
        appendInlineMarkdown(em, token.slice(3, -3), depth + 1);
        el.appendChild(em);
      } else if (token.startsWith("**")) {
        el = document.createElement("strong");
        inner = token.slice(2, -2);
      } else if (token.startsWith("__")) {
        el = document.createElement("u");
        inner = token.slice(2, -2);
      } else if (token.startsWith("~~")) {
        el = document.createElement("s");
        inner = token.slice(2, -2);
      } else if (token.startsWith("~")) {
        el = document.createElement("s");
        inner = token.slice(1, -1);
      } else if (token.startsWith("||")) {
        el = document.createElement("span");
        inner = token.slice(2, -2);
        el.title = "برای نمایش بزنید";
        Object.assign(el.style, { background: "currentColor", borderRadius: "4px", cursor: "pointer" });
        el.style.setProperty("color", "transparent", "important");
        el.addEventListener("click", () => {
          el.style.removeProperty("background");
          el.style.removeProperty("color");
        });
      } else if (token.startsWith("`")) {
        el = document.createElement("code");
        el.textContent = token.slice(1, -1);
        Object.assign(el.style, { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", whiteSpace: "pre-wrap" });
      } else if (token.startsWith("[")) {
        const lm = token.match(/^\[([^\]]+)\]\((.+)\)$/s);
        if (lm) {
          try {
            const url = new URL(lm[2], location.href);
            if (["http:", "https:", "mailto:"].includes(url.protocol)) {
              el = document.createElement("a");
              el.href = url.href;
              el.target = "_blank";
              el.rel = "noopener noreferrer";
              appendInlineMarkdown(el, lm[1], depth + 1);
            }
          } catch (_) {}
        }
      } else if (token.startsWith("*")) {
        el = document.createElement("em");
        inner = token.slice(1, -1);
      } else if (token.startsWith("_")) {
        el = document.createElement("em");
        inner = token.slice(1, -1);
      }
      if (el && inner !== null) appendInlineMarkdown(el, inner, depth + 1);
      container.appendChild(el || document.createTextNode(token));
      pos = match.index + token.length;
    }
    if (pos < text.length) container.appendChild(document.createTextNode(text.slice(pos)));
  }

  function attachSecureIndicatorToTimestamp(container) {
    if (!container || !container.isConnected) return;
    const msgItem = container.closest?.('.message-item') || container.parentElement?.closest?.('.message-item');
    if (!msgItem) return;
    const info = msgItem.querySelector?.('[data-sentry-component="InfoFC"], .bisANn, [class*="bisANn"]');
    if (!info || info.querySelector?.('[data-bale-e2ee-time-shield="true"]')) return;

    const shield = document.createElement("span");
    shield.setAttribute("data-bale-e2ee-time-shield", "true");
    shield.title = "رمزنگاری سرتاسری";
    shield.setAttribute("aria-label", "End-to-end encrypted");
    Object.assign(shield.style, {
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      width: "12px",
      height: "12px",
      marginRight: "3px",
      marginLeft: "2px",
      opacity: "0.7",
      color: "currentColor",
      verticalAlign: "middle",
      flexShrink: "0"
    });
    shield.innerHTML = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.4 19 6v5.4c0 4.2-2.7 7.4-7 9.2-4.3-1.8-7-5-7-9.2V6l7-2.6Z"/><path d="M9.3 11V9.3a2.7 2.7 0 0 1 5.4 0V11m-6.2 0h7v5h-7z"/></svg>';

    const p = info.querySelector?.('p.x3ai0M, p[class*="x3ai0M"], p');
    if (p) {
      p.insertAdjacentElement("beforebegin", shield);
    } else {
      info.appendChild(shield);
    }
  }

  function createSecureIndicator() {
    return document.createComment("e2ee");
  }

  function isRtlString(str) {
    if (!str) return false;
    const clean = str.replace(/[\u200e\u200f\u202a-\u202e\s\d.,!?;:()\[\]{}"'\\\/@#$%^&*+=<>~`|_-]/g, "");
    if (!clean) return false;
    const rtlCount = (clean.match(/[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/g) || []).length;
    return rtlCount / clean.length > 0.3;
  }

  function renderMarkdown(plain) {
    const isRtl = isRtlString(plain);
    const root = document.createElement("span");
    root.setAttribute("data-bale-e2ee-rendered", "true");
    root.setAttribute("dir", isRtl ? "rtl" : "ltr");
    root.style.direction = isRtl ? "rtl" : "ltr";
    root.style.textAlign = isRtl ? "right" : "left";
    root.style.display = "inline-block";
    root.style.width = "100%";
    root.style.whiteSpace = "pre-wrap";
    root.style.overflowWrap = "anywhere";

    const lines = String(plain ?? "").split("\n");
    let inFence = false;
    let fenceLang = "";
    let codeLines = [];
    const flushFence = () => {
      const pre = document.createElement("pre");
      pre.setAttribute("dir", "ltr");
      Object.assign(pre.style, { whiteSpace: "pre-wrap", overflowX: "auto", margin: "6px 0" });
      const code = document.createElement("code");
      if (fenceLang) code.setAttribute("data-language", fenceLang);
      code.textContent = codeLines.join("\n");
      pre.appendChild(code);
      root.appendChild(pre);
      codeLines = [];
    };

    lines.forEach((line, lineIndex) => {
      const fence = line.match(/^```\s*([\w.+#-]*)\s*$/);
      if (fence) {
        if (!inFence) { inFence = true; fenceLang = fence[1] || ""; }
        else { inFence = false; flushFence(); fenceLang = ""; }
        return;
      }
      if (inFence) { codeLines.push(line); return; }

      const block = document.createElement("span");
      const lineRtl = isRtlString(line);
      block.setAttribute("dir", lineRtl ? "rtl" : (isRtl ? "rtl" : "ltr"));
      block.style.direction = lineRtl ? "rtl" : (isRtl ? "rtl" : "ltr");
      block.style.textAlign = lineRtl ? "right" : (isRtl ? "right" : "left");
      block.style.display = "block";
      const heading = line.match(/^#{1,6}\s+(.+)$/);
      const quote = line.match(/^>\s?(.*)$/);
      const bullet = line.match(/^\s*[-+*]\s+(.+)$/);
      const ordered = line.match(/^\s*(\d{1,4})[.)]\s+(.+)$/);
      if (heading) {
        const strong = document.createElement("strong");
        appendInlineMarkdown(strong, heading[1]);
        block.appendChild(strong);
      } else if (quote) {
        block.style.display = "inline-block";
        block.style.paddingInlineStart = "8px";
        block.style.borderInlineStart = "2px solid currentColor";
        block.style.opacity = "0.92";
        appendInlineMarkdown(block, quote[1]);
      } else if (bullet) {
        block.appendChild(document.createTextNode("• "));
        appendInlineMarkdown(block, bullet[1]);
      } else if (ordered) {
        block.appendChild(document.createTextNode(`${ordered[1]}. `));
        appendInlineMarkdown(block, ordered[2]);
      } else {
        appendInlineMarkdown(block, line);
      }
      root.appendChild(block);
      if (lineIndex < lines.length - 1) root.appendChild(document.createElement("br"));
    });
    if (inFence) flushFence();
    return root;
  }

  function renderDecryptedNode(node, cipher, plain) {
    if (!(node instanceof Text) || !node.isConnected) return;
    const value = node.nodeValue || "";
    if (value.trim() === cipher) {
      const rendered = renderMarkdown(plain);
      node.replaceWith(rendered);
      attachSecureIndicatorToTimestamp(rendered);
      return;
    }
    node.nodeValue = value.replace(cipher, plain);
    attachSecureIndicatorToTimestamp(node.parentElement);
  }

  async function processTextNode(node) {
    if (!(node instanceof Text) || !node.nodeValue) return;
    if (!node.parentElement || isComposer(node.parentElement)) return;
    WIRE_RE.lastIndex = 0;
    const original = node.nodeValue;
    const matches = [...original.matchAll(WIRE_RE)].map((m) => m[0]);
    if (!matches.length) return;

    // Fast path for messages we encrypted ourselves: no ciphertext flash and
    // Markdown is rendered client-side because Bale never sees the plaintext.
    if (matches.length === 1 && original.trim() === matches[0]) {
      const cipher = matches[0];
      let plain = outgoingPlain.get(cipher) ?? decryptedCache.get(cipher);
      if (typeof plain === "string") {
        renderDecryptedNode(node, cipher, plain);
        return;
      }
      const restore = hideParent(node);
      try {
        plain = await getDecryptedPlain(cipher);
        if (typeof plain === "string" && node.isConnected) {
          renderDecryptedNode(node, cipher, plain);
          unresolvedWireHosts.delete(nearestWireScanHost(node));
        } else {
          unresolvedWireHosts.add(nearestWireScanHost(node));
        }
      } finally { restore(); }
      return;
    }

    // If Bale mixed the wire with other DOM/text (reply headers, bidi spans,
    // timestamps, etc.), let the range-based scanner replace only the exact
    // authenticated wire. That preserves surrounding UI, Markdown rendering,
    // and the subtle E2EE indicator.
    scheduleFragmentedWireScan(node);
  }

  const fragmentedScanQueue = new Set();
  let fragmentedScanScheduled = false;

  function nearestWireScanHost(source) {
    let el = source instanceof Element ? source : source?.parentElement;
    if (!(el instanceof Element)) return document.body || document.documentElement;
    // Bale often splits one logical message across several spans (especially
    // reply previews / RTL-LTR runs). Climb a few levels so the full wire is
    // reconstructed without scanning the whole chat on every mutation.
    for (let i = 0; i < 4 && el.parentElement; i += 1) {
      const parent = el.parentElement;
      const text = String(parent.textContent || "");
      if (text.length > 16000) break;
      el = parent;
      if (/\b(message|bubble|reply|caption|text|content)\b/i.test(String(el.className || ""))) break;
    }
    return el;
  }

  function buildNormalizedTextMap(root) {
    const textParts = [];
    const map = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (!parent || isComposer(parent)) continue;
      if (parent.closest('[data-bale-e2ee-rendered="true"], [data-bale-e2ee-indicator="true"]')) continue;
      const value = node.nodeValue || "";
      for (let offset = 0; offset < value.length; offset += 1) {
        const ch = value[offset];
        // Bale may inject bidi/zero-width formatting marks into visual RTL/LTR
        // runs. They are not part of the authenticated E2 wire and previously
        // made a perfectly valid ciphertext impossible to match.
        if (WIRE_IGNORED_CHAR_RE.test(ch)) continue;
        textParts.push(ch);
        map.push({ node, offset });
      }
    }
    return { text: textParts.join(""), map };
  }

  async function processFragmentedWireContainer(root) {
    if (!(root instanceof Element) || !root.isConnected) return;
    const quickText = String(root.textContent || "");
    if (!WIRE_HINT_RE.test(quickText)) return;

    const { text, map } = buildNormalizedTextMap(root);
    if (!text || !map.length) return;
    WIRE_RE.lastIndex = 0;
    const matches = [...text.matchAll(WIRE_RE)];
    if (!matches.length) return;

    // Work right-to-left so replacing a later range cannot invalidate offsets
    // of an earlier wire living in the same text node.
    for (const match of matches.reverse()) {
      const cipher = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + cipher.length - 1;
      const start = map[startIndex];
      const end = map[endIndex];
      if (!start?.node?.isConnected || !end?.node?.isConnected) continue;

      let plain = outgoingPlain.get(cipher) ?? decryptedCache.get(cipher);
      if (typeof plain !== "string") plain = await getDecryptedPlain(cipher);
      if (typeof plain !== "string") {
        unresolvedWireHosts.add(root);
        continue;
      }
      unresolvedWireHosts.delete(root);
      if (!start.node.isConnected || !end.node.isConnected) continue;
      if (start.offset > (start.node.nodeValue || "").length || end.offset >= (end.node.nodeValue || "").length) continue;

      try {
        const range = document.createRange();
        range.setStart(start.node, start.offset);
        range.setEnd(end.node, end.offset + 1);
        range.deleteContents();
        range.insertNode(renderMarkdown(plain));
        range.detach?.();
      } catch (_) {
        // React may have rerendered between decrypt() and Range replacement.
        // A subsequent mutation/scan will retry against fresh nodes.
      }
    }
  }

  function scheduleFragmentedWireScan(source) {
    const host = nearestWireScanHost(source);
    if (!(host instanceof Element)) return;
    fragmentedScanQueue.add(host);
    if (fragmentedScanScheduled) return;
    fragmentedScanScheduled = true;
    queueMicrotask(() => {
      fragmentedScanScheduled = false;
      const hosts = [...fragmentedScanQueue];
      fragmentedScanQueue.clear();
      for (const item of hosts) void processFragmentedWireContainer(item);
    });
  }

  function processRoot(root) {
    if (!root) return;
    if (root instanceof Text) { void processTextNode(root); return; }
    if (!(root instanceof Node)) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) {
      WIRE_RE.lastIndex = 0;
      if (n.nodeValue && WIRE_RE.test(n.nodeValue)) void processTextNode(n);
    }
  }

  function periodicEncryptedWireRetry() {
    // Retry only hosts that previously contained a wire we could not decrypt.
    // This fixes transient storage/key/decompression failures without repeatedly
    // walking the entire conversation.
    for (const host of [...unresolvedWireHosts]) {
      if (!(host instanceof Element) || !host.isConnected) {
        unresolvedWireHosts.delete(host);
        continue;
      }
      const text = String(host.textContent || "");
      if (!WIRE_HINT_RE.test(text)) {
        unresolvedWireHosts.delete(host);
        continue;
      }
      processRoot(host);
      scheduleFragmentedWireScan(host);
    }

    // Bale sometimes recycles an existing virtualized row without a mutation
    // shape that identifies the new text reliably. XPath gives us a cheap
    // periodic safety net for visible/raw E2 markers without a full DOM scan.
    try {
      const xpath = document.evaluate(
        "//text()[contains(., 'E2:') or contains(., 'E2C:') or contains(., 'ENC:') or contains(., 'ENC2:')]",
        document,
        null,
        XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
        null
      );
      const limit = Math.min(xpath.snapshotLength, 160);
      for (let i = 0; i < limit; i += 1) {
        const node = xpath.snapshotItem(i);
        if (!(node instanceof Text) || !node.parentElement || isComposer(node.parentElement)) continue;
        void processTextNode(node);
        scheduleFragmentedWireScan(node);
      }
    } catch (_) {}
  }

  function startDecryptObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData") {
          processRoot(mutation.target);
          scheduleFragmentedWireScan(mutation.target);
        }
        for (const added of mutation.addedNodes) {
          processRoot(added);
          scheduleFragmentedWireScan(added);
        }
      }
    });
    observer.observe(document.documentElement, { subtree: true, childList: true, characterData: true });
    if (document.body) {
      processRoot(document.body);
      scheduleFragmentedWireScan(document.body);
    }
    // Bale virtualizes message rows; scrolling can recycle an existing row with
    // a new split text structure without an obvious top-level insertion.
    document.addEventListener("scroll", (event) => scheduleFragmentedWireScan(event.target), true);
    setInterval(periodicEncryptedWireRetry, 1200);
  }

  async function refreshStatus() {
    keyEpoch += 1;
    activeKey = null;
    decryptedCache.clear();
    decryptInflight.clear();
    decryptRetry.clear();
    try {
      const pass = await readPassphrase();
      configured = Boolean(pass);
      if (configured) await deriveKey();
    } catch (_) {
      configured = false;
    }
    post("STATUS", { enabled: configured });
  }

  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.channel !== CHANNEL) return;

    if (msg.type === "HOOK_READY") {
      if (!configured && msg.localPass) {
        try {
          if (ext?.storage?.local) await storageSet({ [STORAGE_KEY]: msg.localPass });
        } catch (_) {}
        await refreshStatus();
      } else {
        post("STATUS", { enabled: configured });
      }
      return;
    }

    if (msg.type === "ENCRYPT_REQUEST") {
      try {
        if (!configured) throw new Error("Set a passphrase in the extension first");
        const items = await encryptTextChunks(String(msg.plain ?? ""));
        for (const item of items) {
          outgoingPlain.set(item.cipher, item.plain);
          setTimeout(() => outgoingPlain.delete(item.cipher), 10 * 60 * 1000);
        }
        post("ENCRYPT_RESULT", { id: msg.id, cipher: items[0]?.cipher || "", items });
      } catch (err) {
        post("ENCRYPT_RESULT", { id: msg.id, error: String(err?.message || err) });
      }
      return;
    }

    if (msg.type === "FILE_ENCRYPT_REQUEST") {
      try {
        if (!configured) throw new Error("Set a passphrase in the extension first");
        const encrypted = await encryptFile(msg.file);
        post("FILE_ENCRYPT_RESULT", { id: msg.id, file: encrypted });
      } catch (err) {
        post("FILE_ENCRYPT_RESULT", { id: msg.id, error: String(err?.message || err) });
      }
      return;
    }

    if (msg.type === "FILE_DECRYPT_REQUEST") {
      try {
        if (!configured) throw new Error("Set a passphrase in the extension first");
        post("FILE_DECRYPT_PROGRESS", { id: msg.id, stage: "decrypting" });
        const { blob, meta } = await decryptFile(msg.blob);
        post("FILE_DECRYPT_PROGRESS", { id: msg.id, stage: "rendering" });
        post("FILE_DECRYPT_RESULT", { id: msg.id, blob, meta });
      } catch (err) {
        post("FILE_DECRYPT_RESULT", { id: msg.id, error: String(err?.message || err) });
      }
      return;
    }

    if (msg.type === "DOWNLOAD_URL_REQUEST") {
      try {
        if (!configured) throw new Error("Set a passphrase in the extension first");
        const url = new URL(String(msg.url || ""));
        if (
          url.protocol !== "https:" ||
          !/(^|\.)(ble\.ir|bale\.ai)$/i.test(url.hostname) ||
          !/\/proxy_download\//i.test(url.pathname)
        ) {
          throw new Error("Rejected non-Nasim download URL");
        }

        post("DOWNLOAD_URL_PROGRESS", { id: msg.id, stage: "connecting" });

        // Download with retry (up to 3 attempts with progressive delay)
        let response = null;
        let lastErr = null;
        for (let attempt = 1; attempt <= 3; attempt++) {
          try {
            response = await fetch(url.href, {
              method: "GET",
              mode: "cors",
              credentials: "omit",
              cache: "no-store",
              redirect: "follow",
              referrerPolicy: "no-referrer"
            });
            if (response.ok) break;
            lastErr = new Error(`Nasim download HTTP ${response.status}`);
          } catch (e) {
            lastErr = e;
          }
          if (attempt < 3) {
            post("DOWNLOAD_URL_PROGRESS", { id: msg.id, stage: "retrying", attempt });
            await new Promise(r => setTimeout(r, 1200 * attempt));
          }
        }
        if (!response || !response.ok) throw (lastErr || new Error("Failed to download from Nasim"));

        post("DOWNLOAD_URL_PROGRESS", { id: msg.id, stage: "downloading" });

        const contentLength = Number(response.headers.get("content-length")) || 0;
        let encryptedBlob = null;

        if (response.body && typeof response.body.getReader === "function") {
          const reader = response.body.getReader();
          const chunks = [];
          let loaded = 0;
          let lastReport = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            loaded += value.byteLength;
            const now = Date.now();
            if (now - lastReport > 200) {
              lastReport = now;
              const percent = contentLength > 0 ? Math.round((loaded / contentLength) * 100) : 0;
              post("DOWNLOAD_URL_PROGRESS", { id: msg.id, stage: "downloading", loaded, total: contentLength, percent });
            }
          }
          encryptedBlob = new Blob(chunks);
        } else {
          encryptedBlob = await response.blob();
        }

        if (encryptedBlob.size < FILE_MAGIC.byteLength) throw new Error("Nasim payload too small");
        const head = new Uint8Array(await encryptedBlob.slice(0, FILE_MAGIC.byteLength).arrayBuffer());
        if (!equalPrefix(head, FILE_MAGIC)) throw new Error("Nasim payload is not BEE3FILE");

        post("DOWNLOAD_URL_PROGRESS", { id: msg.id, stage: "decrypting" });
        const { blob, meta } = await decryptFile(encryptedBlob);

        post("DOWNLOAD_URL_PROGRESS", { id: msg.id, stage: "rendering" });
        post("DOWNLOAD_URL_RESULT", { id: msg.id, blob, meta });
      } catch (err) {
        post("DOWNLOAD_URL_RESULT", { id: msg.id, error: String(err?.message || err) });
      }
      return;
    }

    if (msg.type === "OUTGOING_MAPPING" && typeof msg.cipher === "string") {
      outgoingPlain.set(msg.cipher, String(msg.plain ?? ""));
      setTimeout(() => outgoingPlain.delete(msg.cipher), 10 * 60 * 1000);
    }
  });

  try {
    ext.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes[STORAGE_KEY]) void refreshStatus();
    });
  } catch (err) {
    console.warn("[Bale E2EE] storage listener unavailable", err);
  }

  startDecryptObserver();
  void refreshStatus().then(() => {
    console.log("[Bale E2EE] isolated v12 retry-safe compact-text + Markdown + BEE3FILE + direct Nasim URL decrypt bridge ready.");
  });
})();
