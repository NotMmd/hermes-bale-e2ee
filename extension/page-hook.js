(() => {
  "use strict";

  const CHANNEL = "__BALE_E2EE_V12__";
  const PREFIX = "ENC:";
  const TEXT_V2_PREFIX = "ENC2:";
  const TEXT2_PREFIX = "E2:";
  const TEXT2_CHUNK_PREFIX = "E2C:";
  const FILE_MAGIC_TEXT = "BEE3FILE";
  const FILE_MAGIC = new TextEncoder().encode(FILE_MAGIC_TEXT);
  const INPUT_SELECTORS = [
    "#editable-message-text",
    '[contenteditable="true"]',
    'div[contenteditable="true"]',
    "textarea",
    '[role="textbox"]'
  ];
  const CAPTION_EDITOR_SELECTORS = [
    'textarea',
    'input[type="text"]',
    'input:not([type])',
    '[contenteditable="true"]',
    '[contenteditable="plaintext-only"]',
    '[role="textbox"]'
  ];
  const CAPTION_HINT_RE = /(caption|description|comment|توضیح|شرح|زیرنویس|کپشن|پیام)/i;
  const CAPTION_NEGATIVE_HINT_RE = /(search|جستجو|rename|filename|file-name|نام فایل)/i;
  // UI often truncates `attachment-<hex>.bin` to `attachment-5347f7…`.
  // Note: Bale Web prepends "BIN" or "DOC" badge without spaces (e.g. "BINattachment-xxx.bin"),
  // so do NOT require a leading word boundary (\b) before "attachment-".
  const GENERIC_ATTACHMENT_RE = /(?:attachment-[0-9a-f]{6,64}(?:\.bin)?|[^\s/?#\\<>:"|*]{1,160}\.enc\b)/i;

  const SEND_SELECTORS = [
    'div[aria-label="send-button"]',
    'button[aria-label="send-button"]',
    'button[type="submit"]',
    'button[aria-label*="send" i]',
    '[role="button"][aria-label*="send" i]',
    'button[aria-label*="ارسال"]',
    '[role="button"][aria-label*="ارسال"]',
    '[data-testid*="send" i]',
    '[class*="modal-send" i]',
    '[class*="send-button" i]',
    '[class*="confirm" i][role="button"]',
    'button[class*="confirm" i]'
  ];

  // Broad selectors are intentionally kept separate from normal text-send
  // selectors. A generic `button:has(svg)` matches attachment/emoji/crop tools
  // too, so it is only considered while a media preview/dialog is active.
  const MEDIA_CONFIRM_SELECTORS = [
    '.modal button',
    '.dialog button',
    '[role="dialog"] button',
    '[class*="modal" i] button',
    '[class*="dialog" i] button',
    '[class*="confirm" i]',
    '[class*="send" i]',
    'button:has(svg)'
  ];
  const UPLOAD_URL_RE = /(nasim|upload|fileurl|file-url|file_url|\/files?\/|storage)/i;
  const MEDIA_CONTEXT_MS = 10 * 60 * 1000;

  let enabled = false;
  let sending = false;
  let bypassNextSendClick = false;
  let mediaReplayInProgress = false;
  const pending = new Map();
  const processedCommandEvents = new WeakSet();
  const processedClickEvents = new WeakSet();
  const processedAttachmentEvents = new WeakSet();
  const filenameDisplayMap = new Map();
  const decryptedBlobCache = new Map();
  const autoPreviewAnchors = new WeakSet();
  const autoPreviewByHref = new Map();
  const inlinePreviewUrls = new Map();
  let autoPreviewScanTimer = null;
  let pendingAttachmentClick = null;

  // v8 secure-document mode: plaintext attachments are intercepted before Bale
  // consumes the selection. The isolated-world crypto layer returns a BEE3FILE
  // File with a generic name + application/octet-stream. Bale therefore builds
  // a normal document/file message instead of a native Photo/Video entity.
  // The older staged/armed machinery remains as a fail-closed network guard for
  // unexpected late Blobs created by Bale.
  const stagedMedia = new Map(); // File/Blob -> { encrypted, promise, error, armed }
  let activeMedia = [];
  let mediaCandidates = [];
  let activeMediaGeneration = 0;
  let lastMediaStageAt = 0;
  let uploadGuardArmedUntil = 0;
  let mediaSendPhaseUntil = 0;
  let secureDocumentModeUntil = 0;

  const armedMedia = new WeakMap(); // original Blob/File -> encrypted File
  const derivedMedia = new WeakSet();
  const encryptedMediaBlobs = new WeakSet();
  const genericBlobNames = new WeakMap();
  const xhrRequestMeta = new WeakMap();
  const originalFetch = window.fetch.bind(window);
  const originalXhrOpen = XMLHttpRequest.prototype.open;
  const originalXhrSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  const originalXhrSend = XMLHttpRequest.prototype.send;
  const originalCreateObjectURL = URL.createObjectURL.bind(URL);
  const originalAnchorClick = globalThis.HTMLAnchorElement?.prototype?.click;
  const originalFormDataAppend = FormData.prototype.append;
  const originalFormDataSet = FormData.prototype.set;
  const originalCanvasToBlob = globalThis.HTMLCanvasElement?.prototype?.toBlob;
  const originalOffscreenConvertToBlob = globalThis.OffscreenCanvas?.prototype?.convertToBlob;
  const originalFileReaderReadAsArrayBuffer = FileReader.prototype.readAsArrayBuffer;
  const originalFileReaderReadAsBinaryString = FileReader.prototype.readAsBinaryString;
  const originalFileReaderReadAsText = FileReader.prototype.readAsText;
  const originalFileReaderReadAsDataURL = FileReader.prototype.readAsDataURL;
  const originalWorkerPostMessage = globalThis.Worker?.prototype?.postMessage;
  const originalWebSocketSend = globalThis.WebSocket?.prototype?.send;
  const originalWindowOpen = globalThis.open?.bind(globalThis);
  const originalElementSetAttribute = Element.prototype.setAttribute;
  const iframeSrcDescriptor = globalThis.HTMLIFrameElement
    ? Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "src")
    : null;
  const watchedWebSockets = new WeakSet();
  const resolvedNasimTasks = new Map();

  function post(type, payload = {}) {
    window.postMessage({ channel: CHANNEL, type, ...payload }, location.origin);
  }

  function makeId() {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  }

  function waitForResult(type, requestType, payload, timeoutMs = 120000, onProgress = null) {
    const id = makeId();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`${requestType.toLowerCase()} bridge timeout`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timer, type, onProgress });
      post(requestType, { id, ...payload });
    });
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.channel !== CHANNEL) return;

    if (msg.type === "STATUS") {
      enabled = Boolean(msg.enabled);
      if (enabled) scheduleAutoPreviewScan(0);
      return;
    }

    if (msg.type.endsWith("_PROGRESS")) {
      const waiter = pending.get(msg.id);
      if (waiter && typeof waiter.onProgress === "function") {
        try { waiter.onProgress(msg); } catch (_) {}
      }
      return;
    }

    if (msg.type.endsWith("_RESULT")) {
      const waiter = pending.get(msg.id);
      if (!waiter || waiter.type !== msg.type) return;
      pending.delete(msg.id);
      clearTimeout(waiter.timer);
      if (msg.error) waiter.reject(new Error(msg.error));
      else waiter.resolve(msg);
    }
  });

  async function requestEncrypt(plain) {
    const result = await waitForResult("ENCRYPT_RESULT", "ENCRYPT_REQUEST", { plain }, 30000);
    const items = Array.isArray(result.items) && result.items.length
      ? result.items
      : (result.cipher ? [{ cipher: result.cipher, plain: String(plain ?? "") }] : []);
    if (!items.length) throw new Error("empty encrypted payload");
    return items;
  }

  function isEncryptedWire(value) {
    const text = String(value || "").trim();
    return text.startsWith(PREFIX) || text.startsWith(TEXT_V2_PREFIX) || text.startsWith(TEXT2_PREFIX) || text.startsWith(TEXT2_CHUNK_PREFIX);
  }

  async function requestEncryptFile(file) {
    const result = await waitForResult("FILE_ENCRYPT_RESULT", "FILE_ENCRYPT_REQUEST", { file }, 10 * 60 * 1000);
    return result.file;
  }

  async function requestDecryptBlob(blob, onProgress = null) {
    const result = await waitForResult("FILE_DECRYPT_RESULT", "FILE_DECRYPT_REQUEST", { blob }, 10 * 60 * 1000, onProgress);
    return { blob: result.blob, meta: result.meta || {} };
  }

  async function requestResolvedNasimDownload(url, onProgress = null) {
    const result = await waitForResult(
      "DOWNLOAD_URL_RESULT",
      "DOWNLOAD_URL_REQUEST",
      { url: String(url || "") },
      10 * 60 * 1000,
      onProgress
    );
    return { blob: result.blob, meta: result.meta || {} };
  }

  function activePendingAttachment() {
    const pendingInfo = pendingAttachmentClick;
    if (!pendingInfo || Date.now() > pendingInfo.expires || !pendingInfo.surface?.isConnected) return null;
    return pendingInfo;
  }

  function isNasimProxyDownloadUrl(value) {
    try {
      const url = new URL(String(value || ""), location.href);
      return url.protocol === "https:" && /(^|\.)(ble\.ir|bale\.ai)$/i.test(url.hostname) && /\/proxy_download\//i.test(url.pathname);
    } catch (_) {
      return false;
    }
  }

  function isEncryptedAttachmentUrlOrName(value) {
    if (!value) return false;
    const str = String(value);
    if (GENERIC_ATTACHMENT_RE.test(str)) return true;
    if (/attachment-[0-9a-f]{4,64}/i.test(str)) return true;
    if (isNasimProxyDownloadUrl(str)) {
      try {
        const u = new URL(str, location.href);
        const fn = u.searchParams.get("filename") || "";
        if (GENERIC_ATTACHMENT_RE.test(fn) || fn.endsWith(".bin") || /attachment-/i.test(fn)) return true;
        if (/\/proxy_download\//i.test(u.pathname)) return true;
      } catch (_) {}
    }
    return false;
  }

  function extractNasimProxyUrlsFromBytes(bytes) {
    try {
      if (!(bytes instanceof Uint8Array) || bytes.byteLength < 16) return [];
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      const matches = text.match(/https:\/\/[^\x00-\x20"'<>]+\/proxy_download\/[^\x00-\x20"'<>]+/gi) || [];
      const unique = [];
      const seen = new Set();
      for (const raw of matches) {
        let url = raw;
        // Protobuf strings end at a length boundary. The regex already stops on
        // control bytes, but normalize through URL to reject accidental garbage.
        try { url = new URL(raw).href; } catch (_) { continue; }
        if (!isNasimProxyDownloadUrl(url) || seen.has(url)) continue;
        seen.add(url);
        unique.push(url);
      }
      return unique;
    } catch (_) {
      return [];
    }
  }

  async function websocketPayloadBytes(data) {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
    if (typeof data === "string") return new TextEncoder().encode(data);
    return null;
  }

  function isReplyOrQuoteElement(node) {
    if (!(node instanceof Element)) return false;
    return Boolean(
      node.closest?.(
        '.BAsWs0, ' +
        '[data-sentry-component="Preview"], ' +
        '[data-sentry-component*="Preview" i], ' +
        '[data-sentry-source-file*="Preview" i], ' +
        '[data-testid*="reply" i], ' +
        '[data-testid*="quote" i], ' +
        '[class*="reply" i], ' +
        '[class*="quote" i], ' +
        '[class*="quoted" i]'
      )
    );
  }

  async function handleResolvedNasimUrl(url, source = "unknown") {
    if (!enabled || !isNasimProxyDownloadUrl(url)) return false;
    const pendingInfo = activePendingAttachment();
    let urlOuterName = "";
    try {
      const u = new URL(url);
      const fn = u.searchParams.get("filename") || "";
      const m = fn.match(GENERIC_ATTACHMENT_RE);
      if (m) urlOuterName = m[0];
    } catch (_) {}

    const outerName = pendingInfo?.outerName || urlOuterName || "";
    if (!pendingInfo && !outerName) return false;

    const normalized = new URL(url).href;
    if (resolvedNasimTasks.has(normalized)) return true;

    let targetSurface = pendingInfo?.surface;
    if (!targetSurface?.isConnected || isReplyOrQuoteElement(targetSurface)) {
      targetSurface = findCardByOuterName(outerName);
    }
    if (!targetSurface && outerName) {
      targetSurface = findCardByOuterName(outerName);
    }

    const snapshot = {
      surface: targetSurface,
      outerName,
      trusted: Boolean(pendingInfo?.trusted),
      expires: pendingInfo?.expires || (Date.now() + 60000)
    };
    try { snapshot.surface?.setAttribute?.("data-bale-e2ee-auto-preview", "rpc-downloading"); } catch (_) {}

    const task = (async () => {
      console.log(`[Bale E2EE] captured GetNasimFileUrls download URL via ${source}`, normalized);
      const effectiveOuter = snapshot.outerName || "";
      updateCardStage(effectiveOuter || snapshot.surface, "در حال اتصال به سرور نسیم...");

      const { blob: plainBlob, meta } = await requestResolvedNasimDownload(normalized, (progress) => {
        const target = effectiveOuter || snapshot.surface;
        if (progress.stage === "connecting") {
          updateCardStage(target, "در حال اتصال به سرور نسیم...");
        } else if (progress.stage === "retrying") {
          updateCardStage(target, `تلاش مجدد برای ارتباط با سرور (${progress.attempt || 1})...`);
        } else if (progress.stage === "downloading") {
          if (progress.percent > 0) {
            updateCardStage(target, `در حال دانلود فایل (${progress.percent}٪)...`);
          } else if (progress.loaded > 0) {
            updateCardStage(target, `در حال دانلود فایل (${formatFileSize(progress.loaded)})...`);
          } else {
            updateCardStage(target, "در حال دانلود فایل رمزشده...");
          }
        } else if (progress.stage === "decrypting") {
          updateCardStage(target, "در حال رمزگشایی سرتاسری...");
        } else if (progress.stage === "rendering") {
          updateCardStage(target, "در حال آماده‌سازی و نمایش...");
        }
      });

      const resolvedOuter = effectiveOuter || (meta?.name ? String(meta.name) : "");
      let head = null;
      try { head = new Uint8Array(await plainBlob.slice(0, 64).arrayBuffer()); } catch (_) {}
      const properName = resolveProperFilename(plainBlob, meta, resolvedOuter, head);

      if (resolvedOuter && properName) {
        decryptedBlobCache.set(resolvedOuter, { blob: plainBlob, meta, outerName: properName });
        rememberDecryptedFilename(resolvedOuter, properName);
      }
      if (properName) {
        decryptedBlobCache.set(properName, { blob: plainBlob, meta, outerName: properName });
      }
      decryptedBlobCache.set(normalized, { blob: plainBlob, meta, outerName: properName });

      let finalSurface = snapshot.surface;
      if (!finalSurface?.isConnected || isReplyOrQuoteElement(finalSurface)) {
        finalSurface = findCardByOuterName(resolvedOuter);
      }

      let rendered = false;
      if (finalSurface?.isConnected) {
        rendered = renderInlineDecryptedMediaAtSurface(finalSurface, plainBlob, meta, resolvedOuter);
        finalSurface.setAttribute(
          "data-bale-e2ee-auto-preview",
          rendered ? "ready" : "document-ready"
        );
      }

      if (pendingAttachmentClick?.surface === snapshot.surface || pendingAttachmentClick?.surface === finalSurface) {
        pendingAttachmentClick = null;
      }

      const type = String(meta?.type || plainBlob.type || "").toLowerCase();
      const isMedia = type.startsWith("image/") || type.startsWith("video/") || type.startsWith("audio/");

      // If it is a non-media document (e.g. APK, PDF, ZIP), the user tapped to download the file.
      // ALWAYS trigger plaintext download with the original decrypted filename!
      if (!isMedia) {
        saveDecryptedBlob(plainBlob, properName);
        toast(`فایل ${properName} رمزگشایی و دریافت شد`);
      } else {
        toast("مدیا رمزگشایی شد");
      }
    })().catch((err) => {
      resolvedNasimTasks.delete(normalized); // Delete lock IMMEDIATELY so user can retry at once!
      try { snapshot.surface?.setAttribute?.("data-bale-e2ee-auto-preview", "failed"); } catch (_) {}
      const target = snapshot.outerName || snapshot.surface;
      updateCardStage(target, "خطا در دریافت فایل (برای تلاش مجدد کلیک کنید)", true);
      console.warn("[Bale E2EE] direct GetNasimFileUrls decrypt failed", err);
      toast("خطا در دریافت یا رمزگشایی فایل", true);
    }).finally(() => {
      setTimeout(() => resolvedNasimTasks.delete(normalized), 5000);
    });

    resolvedNasimTasks.set(normalized, task);
    return true;
  }

  function inspectBaleWebSocketMessage(event) {
    if (!enabled) return;
    void (async () => {
      try {
        const bytes = await websocketPayloadBytes(event.data);
        if (!bytes) return;
        for (const url of extractNasimProxyUrlsFromBytes(bytes)) {
          if (isEncryptedAttachmentUrlOrName(url)) {
            void handleResolvedNasimUrl(url, "WebSocket protobuf response");
          }
        }
      } catch (err) {
        console.debug("[Bale E2EE] WebSocket download URL inspection failed", err);
      }
    })();
  }

  function ensureWebSocketObserver(socket) {
    if (!(socket instanceof WebSocket) || watchedWebSockets.has(socket)) return;
    watchedWebSockets.add(socket);
    try { socket.addEventListener("message", inspectBaleWebSocketMessage); } catch (_) {}
  }

  if (originalWebSocketSend && globalThis.WebSocket?.prototype) {
    WebSocket.prototype.send = function baleE2EEWebSocketSend(data) {
      ensureWebSocketObserver(this);
      return originalWebSocketSend.call(this, data);
    };
  }

  function toast(message, error = false) {
    const old = document.querySelector('[data-bale-e2ee-toast="true"]');
    old?.remove();
    const el = document.createElement("div");
    el.setAttribute("data-bale-e2ee-toast", "true");
    el.setAttribute("dir", "auto");
    el.textContent = message;
    Object.assign(el.style, {
      position: "fixed",
      left: "50%",
      bottom: "24px",
      transform: "translateX(-50%)",
      zIndex: "2147483647",
      maxWidth: "min(92vw, 520px)",
      padding: "10px 14px",
      borderRadius: "12px",
      background: error ? "rgba(160, 20, 20, .94)" : "rgba(20, 20, 20, .92)",
      color: "white",
      font: "13px/1.5 system-ui, sans-serif",
      textAlign: "start",
      boxShadow: "0 6px 24px rgba(0,0,0,.25)"
    });
    document.documentElement.appendChild(el);
    setTimeout(() => el.remove(), error ? 5200 : 2600);
  }

  const E2EE_UI_STYLE_ID = "bale-e2ee-v12-ui";

  function ensureE2EEUiStyles() {
    if (document.getElementById(E2EE_UI_STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = E2EE_UI_STYLE_ID;
    style.textContent = `
      .bee11-secure-card {
        display: block;
        max-width: min(100%, 560px);
        margin: 4px 0;
        overflow: hidden;
        border-radius: 14px;
        background: rgba(0, 0, 0, 0.12);
        border: none;
        box-shadow: none;
        backdrop-filter: none;
        -webkit-backdrop-filter: none;
        animation: bee11CardIn 0.22s cubic-bezier(0.16, 1, 0.3, 1);
        transition: transform 0.16s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes bee11CardIn {
        from { opacity: 0; transform: scale(0.97) translateY(4px); }
        to { opacity: 1; transform: scale(1) translateY(0); }
      }
      .bee11-secure-card:hover {
        box-shadow: none;
      }
      .bee11-secure-media {
        display: block;
        width: 100%;
        max-height: min(58vh, 520px);
        object-fit: contain;
        background: rgba(0, 0, 0, 0.2);
        border-radius: 14px 14px 0 0;
      }
      .bee11-secure-image {
        cursor: zoom-in;
        transition: opacity 0.2s ease, transform 0.2s ease;
      }
      .bee11-secure-image:active {
        opacity: 0.9;
        transform: scale(0.99);
      }
      .bee11-secure-footer {
        display: flex;
        align-items: center;
        gap: 10px;
        min-height: 42px;
        padding: 6px 12px;
        color: #f8fafc;
        font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Shabnam", system-ui, sans-serif;
        background: rgba(0, 0, 0, 0.12);
        border-radius: 0 0 14px 14px;
      }
      .bee11-secure-file-icon {
        width: 36px;
        height: 36px;
        border-radius: 10px;
        display: grid;
        place-items: center;
        flex: 0 0 auto;
        background: rgba(56, 189, 248, 0.16);
        color: #38bdf8;
      }
      .bee11-icon-apk {
        background: rgba(34, 197, 94, 0.16) !important;
        color: #4ade80 !important;
      }
      .bee11-icon-pdf {
        background: rgba(239, 68, 68, 0.16) !important;
        color: #f87171 !important;
      }
      .bee11-icon-zip {
        background: rgba(245, 158, 11, 0.16) !important;
        color: #fbbf24 !important;
      }
      .bee11-icon-media {
        background: rgba(168, 85, 247, 0.16) !important;
        color: #c084fc !important;
      }
      .bee11-secure-meta {
        min-width: 0;
        flex: 1;
        cursor: pointer;
      }
      .bee11-secure-name {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font-weight: 600;
        letter-spacing: -0.01em;
        font-size: 13px;
        color: #ffffff;
      }
      .bee11-secure-sub {
        margin-top: 2px;
        opacity: 0.7;
        font-size: 11.5px;
        color: #cbd5e1;
      }
      .bee11-download-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.16);
        color: #ffffff;
        border: none;
        cursor: pointer;
        flex: 0 0 auto;
        transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
        -webkit-tap-highlight-color: transparent;
      }
      .bee11-download-btn:hover {
        background: rgba(255, 255, 255, 0.26);
        transform: scale(1.05);
      }
      .bee11-download-btn:active {
        transform: scale(0.92);
        background: rgba(255, 255, 255, 0.36);
      }
      .bee11-download-btn svg {
        pointer-events: none;
      }
      .bee11-secure-badge {
        display: inline-grid;
        place-items: center;
        width: 20px;
        height: 20px;
        border-radius: 999px;
        color: #34d399;
        opacity: 0.85;
        pointer-events: none;
        flex: 0 0 auto;
      }
      .bee11-icon-button {
        min-width: 40px; min-height: 40px; width: 40px; height: 40px; display: grid; place-items: center; flex: 0 0 auto; border: 0;
        border-radius: 10px; background: transparent; color: inherit; cursor: pointer; opacity: .75;
        transition: background 0.14s ease, opacity 0.14s ease, transform 0.1s ease;
        -webkit-tap-highlight-color: transparent;
      }
      .bee11-icon-button:hover { background: color-mix(in srgb, currentColor 10%, transparent); opacity: 1; }
      .bee11-icon-button:active { transform: scale(0.92); }
      .bee11-icon-button svg, .bee11-secure-file-icon svg, .bee11-secure-badge svg, .bee11-viewer-top-close svg {
        pointer-events: none;
      }
      .bee11-card-badge {
        position: absolute; inset-inline-end: 6px; inset-block-start: 6px; z-index: 2;
        width: 22px; height: 22px; display: grid; place-items: center; border-radius: 999px;
        background: rgba(20,24,28,.72); color: #10b981; backdrop-filter: blur(6px); pointer-events: none;
        box-shadow: 0 1px 3px rgba(0,0,0,.2);
      }
      .bee11-icon-loading {
        position: relative !important;
      }
      .bee11-card-spinner {
        position: absolute; inset: 0; display: grid; place-items: center; border-radius: inherit;
        background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(4px); color: #38bdf8; z-index: 10;
        pointer-events: none !important;
        animation: bee11FadeIn 0.15s ease;
      }
      .bee11-spin {
        animation: bee11Rotate 0.75s linear infinite;
      }
      @keyframes bee11Rotate {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }
      .bee11-decrypting-badge {
        display: inline-block; font-size: 11px; color: #38bdf8; margin-top: 2px;
        font-family: -apple-system, BlinkMacSystemFont, "Shabnam", system-ui, sans-serif;
        animation: bee11Pulse 1.2s ease-in-out infinite;
        direction: rtl; text-align: right;
      }
      .bee11-decrypting-badge.is-error {
        color: #f87171 !important; animation: none !important;
      }
      @keyframes bee11Pulse {
        0%, 100% { opacity: 0.65; }
        50% { opacity: 1; }
      }
      .bee11-viewer {
        position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center;
        padding: max(16px, env(safe-area-inset-top)) max(16px, env(safe-area-inset-right)) max(16px, env(safe-area-inset-bottom)) max(16px, env(safe-area-inset-left));
        background: rgba(7, 9, 12, 0.92); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
        animation: bee11FadeIn 0.18s cubic-bezier(0.16, 1, 0.3, 1);
        touch-action: pan-y;
      }
      @keyframes bee11FadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      .bee11-viewer-top-close {
        position: fixed; inset-inline-end: max(16px, env(safe-area-inset-right)); inset-block-start: max(16px, env(safe-area-inset-top));
        z-index: 2147483647; width: 44px; height: 44px; border-radius: 999px;
        background: rgba(30, 38, 48, 0.82); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        color: #ffffff; cursor: pointer; display: grid; place-items: center; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
        transition: transform 0.12s ease, background 0.12s ease;
        -webkit-tap-highlight-color: transparent;
      }
      .bee11-viewer-top-close:active { transform: scale(0.92); background: rgba(50, 60, 75, 0.95); }
      .bee11-viewer-card {
        max-width: min(96vw, 1100px); max-height: 94vh; display: flex; flex-direction: column; overflow: hidden;
        border-radius: 20px; background: #0f141a; border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 32px 100px rgba(0, 0, 0, 0.6);
        animation: bee11ZoomIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes bee11ZoomIn {
        from { transform: scale(0.96); opacity: 0.8; }
        to { transform: scale(1); opacity: 1; }
      }
      .bee11-viewer-media { display: block; max-width: 96vw; max-height: 80vh; object-fit: contain; background: #080b0e; }
      .bee11-viewer-bar {
        display: flex; align-items: center; gap: 12px; padding: 12px 16px; color: #f8fafc;
        background: rgba(15, 20, 26, 0.9); backdrop-filter: blur(12px);
        font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Shabnam", system-ui, sans-serif;
      }
      .bee11-viewer-name { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
      [data-bale-e2ee-encrypted-card="true"] { position: relative !important; }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function makeUiIcon(name, size = 18) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", String(size));
    svg.setAttribute("height", String(size));
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    const paths = {
      secure: ["M12 3.4 19 6v5.4c0 4.2-2.7 7.4-7 9.2-4.3-1.8-7-5-7-9.2V6l7-2.6Z", "M9.3 11V9.3a2.7 2.7 0 0 1 5.4 0V11m-6.2 0h7v5h-7z"],
      download: ["M12 3v11", "m8 10 4 4 4-4", "M5 20h14"],
      close: ["M6 6l12 12", "M18 6 6 18"],
      file: ["M7 3h7l4 4v14H7z", "M14 3v5h5"],
      image: ["M4 5h16v14H4z", "m6 14 3.8-4.6 3 3 2.2-2.4 5 4", "M9 9.2h.01"],
      video: ["M4 6h11v12H4z", "m15 9 4-3v6z"],
      audio: ["M9 18V6l9-2v12", "M9 18a3 2 0 1 1-6 0 3 2 0 1 1 6 0Zm9-2a3 2 0 1 1-6 0 3 2 0 1 1 6 0Z"],
      apk: ["M5 16V9a7 7 0 0 1 14 0v7a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2Z", "M9 9h.01", "M15 9h.01", "M8.5 4.5 7 2", "M15.5 4.5 17 2"]
    };
    for (const d of paths[name] || paths.file) {
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", d);
      svg.appendChild(path);
    }
    return svg;
  }

  function formatFileSize(bytes) {
    const n = Number(bytes || 0);
    if (!Number.isFinite(n) || n < 0) return "";
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB"];
    let value = n / 1024;
    let unit = units[0];
    for (let i = 1; i < units.length && value >= 1024; i += 1) { value /= 1024; unit = units[i]; }
    return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${unit}`;
  }

  async function saveDecryptedBlob(blob, name) {
    if (!(blob instanceof Blob)) return;
    let head = null;
    try {
      head = new Uint8Array(await blob.slice(0, 64).arrayBuffer());
    } catch (_) {}
    const cleanName = resolveProperFilename(blob, { name }, name, head);
    let mime = blob.type && blob.type !== "application/octet-stream" ? blob.type : "";
    if (!mime && head) mime = inferMimeFromHead(head, cleanName);
    if (!mime) mime = "application/octet-stream";
    const typedBlob = blob.type === mime ? blob : new Blob([blob], { type: mime });
    const url = originalCreateObjectURL(typedBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = cleanName;
    a.setAttribute("download", cleanName);
    a.setAttribute("data-bale-e2ee-safe-download", "true");
    a.style.display = "none";
    (document.body || document.documentElement).appendChild(a);
    try {
      if (originalAnchorClick) originalAnchorClick.call(a);
      else a.click();
    } catch (_) {
      try { a.click(); } catch (_) {}
    }
    setTimeout(() => {
      try { a.remove(); } catch (_) {}
      try { URL.revokeObjectURL(url); } catch (_) {}
    }, 60000);
    toast(`فایل ${cleanName} دریافت و ذخیره شد`);
  }

  function markEncryptedAttachmentSurface(surface) {
    if (!(surface instanceof Element) || !surface.isConnected) return;
    ensureE2EEUiStyles();
    const host = findClickableAttachmentSurface(surface) || surface;
    if (!(host instanceof Element)) return;
    host.setAttribute("data-bale-e2ee-encrypted-card", "true");
  }

  function clearCardDecryptingState(card) {
    if (!(card instanceof Element)) return;
    card.removeAttribute("data-bale-e2ee-decrypting");
    const spinner = card.querySelector?.('.bee11-card-spinner');
    if (spinner) spinner.remove();
    const iconContainer = card.querySelector?.('.vMR6Iw, [class*="vMR6Iw"]');
    if (iconContainer) iconContainer.classList.remove("bee11-icon-loading");
    const badge = card.querySelector?.('.bee11-decrypting-badge');
    if (badge) badge.remove();
  }

  function showCardDecryptingState(card, outerName, stageText = "در حال دریافت لینک فایل...") {
    if (!(card instanceof Element)) return;
    requestAnimationFrame(() => {
      if (!card.isConnected) return;
      ensureE2EEUiStyles();
      card.setAttribute("data-bale-e2ee-decrypting", "true");
      if (outerName) card.setAttribute("data-bale-e2ee-outer-name", outerName);
      
      const iconContainer = card.querySelector?.('.vMR6Iw, [class*="vMR6Iw"]') || card.querySelector?.('svg')?.parentElement || card;
      if (iconContainer instanceof Element && !iconContainer.querySelector?.('.bee11-card-spinner')) {
        iconContainer.classList.add("bee11-icon-loading");
        const spinner = document.createElement("div");
        spinner.className = "bee11-card-spinner";
        spinner.innerHTML = `
          <svg viewBox="0 0 24 24" width="22" height="22" class="bee11-spin">
            <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-dasharray="28" stroke-dashoffset="10"/>
          </svg>
        `;
        iconContainer.appendChild(spinner);
      }

      let badge = card.querySelector?.('.bee11-decrypting-badge');
      const titleEl = card.querySelector?.('.rCv9Za, p[dir="auto"], [class*="rCv9Za"]');
      if (!badge && titleEl instanceof Element) {
        badge = document.createElement("span");
        badge.className = "bee11-decrypting-badge";
        badge.setAttribute("dir", "rtl");
        titleEl.insertAdjacentElement("afterend", badge);
      }
      if (badge) {
        badge.textContent = stageText;
      }
    });

    // Auto-timeout after 90 seconds (generous for large files/videos)
    setTimeout(() => {
      if (card.isConnected && card.getAttribute("data-bale-e2ee-decrypting") === "true") {
        clearCardDecryptingState(card);
      }
    }, 90000);
  }

  function updateCardStage(cardOrOuterName, stageText, isError = false) {
    let card = null;
    if (cardOrOuterName instanceof Element) {
      card = cardOrOuterName;
    } else if (typeof cardOrOuterName === "string" && cardOrOuterName) {
      card = findCardByOuterName(cardOrOuterName);
      if (!card && pendingAttachmentClick?.outerName === cardOrOuterName) {
        card = pendingAttachmentClick.surface;
      }
    }
    if (!card || !card.isConnected) return;
    const badge = card.querySelector?.('.bee11-decrypting-badge');
    if (badge) {
      badge.textContent = stageText;
      if (isError) {
        badge.classList.add("is-error");
        const spinner = card.querySelector?.('.bee11-card-spinner');
        if (spinner) spinner.remove();
        const iconContainer = card.querySelector?.('.vMR6Iw, [class*="vMR6Iw"]');
        if (iconContainer) iconContainer.classList.remove("bee11-icon-loading");
      } else {
        badge.classList.remove("is-error");
      }
    } else {
      showCardDecryptingState(card, typeof cardOrOuterName === "string" ? cardOrOuterName : "", stageText);
      if (isError) {
        requestAnimationFrame(() => {
          card.querySelector?.('.bee11-decrypting-badge')?.classList.add("is-error");
          card.querySelector?.('.bee11-card-spinner')?.remove();
          card.querySelector?.('.vMR6Iw, [class*="vMR6Iw"]')?.classList.remove("bee11-icon-loading");
        });
      }
    }
  }

  function findComposerFrom(target) {
    if (target instanceof Element) {
      for (const selector of INPUT_SELECTORS) {
        const hit = target.closest?.(selector);
        if (hit) return hit;
      }
    }
    const active = document.activeElement;
    if (active instanceof Element) {
      for (const selector of INPUT_SELECTORS) {
        const hit = active.closest?.(selector);
        if (hit) return hit;
      }
    }
    for (const selector of INPUT_SELECTORS) {
      const el = document.querySelector(selector);
      if (el) return el;
    }
    return null;
  }

  function mediaContextActive() {
    return mediaCandidates.length > 0 || Date.now() - lastMediaStageAt < MEDIA_CONTEXT_MS;
  }

  function mediaDialogFor(target) {
    if (!(target instanceof Element)) return null;
    // Prefer semantic/explicit dialog containers. Do not let a control whose own
    // class is e.g. `modal-send` or `dialog-confirm` become the "dialog" itself.
    const explicit = target.closest?.('[role="dialog"], .modal, .dialog');
    if (explicit) return explicit;
    return target.parentElement?.closest?.('[class*="modal" i], [class*="dialog" i]') || null;
  }

  function secureDocumentSendPending() {
    return mediaCandidates.length > 0 && Date.now() <= secureDocumentModeUntil;
  }

  function mediaSendContextActive() {
    return activeMedia.length > 0 || secureDocumentSendPending();
  }

  function findActiveMediaDialog() {
    const fromActive = mediaDialogFor(document.activeElement);
    if (fromActive && isVisible(fromActive)) return fromActive;
    const dialogs = [...document.querySelectorAll(
      '[role="dialog"], .modal, .dialog, [class*="modal" i], [class*="dialog" i]'
    )].filter(isVisible);
    return dialogs.at(-1) || null;
  }

  function isCaptionEditorCandidate(el) {
    if (!(el instanceof Element) || !isVisible(el)) return false;
    if (el.id === "editable-message-text") return false;
    if (el instanceof HTMLInputElement) {
      const type = (el.type || "text").toLowerCase();
      if (!["text", ""].includes(type)) return false;
    }
    return CAPTION_EDITOR_SELECTORS.some((selector) => el.matches?.(selector));
  }

  function captionCandidateSignal(el) {
    return [
      el.getAttribute?.("aria-label"),
      el.getAttribute?.("placeholder"),
      el.getAttribute?.("data-testid"),
      el.getAttribute?.("name"),
      el.id,
      typeof el.className === "string" ? el.className : ""
    ].filter(Boolean).join(" ");
  }

  function findCaptionComposer(target) {
    const dialog = mediaDialogFor(target) || findActiveMediaDialog();
    if (!dialog) return null;

    const active = document.activeElement;
    if (active instanceof Element && dialog.contains(active) && isCaptionEditorCandidate(active)) {
      const signal = captionCandidateSignal(active);
      if (!CAPTION_NEGATIVE_HINT_RE.test(signal)) return active;
    }

    const seen = new Set();
    const candidates = [];
    for (const selector of CAPTION_EDITOR_SELECTORS) {
      for (const el of dialog.querySelectorAll(selector)) {
        if (seen.has(el) || !isCaptionEditorCandidate(el)) continue;
        seen.add(el);
        const signal = captionCandidateSignal(el);
        if (CAPTION_NEGATIVE_HINT_RE.test(signal)) continue;
        let score = 0;
        if (CAPTION_HINT_RE.test(signal)) score += 100;
        if (getText(el).trim()) score += 35;
        if (el.getAttribute("role") === "textbox") score += 15;
        if (el.isContentEditable) score += 10;
        const rect = el.getBoundingClientRect();
        const dr = dialog.getBoundingClientRect();
        if (rect.top > dr.top + dr.height * 0.45) score += 12;
        if (target instanceof Element) {
          const tr = target.getBoundingClientRect();
          const dy = Math.abs((rect.top + rect.height / 2) - (tr.top + tr.height / 2));
          score += Math.max(0, 20 - Math.min(20, dy / 20));
        }
        candidates.push({ el, score });
      }
    }
    candidates.sort((a, b) => b.score - a.score);
    if (!candidates.length) return null;
    if (candidates.length === 1) return candidates[0].el;
    return candidates[0].score >= 25 ? candidates[0].el : null;
  }

  function findComposerForSendTarget(target) {
    if (mediaSendContextActive() || mediaDialogFor(target)) {
      const caption = findCaptionComposer(target);
      if (caption) return caption;
    }
    return findComposerFrom(document.activeElement || target);
  }

  function hasPositiveSendSemantics(el) {
    if (!(el instanceof Element)) return false;
    const text = String(el.innerText || el.textContent || "").trim();
    const aria = String(el.getAttribute("aria-label") || "");
    const title = String(el.getAttribute("title") || "");
    const testid = String(el.getAttribute("data-testid") || "");
    const cls = typeof el.className === "string" ? el.className : "";
    const signal = `${text} ${aria} ${title} ${testid} ${cls}`;
    if (/(send|submit|confirm|done|check|ارسال|تایید|تأیید|ثبت|✓|✔)/i.test(signal)) return true;

    // Bale media confirmation can be an icon-only button. Only accept a
    // generic SVG button if it sits near the bottom edge of a media dialog;
    // this avoids treating crop/rotate toolbar buttons as Send.
    if (el.matches?.('button:has(svg), [role="button"]:has(svg)')) {
      const dialog = mediaDialogFor(el);
      if (!dialog) return false;
      const br = el.getBoundingClientRect();
      const dr = dialog.getBoundingClientRect();
      return br.bottom >= dr.bottom - Math.min(140, Math.max(80, dr.height * 0.22));
    }
    return false;
  }

  function isMediaConfirmTarget(target) {
    if (!mediaSendContextActive() || !(target instanceof Element)) return false;
    const candidate = target.closest?.(MEDIA_CONFIRM_SELECTORS.join(","));
    return Boolean(candidate && isVisible(candidate) && hasPositiveSendSemantics(candidate));
  }

  function findSendButton() {
    for (const selector of SEND_SELECTORS) {
      for (const el of document.querySelectorAll(selector)) {
        if (isVisible(el)) return el;
      }
    }
    if (mediaContextActive()) {
      for (const selector of MEDIA_CONFIRM_SELECTORS) {
        for (const el of document.querySelectorAll(selector)) {
          if (isVisible(el) && hasPositiveSendSemantics(el)) return el;
        }
      }
    }
    return null;
  }

  function findSendButtonNear(target) {
    const dialog = mediaDialogFor(target) || findActiveMediaDialog();
    if (!dialog) return null;
    for (const selector of SEND_SELECTORS) {
      for (const el of dialog.querySelectorAll(selector)) {
        if (isVisible(el)) return el;
      }
    }
    for (const selector of MEDIA_CONFIRM_SELECTORS) {
      for (const el of dialog.querySelectorAll(selector)) {
        if (isVisible(el) && hasPositiveSendSemantics(el)) return el;
      }
    }
    return null;
  }

  function isSendTarget(target) {
    if (!(target instanceof Element)) return false;
    if (SEND_SELECTORS.some((selector) => target.closest?.(selector))) return true;
    return isMediaConfirmTarget(target);
  }

  function resolveSendTarget(target) {
    if (!(target instanceof Element)) return null;
    for (const selector of SEND_SELECTORS) {
      const hit = target.closest?.(selector);
      if (hit && isVisible(hit)) return hit;
    }
    if (mediaSendContextActive()) {
      for (const selector of MEDIA_CONFIRM_SELECTORS) {
        const hit = target.closest?.(selector);
        if (hit && isVisible(hit) && hasPositiveSendSemantics(hit)) return hit;
      }
    }
    return null;
  }

  function isVisible(el) {
    if (!(el instanceof Element)) return false;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  }

  function getText(el) {
    if (!el) return "";
    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return el.value || "";
    return el.innerText || el.textContent || "";
  }

  function setNativeValue(input, value) {
    const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
    if (descriptor?.set) descriptor.set.call(input, value);
    else input.value = value;
  }

  function setTextLikeBale(el, text) {
    if (!el) return false;
    el.focus();

    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
      setNativeValue(el, text);
      el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return el.value === text;
    }

    if (el.isContentEditable || el.getAttribute("role") === "textbox") {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      selection?.removeAllRanges();
      selection?.addRange(range);

      let inserted = false;
      try {
        // Never use document-wide selectAll here: Bale can have the main chat
        // composer and a media-caption editor mounted at the same time. The
        // explicit Range keeps the mutation scoped to the intended editor.
        inserted = document.execCommand("insertText", false, text);
      } catch (_) {
        inserted = false;
      }

      if (!inserted || getText(el).trim() !== text.trim()) {
        const fallbackRange = document.createRange();
        fallbackRange.selectNodeContents(el);
        fallbackRange.deleteContents();
        fallbackRange.insertNode(document.createTextNode(text));
        fallbackRange.collapse(false);
        selection?.removeAllRanges();
        selection?.addRange(fallbackRange);
      }

      el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return getText(el).trim() === text.trim();
    }

    return false;
  }

  function rememberInlineStyle(el, property) {
    return {
      value: el.style.getPropertyValue(property),
      priority: el.style.getPropertyPriority(property)
    };
  }

  function restoreInlineStyle(el, property, old) {
    if (!old.value && !old.priority) el.style.removeProperty(property);
    else el.style.setProperty(property, old.value, old.priority);
  }

  function createPlaintextMirror(composer, plain) {
    const rect = composer.getBoundingClientRect();
    const cs = getComputedStyle(composer);
    const overlay = document.createElement("div");
    overlay.setAttribute("data-bale-e2ee-mirror", "true");
    overlay.setAttribute("dir", composer.getAttribute?.("dir") || "auto");
    overlay.textContent = plain;
    Object.assign(overlay.style, {
      position: "fixed",
      left: `${rect.left}px`,
      top: `${rect.top}px`,
      width: `${rect.width}px`,
      height: `${rect.height}px`,
      boxSizing: cs.boxSizing,
      padding: cs.padding,
      margin: "0",
      border: "0",
      overflow: "hidden",
      whiteSpace: "pre-wrap",
      overflowWrap: "anywhere",
      pointerEvents: "none",
      zIndex: "2147483647",
      background: "transparent",
      color: cs.color,
      font: cs.font,
      fontFamily: cs.fontFamily,
      fontSize: cs.fontSize,
      fontWeight: cs.fontWeight,
      lineHeight: cs.lineHeight,
      letterSpacing: cs.letterSpacing,
      textAlign: cs.textAlign
    });

    const props = ["color", "caret-color", "-webkit-text-fill-color", "height", "max-height", "overflow"];
    const old = Object.fromEntries(props.map((p) => [p, rememberInlineStyle(composer, p)]));
    composer.style.setProperty("color", "transparent", "important");
    composer.style.setProperty("caret-color", "transparent", "important");
    composer.style.setProperty("-webkit-text-fill-color", "transparent", "important");
    composer.style.setProperty("height", `${rect.height}px`, "important");
    composer.style.setProperty("max-height", `${rect.height}px`, "important");
    composer.style.setProperty("overflow", "hidden", "important");
    document.documentElement.appendChild(overlay);

    return () => {
      overlay.remove();
      for (const prop of props) restoreInlineStyle(composer, prop, old[prop]);
    };
  }

  function nextFrame() {
    return new Promise((resolve) => requestAnimationFrame(resolve));
  }

  async function waitForMainComposer(timeoutMs = 4000) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const direct = document.querySelector('#editable-message-text');
      if (direct instanceof Element && isVisible(direct) && !direct.closest('[role="dialog"], .modal, .dialog, [class*="modal" i], [class*="dialog" i]')) return direct;
      for (const selector of INPUT_SELECTORS) {
        for (const el of document.querySelectorAll(selector)) {
          if (isVisible(el) && !el.closest('[role="dialog"], .modal, .dialog, [class*="modal" i], [class*="dialog" i]')) return el;
        }
      }
      await new Promise((r) => setTimeout(r, 80));
    }
    return findComposerFrom(document.activeElement);
  }

  async function sendEncrypted(composer, plain, options = {}) {
    if (sending) return false;
    sending = true;
    let cleanupMirror = null;
    let currentComposer = composer;

    try {
      const items = await requestEncrypt(plain);
      if (!items.length || items.some((item) => !isEncryptedWire(item?.cipher))) throw new Error("invalid encrypted payload");

      for (let index = 0; index < items.length; index += 1) {
        const item = items[index];
        const cipher = String(item.cipher || "");
        const plainPiece = String(item.plain ?? "");

        if (index > 0) {
          cleanupMirror?.();
          cleanupMirror = null;
          currentComposer = await waitForMainComposer();
          if (!(currentComposer instanceof Element)) throw new Error("Bale composer not found for encrypted continuation chunk");
        }

        const customDisplay = index === 0 && Object.prototype.hasOwnProperty.call(options, "displayText")
          ? String(options.displayText ?? "")
          : plainPiece;
        cleanupMirror = createPlaintextMirror(currentComposer, customDisplay);
        post("OUTGOING_MAPPING", { cipher, plain: plainPiece });
        setTextLikeBale(currentComposer, cipher);

        await nextFrame();
        if (getText(currentComposer).trim() !== cipher.trim()) setTextLikeBale(currentComposer, cipher);

        const preferredSend = index === 0 && options.sendTarget instanceof Element && isVisible(options.sendTarget)
          ? options.sendTarget
          : null;
        const send = preferredSend || findSendButton();
        if (!send) throw new Error("Bale send button not found");

        bypassNextSendClick = true;
        send.dispatchEvent(new MouseEvent("click", {
          bubbles: true,
          cancelable: true,
          composed: true,
          view: window
        }));

        await nextFrame();
        await new Promise((r) => setTimeout(r, index === 0 && preferredSend ? 180 : 100));

        const composerDetached = !currentComposer.isConnected;
        const sendDetached = preferredSend ? !preferredSend.isConnected : false;
        let after = composerDetached ? "" : getText(currentComposer).trim();
        // React can clear a controlled composer a little after the click handler.
        for (let retry = 0; retry < 4 && after === cipher.trim() && !composerDetached && !sendDetached; retry += 1) {
          await new Promise((r) => setTimeout(r, 100));
          after = currentComposer.isConnected ? getText(currentComposer).trim() : "";
        }
        if (after === cipher.trim() && currentComposer.isConnected && !sendDetached) {
          if (!(index === 0 && options.acceptDispatchedSend)) {
            const fallback = Object.prototype.hasOwnProperty.call(options, "restoreText") ? String(options.restoreText ?? "") : plain;
            setTextLikeBale(currentComposer, fallback);
            throw new Error("Bale did not consume the encrypted draft");
          }
          console.debug("[Bale E2EE] encrypted media caption chunk dispatched while Bale finishes the media send");
        }
      }

      if (Object.prototype.hasOwnProperty.call(options, "restoreText")) {
        const target = currentComposer?.isConnected ? currentComposer : await waitForMainComposer(1500);
        if (target?.isConnected) setTextLikeBale(target, String(options.restoreText ?? ""));
      }
      return true;
    } catch (err) {
      console.error("[Bale E2EE] encrypted send failed:", err);
      const fallback = Object.prototype.hasOwnProperty.call(options, "restoreText") ? String(options.restoreText ?? "") : plain;
      if (!options.keepCipherOnFailure && currentComposer?.isConnected && isEncryptedWire(getText(currentComposer).trim())) {
        setTextLikeBale(currentComposer, fallback);
      }
      return false;
    } finally {
      cleanupMirror?.();
      sending = false;
    }
  }

  function intercept(event, composer) {
    if (!enabled || !composer) return false;
    const plain = getText(composer);
    if (!plain.trim() || isEncryptedWire(plain.trim())) return false;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation?.();
    if (sending) {
      console.debug("[Bale E2EE] send ignored while previous encrypted send is still settling; plaintext event remained blocked");
      return true;
    }
    void sendEncrypted(composer, plain);
    return true;
  }

  function fileListToArray(fileList) {
    return Array.from(fileList || []).filter((x) => x instanceof File);
  }

  function mediaListFromTransfer(transfer) {
    return fileListToArray(transfer?.files);
  }

  function makeGenericOuterName() {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    return `attachment-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}.bin`;
  }

  function genericOuterNameFor(blob) {
    if (blob instanceof File && blob.name) return blob.name;
    if (!(blob instanceof Blob)) return makeGenericOuterName();
    let name = genericBlobNames.get(blob);
    if (!name) {
      name = makeGenericOuterName();
      genericBlobNames.set(blob, name);
    }
    return name;
  }

  function currentOuterFilename() {
    const file = mediaCandidates.find((item) => item instanceof File && item.name);
    return file?.name || "attachment.bin";
  }

  function isVisualAttachment(file) {
    return file instanceof Blob && /^(image|video)\//i.test(String(file.type || ""));
  }

  function inputSignal(input) {
    if (!(input instanceof HTMLInputElement)) return "";
    const parent = input.closest?.('[role="menu"], [role="dialog"], label, [class*="attach" i], [class*="upload" i]');
    return [
      input.accept,
      input.getAttribute("aria-label"),
      input.getAttribute("title"),
      input.getAttribute("name"),
      input.id,
      typeof input.className === "string" ? input.className : "",
      parent?.getAttribute?.("aria-label"),
      parent?.getAttribute?.("title"),
      parent?.textContent?.slice?.(0, 160)
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function looksLikeMediaPicker(input) {
    const signal = inputSignal(input);
    return /(image|video|photo|gallery|camera|media|عکس|تصویر|ویدیو|گالری|دوربین)/i.test(signal);
  }

  function scoreDocumentInput(input, sourceInput) {
    if (!(input instanceof HTMLInputElement) || input.type !== "file" || input.disabled) return -Infinity;
    const accept = String(input.accept || "").toLowerCase().trim();
    const signal = inputSignal(input);
    let score = 0;
    if (input === sourceInput) score -= 12;
    if (!accept || accept === "*/*") score += 12;
    if (/(application|text|pdf|zip|document|file|سند|فایل)/i.test(`${accept} ${signal}`)) score += 10;
    if (/(image|video|photo|gallery|camera|media|عکس|تصویر|ویدیو|گالری|دوربین)/i.test(`${accept} ${signal}`)) score -= 18;
    if (input.multiple) score += 1;
    return score;
  }

  function findDocumentFileInput(sourceInput = null) {
    let best = null;
    let bestScore = -Infinity;
    for (const input of document.querySelectorAll('input[type="file"]')) {
      const score = scoreDocumentInput(input, sourceInput);
      if (score > bestScore) {
        best = input;
        bestScore = score;
      }
    }
    return bestScore >= 0 ? best : null;
  }

  async function waitForDocumentFileInput(sourceInput = null, timeoutMs = 700) {
    const immediate = findDocumentFileInput(sourceInput);
    if (immediate) return immediate;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      const found = findDocumentFileInput(sourceInput);
      if (found) return found;
    }
    return null;
  }

  function makeFileList(files) {
    let transfer = null;
    try { transfer = new DataTransfer(); } catch (_) {}
    if (!transfer && typeof ClipboardEvent === "function") {
      try { transfer = new ClipboardEvent("").clipboardData; } catch (_) {}
    }
    if (!transfer?.items) throw new Error("DataTransfer is unavailable in this browser context");
    for (const file of files) transfer.items.add(file);
    return { transfer, files: transfer.files };
  }

  function setInputFiles(input, files) {
    const { files: fileList } = makeFileList(files);
    try {
      input.files = fileList;
      return input.files?.length === files.length;
    } catch (_) {
      return false;
    }
  }

  function markForwardedEvent(event) {
    try { Object.defineProperty(event, "__baleE2EEForwarded", { value: true }); } catch (_) {}
    processedAttachmentEvents.add(event);
    return event;
  }

  function rememberFilename(original, encrypted) {
    const origName = typeof original === "string" ? original : original?.name;
    const encName = typeof encrypted === "string" ? encrypted : encrypted?.name;
    if (!origName || !encName || origName === encName) return;
    filenameDisplayMap.set(encName, origName);
    try { sessionStorage.setItem("bale_fn_" + encName, origName); } catch (_) {}
    setTimeout(() => filenameDisplayMap.delete(encName), 60 * 60 * 1000);
  }

  function markSecureDocumentContext(encryptedFiles) {
    activeMediaGeneration += 1;
    const generation = activeMediaGeneration;
    const now = Date.now();
    activeMedia = [];
    mediaCandidates = encryptedFiles.slice();
    lastMediaStageAt = now;
    uploadGuardArmedUntil = Math.max(uploadGuardArmedUntil, now + MEDIA_CONTEXT_MS);
    secureDocumentModeUntil = Math.max(secureDocumentModeUntil, now + MEDIA_CONTEXT_MS);
    for (const file of encryptedFiles) encryptedMediaBlobs.add(file);
    setTimeout(() => {
      if (activeMediaGeneration === generation) mediaCandidates = [];
    }, MEDIA_CONTEXT_MS);
  }

  async function encryptSelectionFiles(files, source) {
    const encryptedFiles = [];
    for (let i = 0; i < files.length; i += 1) {
      const original = files[i];
      toast(`در حال رمزنگاری فایل ${i + 1}/${files.length}…`);
      const encrypted = await requestEncryptFile(original);
      if (!(encrypted instanceof Blob)) throw new Error("encrypted file bridge returned invalid data");
      const safeFile = encrypted instanceof File
        ? encrypted
        : new File([encrypted], makeGenericOuterName(), { type: "application/octet-stream", lastModified: Date.now() });
      encryptedMediaBlobs.add(safeFile);
      rememberFilename(original, safeFile);
      encryptedFiles.push(safeFile);
    }
    markSecureDocumentContext(encryptedFiles);
    console.log(`[Bale E2EE] v8 encrypted ${encryptedFiles.length} attachment(s) before Bale consumed ${source}`, encryptedFiles.map((file) => ({
      outerName: file.name,
      outerType: file.type,
      encryptedSize: file.size
    })));
    return encryptedFiles;
  }

  function dispatchEncryptedInputChange(targetInput, encryptedFiles, sourceInput) {
    const oldAccept = targetInput.accept;
    // If we must reuse a media input, make the synchronous handler see a generic
    // file picker. The ciphertext File itself is also octet-stream + .bin.
    if (targetInput === sourceInput && looksLikeMediaPicker(sourceInput)) targetInput.accept = "";
    if (!setInputFiles(targetInput, encryptedFiles)) throw new Error("browser refused encrypted FileList substitution");
    const forwarded = markForwardedEvent(new Event("change", { bubbles: true, composed: true }));
    targetInput.dispatchEvent(forwarded);
    queueMicrotask(() => { targetInput.accept = oldAccept; });
  }

  async function routeInputSelectionAsEncryptedDocument(input, files) {
    const encryptedFiles = await encryptSelectionFiles(files, "file-input");
    const visual = files.some(isVisualAttachment) || looksLikeMediaPicker(input);
    const documentInput = visual ? await waitForDocumentFileInput(input) : input;
    const targetInput = documentInput || input;
    dispatchEncryptedInputChange(targetInput, encryptedFiles, input);
    if (visual) {
      console.log(`[Bale E2EE] v8 routed visual attachment through ${targetInput === input ? "genericized source input" : "document input"}; native Photo pipeline bypassed`);
    }
    toast(visual ? "عکس/ویدیو به صورت فایل رمزنگاری‌شده امن آماده شد" : "فایل رمزنگاری شد");
  }

  function makeSyntheticTransferEvent(type, files) {
    const { transfer } = makeFileList(files);
    let event;
    try {
      if (type === "drop" && typeof DragEvent === "function") {
        event = new DragEvent("drop", { bubbles: true, cancelable: true, composed: true, dataTransfer: transfer });
      } else if (type === "paste" && typeof ClipboardEvent === "function") {
        event = new ClipboardEvent("paste", { bubbles: true, cancelable: true, composed: true, clipboardData: transfer });
      }
    } catch (_) {}
    if (!event) event = new Event(type, { bubbles: true, cancelable: true, composed: true });
    const key = type === "paste" ? "clipboardData" : "dataTransfer";
    try { Object.defineProperty(event, key, { configurable: true, value: transfer }); } catch (_) {}
    return markForwardedEvent(event);
  }

  async function routeTransferAsEncryptedDocument(originalEvent, files, source) {
    const encryptedFiles = await encryptSelectionFiles(files, source);
    const documentInput = await waitForDocumentFileInput(null, 350);
    if (documentInput) {
      dispatchEncryptedInputChange(documentInput, encryptedFiles, documentInput);
      console.log(`[Bale E2EE] v8 routed ${source} attachment through Bale document input`);
    } else if (originalEvent.target instanceof EventTarget) {
      originalEvent.target.dispatchEvent(makeSyntheticTransferEvent(source === "clipboard-paste" ? "paste" : "drop", encryptedFiles));
      console.log(`[Bale E2EE] v8 replayed ${source} with octet-stream BEE3FILE payloads`);
    } else {
      throw new Error("could not find a Bale document attachment target");
    }
    toast("پیوست به صورت فایل رمزنگاری‌شده امن آماده شد");
  }

  function stageOneMedia(file) {
    if (!(file instanceof Blob)) return null;
    const known = stagedMedia.get(file);
    if (known) return known;

    const state = { encrypted: null, error: null, armed: false, promise: null, plainSize: file.size };
    state.promise = requestEncryptFile(file)
      .then((encrypted) => {
        if (!(encrypted instanceof Blob)) throw new Error("encrypted file bridge returned invalid data");
        state.encrypted = encrypted instanceof File
          ? encrypted
          : new File([encrypted], makeGenericOuterName(), {
              type: "application/octet-stream",
              lastModified: Date.now()
            });
        encryptedMediaBlobs.add(state.encrypted);
        return state.encrypted;
      })
      .catch((err) => {
        state.error = err;
        throw err;
      });
    stagedMedia.set(file, state);
    return state;
  }

  function stageMediaFiles(files, source = "selection") {
    if (!enabled || !files.length) return;
    activeMediaGeneration += 1;
    const generation = activeMediaGeneration;
    lastMediaStageAt = Date.now();
    uploadGuardArmedUntil = Math.max(uploadGuardArmedUntil, lastMediaStageAt + MEDIA_CONTEXT_MS);
    activeMedia = files.filter((file, index, arr) => file instanceof Blob && arr.indexOf(file) === index);
    mediaCandidates = activeMedia.slice();
    for (const file of activeMedia) stageOneMedia(file);
    console.log(`[Bale E2EE] staging ${activeMedia.length} media file(s) in background from ${source}`);

    // Stale selections should never affect a later unrelated Send click.
    setTimeout(() => {
      if (activeMediaGeneration === generation) {
        activeMedia = [];
        mediaCandidates = [];
      }
    }, MEDIA_CONTEXT_MS);
  }

  function registerDerivedMedia(blob, source = "derived") {
    if (!enabled || !(blob instanceof Blob) || !mediaContextActive()) return;
    if (encryptedMediaBlobs.has(blob) || derivedMedia.has(blob) || stagedMedia.has(blob)) return;
    derivedMedia.add(blob);
    lastMediaStageAt = Date.now();
    if (!mediaCandidates.includes(blob)) mediaCandidates.push(blob);

    // In v8 secure-document mode Bale never receives the original image/video;
    // any normal derived Blob should already derive from BEE3FILE ciphertext. Do
    // not double-encrypt it here. The final upload guard verifies magic and only
    // encrypts a genuinely unknown/raw Blob if one somehow appears.
    if (Date.now() <= secureDocumentModeUntil) {
      console.log(`[Bale E2EE] tracked secure-document derived Blob from ${source}`, {
        type: blob.type || "application/octet-stream",
        size: blob.size
      });
      return;
    }

    stageOneMedia(blob);
    console.log(`[Bale E2EE] tracked Bale-created media Blob from ${source}`, {
      type: blob.type || "application/octet-stream",
      size: blob.size
    });
  }

  // Track media objects Bale creates after selection (crop/resize/preview).
  // We never replace them here, so the UI still sees normal JPEG/PNG/video bytes.
  URL.createObjectURL = function baleE2EECreateObjectURL(object) {
    if (object instanceof Blob) {
      registerDerivedMedia(object, "URL.createObjectURL");
      if (pendingAttachmentClick) void inspectDownloadedBlobForPendingPreview(object, pendingAttachmentClick.outerName || "");
    }
    return originalCreateObjectURL(object);
  };

  FormData.prototype.append = function baleE2EEFormDataAppend(name, value, filename) {
    if (value instanceof Blob) registerDerivedMedia(value, "FormData.append");
    // v8 metadata guard: once an encrypted-document send is active, never let
    // an explicit third-argument filename override the generic encrypted name.
    const safeOuterFilename = value instanceof Blob && Date.now() <= secureDocumentModeUntil
      ? genericOuterNameFor(value)
      : filename;
    return safeOuterFilename === undefined
      ? originalFormDataAppend.call(this, name, value)
      : originalFormDataAppend.call(this, name, value, safeOuterFilename);
  };

  FormData.prototype.set = function baleE2EEFormDataSet(name, value, filename) {
    if (value instanceof Blob) registerDerivedMedia(value, "FormData.set");
    const safeOuterFilename = value instanceof Blob && Date.now() <= secureDocumentModeUntil
      ? genericOuterNameFor(value)
      : filename;
    return safeOuterFilename === undefined
      ? originalFormDataSet.call(this, name, value)
      : originalFormDataSet.call(this, name, value, safeOuterFilename);
  };

  if (typeof originalCanvasToBlob === "function") {
    HTMLCanvasElement.prototype.toBlob = function baleE2EECanvasToBlob(callback, type, quality) {
      return originalCanvasToBlob.call(this, (blob) => {
        if (blob instanceof Blob) registerDerivedMedia(blob, "canvas.toBlob");
        callback?.(blob);
      }, type, quality);
    };
  }

  if (typeof originalOffscreenConvertToBlob === "function") {
    OffscreenCanvas.prototype.convertToBlob = async function baleE2EEConvertToBlob(options) {
      const blob = await originalOffscreenConvertToBlob.call(this, options);
      if (blob instanceof Blob) registerDerivedMedia(blob, "OffscreenCanvas.convertToBlob");
      return blob;
    };
  }

  function encryptedFor(blob) {
    return armedMedia.get(blob) || stagedMedia.get(blob)?.encrypted || null;
  }

  function shadowReadonly(obj, key, getter) {
    try {
      Object.defineProperty(obj, key, { configurable: true, enumerable: false, get: getter });
      return true;
    } catch (_) {
      return false;
    }
  }

  function armMediaObject(original, encrypted) {
    if (!(original instanceof Blob) || !(encrypted instanceof Blob)) return;
    if (armedMedia.get(original) === encrypted) return;
    armedMedia.set(original, encrypted);

    // JS-side readers used for CRC/chunking now observe ciphertext. createObjectURL
    // is deliberately NOT hooked, so an already-rendered/plain preview remains intact.
    try { original.slice = (...args) => encrypted.slice(...args); } catch (_) {}
    try { original.arrayBuffer = () => encrypted.arrayBuffer(); } catch (_) {}
    try { original.stream = () => encrypted.stream(); } catch (_) {}
    try { original.text = () => encrypted.text(); } catch (_) {}
    try { if (typeof encrypted.bytes === "function") original.bytes = () => encrypted.bytes(); } catch (_) {}
    shadowReadonly(original, "size", () => encrypted.size);
    shadowReadonly(original, "type", () => encrypted.type || "application/octet-stream");
  }

  async function prepareActiveMedia() {
    const files = mediaCandidates.filter((f, index, arr) => f instanceof Blob && arr.indexOf(f) === index);
    if (!files.length) return [];

    const prepared = [];
    for (let i = 0; i < files.length; i += 1) {
      const file = files[i];
      const state = stageOneMedia(file);
      toast(`در حال آماده‌سازی رمزنگاری فایل ${i + 1}/${files.length}…`);
      let encrypted;
      try {
        encrypted = state.encrypted || await state.promise;
      } catch (err) {
        throw new Error(`media encryption failed: ${err?.message || err}`);
      }
      armMediaObject(file, encrypted);
      state.armed = true;
      prepared.push({ original: file, encrypted });
    }
    return prepared;
  }

  function replaceArmedBody(body) {
    if (!body) return body;
    const direct = encryptedFor(body);
    if (direct) return direct;

    if (body instanceof FormData) {
      let changed = false;
      const next = new FormData();
      for (const [key, value] of body.entries()) {
        if (value instanceof Blob) {
          const encrypted = encryptedFor(value);
          if (encrypted) {
            changed = true;
            const filename = encrypted instanceof File ? encrypted.name : undefined;
            if (filename !== undefined) originalFormDataAppend.call(next, key, encrypted, filename);
            else originalFormDataAppend.call(next, key, encrypted);
            continue;
          }
        }
        originalFormDataAppend.call(next, key, value);
      }
      return changed ? next : body;
    }
    return body;
  }

  function looksLikeUploadUrl(url) {
    return Boolean(url && UPLOAD_URL_RE.test(String(url)));
  }

  function uploadGuardActive() {
    return enabled && Date.now() <= uploadGuardArmedUntil && mediaContextActive();
  }

  function bytesHaveFileMagic(value) {
    let bytes = null;
    if (value instanceof ArrayBuffer) bytes = new Uint8Array(value);
    else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    if (!bytes || bytes.byteLength < FILE_MAGIC.byteLength) return false;
    for (let i = 0; i < FILE_MAGIC.byteLength; i += 1) if (bytes[i] !== FILE_MAGIC[i]) return false;
    return true;
  }

  async function ensureEncryptedUploadBlob(blob, reason = "network-upload") {
    if (!(blob instanceof Blob)) throw new Error("upload payload is not a Blob");
    if (encryptedMediaBlobs.has(blob)) return blob;
    const existing = encryptedFor(blob);
    if (existing) return existing;
    if (await blobHasMagic(blob)) return blob;

    registerDerivedMedia(blob, reason);
    const state = stageOneMedia(blob);
    if (!state) throw new Error("could not stage final Bale upload Blob");
    const encrypted = state.encrypted || await state.promise;
    encryptedMediaBlobs.add(encrypted);
    armMediaObject(blob, encrypted);
    state.armed = true;
    return encrypted;
  }

  async function prepareUploadBody(body, url, transport = "fetch") {
    if (!uploadGuardActive() || !looksLikeUploadUrl(url) || body == null) return body;

    if (body instanceof Blob) {
      const encrypted = await ensureEncryptedUploadBlob(body, `${transport}:blob`);
      if (encrypted !== body) console.log(`[Bale E2EE] ${transport} final Blob encrypted at upload boundary`, url);
      return encrypted;
    }

    if (body instanceof FormData) {
      const next = new FormData();
      let sawBlob = false;
      for (const [key, value] of body.entries()) {
        if (value instanceof Blob) {
          sawBlob = true;
          const encrypted = await ensureEncryptedUploadBlob(value, `${transport}:formdata`);
          const filename = encrypted instanceof File ? encrypted.name : undefined;
          if (filename === undefined) originalFormDataAppend.call(next, key, encrypted);
          else originalFormDataAppend.call(next, key, encrypted, filename);
        } else {
          originalFormDataAppend.call(next, key, value);
        }
      }
      if (sawBlob) {
        console.log(`[Bale E2EE] ${transport} FormData media encrypted at upload boundary`, url);
        return next;
      }
      return body;
    }

    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      if (bytesHaveFileMagic(body)) return body;

      // If Bale flattened one complete selected file into bytes, we can still
      // substitute the already prepared encrypted twin safely. Chunk/range
      // uploads cannot be independently wrapped as BEE3FILE chunks because the
      // resulting concatenation would not be a valid single container.
      const byteLength = body instanceof ArrayBuffer ? body.byteLength : body.byteLength;
      const exact = mediaCandidates
        .map((blob) => ({ blob, state: stagedMedia.get(blob) }))
        .filter(({ blob, state }) => blob instanceof Blob && state && state.plainSize === byteLength);
      if (exact.length === 1) {
        const encrypted = exact[0].state.encrypted || await exact[0].state.promise;
        console.log(`[Bale E2EE] ${transport} full-buffer upload replaced with ciphertext`, url);
        return await encrypted.arrayBuffer();
      }

      throw new Error("Bale media upload reached the network as an unknown raw buffer/chunk; plaintext upload blocked");
    }

    if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) {
      throw new Error("Bale media upload reached the network as an untracked stream; plaintext upload blocked");
    }

    return body;
  }

  // Native FileReader bypasses an instance's overridden arrayBuffer(), so route
  // reads of an armed File to its encrypted twin as well.
  if (typeof originalFileReaderReadAsArrayBuffer === "function") {
    FileReader.prototype.readAsArrayBuffer = function baleE2EEReadAsArrayBuffer(blob) {
      return originalFileReaderReadAsArrayBuffer.call(this, encryptedFor(blob) || blob);
    };
  }
  if (typeof originalFileReaderReadAsBinaryString === "function") {
    FileReader.prototype.readAsBinaryString = function baleE2EEReadAsBinaryString(blob) {
      return originalFileReaderReadAsBinaryString.call(this, encryptedFor(blob) || blob);
    };
  }
  if (typeof originalFileReaderReadAsText === "function") {
    FileReader.prototype.readAsText = function baleE2EEReadAsText(blob, encoding) {
      return originalFileReaderReadAsText.call(this, encryptedFor(blob) || blob, encoding);
    };
  }
  if (typeof originalFileReaderReadAsDataURL === "function") {
    FileReader.prototype.readAsDataURL = function baleE2EEReadAsDataURL(blob) {
      return originalFileReaderReadAsDataURL.call(this, encryptedFor(blob) || blob);
    };
  }

  function cloneReplacingArmed(value, seen = new WeakMap()) {
    if (!value || typeof value !== "object") return value;
    const encrypted = encryptedFor(value);
    if (encrypted) return encrypted;
    if (seen.has(value)) return seen.get(value);
    if (Array.isArray(value)) {
      const out = [];
      seen.set(value, out);
      for (const item of value) out.push(cloneReplacingArmed(item, seen));
      return out;
    }
    // Do not clone framework/protobuf/class instances. Only plain objects used
    // as Worker envelopes are safe to copy.
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return value;
    const out = {};
    seen.set(value, out);
    for (const [k, v] of Object.entries(value)) out[k] = cloneReplacingArmed(v, seen);
    return out;
  }

  function collectBlobs(value, out = [], seen = new WeakSet()) {
    if (!value || typeof value !== "object" || seen.has(value)) return out;
    seen.add(value);
    if (value instanceof Blob) {
      out.push(value);
      return out;
    }
    if (Array.isArray(value)) {
      for (const item of value) collectBlobs(item, out, seen);
      return out;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return out;
    for (const v of Object.values(value)) collectBlobs(v, out, seen);
    return out;
  }

  if (originalWorkerPostMessage) {
    Worker.prototype.postMessage = function baleE2EEWorkerPostMessage(message, transfer) {
      const worker = this;
      const unknown = enabled && Date.now() <= mediaSendPhaseUntil
        ? collectBlobs(message).filter((blob) => !encryptedFor(blob) && !encryptedMediaBlobs.has(blob))
        : [];

      if (unknown.length) {
        // A crop/resize Blob may be created only inside Bale's send handler.
        // Delay the worker message until that final Blob has an encrypted twin,
        // then substitute it before CRC/chunk/upload work starts.
        void Promise.all(unknown.map(async (blob) => {
          registerDerivedMedia(blob, "Worker.postMessage");
          const state = stageOneMedia(blob);
          const encrypted = state.encrypted || await state.promise;
          armMediaObject(blob, encrypted);
          state.armed = true;
        })).then(() => {
          const replaced = cloneReplacingArmed(message);
          if (transfer === undefined) originalWorkerPostMessage.call(worker, replaced);
          else originalWorkerPostMessage.call(worker, replaced, transfer);
        }).catch((err) => {
          console.error("[Bale E2EE] worker media handoff blocked; plaintext fallback forbidden:", err);
          toast("پردازش فایل بله قبل از رمزنگاری متوقف شد؛ فایل خام ارسال نشد.", true);
        });
        return undefined;
      }

      const replaced = cloneReplacingArmed(message);
      return transfer === undefined
        ? originalWorkerPostMessage.call(worker, replaced)
        : originalWorkerPostMessage.call(worker, replaced, transfer);
    };
  }

  async function replaySendAfterMediaReady(target) {
    if (mediaReplayInProgress) return;
    mediaReplayInProgress = true;
    mediaSendPhaseUntil = Date.now() + 2 * 60 * 1000;
    uploadGuardArmedUntil = Math.max(uploadGuardArmedUntil, mediaSendPhaseUntil);
    try {
      const prepared = await prepareActiveMedia();
      if (!prepared.length) throw new Error("no staged attachment available");
      console.log("[Bale E2EE] media armed for ciphertext size/CRC/read/upload", prepared.map(({ original, encrypted }) => ({
        originalName: "<hidden>",
        plainSize: stagedMedia.get(original)?.plainSize,
        encryptedSize: encrypted.size,
        encryptedType: encrypted.type
      })));

      const composer = findComposerForSendTarget(target);
      const caption = getText(composer);
      if (composer && caption.trim() && !isEncryptedWire(caption.trim())) {
        // sendEncrypted() performs the replay click itself after encrypting caption.
        const ok = await sendEncrypted(composer, caption, {
          sendTarget: resolveSendTarget(target) || findSendButton(),
          acceptDispatchedSend: true,
          keepCipherOnFailure: true
        });
        if (!ok) throw new Error("media caption encryption/send failed");
      } else {
        bypassNextSendClick = true;
        const send = resolveSendTarget(target) || findSendButton();
        if (!send) throw new Error("Bale send button not found after media encryption");
        send.dispatchEvent(new MouseEvent("click", {
          bubbles: true,
          cancelable: true,
          composed: true,
          view: window
        }));
      }

      // Keep armed mappings around for async upload/chunk reads, but stop treating
      // them as an active attachment for later unrelated Send clicks.
      activeMedia = [];
      toast("فایل در پس‌زمینه رمزنگاری و برای آپلود آماده شد");
    } catch (err) {
      console.error("[Bale E2EE] media send blocked; plaintext fallback forbidden:", err);
      toast("رمزنگاری فایل کامل نشد؛ برای امنیت، ارسال فایل متوقف شد.", true);
    } finally {
      mediaReplayInProgress = false;
    }
  }

  async function replaySecureDocumentSend(target) {
    if (mediaReplayInProgress) return;
    mediaReplayInProgress = true;
    mediaSendPhaseUntil = Date.now() + 2 * 60 * 1000;
    uploadGuardArmedUntil = Math.max(uploadGuardArmedUntil, mediaSendPhaseUntil);
    try {
      const send = resolveSendTarget(target) || findSendButtonNear(target) || findSendButton();
      if (!send) throw new Error("Bale secure-document send button not found");

      const composer = findCaptionComposer(send) || findComposerForSendTarget(send);
      const caption = composer ? getText(composer) : "";
      if (composer && caption.trim() && !isEncryptedWire(caption.trim())) {
        console.log("[Bale E2EE] encrypting media/document caption from dialog-local composer", {
          id: composer.id || "",
          ariaLabel: composer.getAttribute?.("aria-label") || "",
          role: composer.getAttribute?.("role") || "",
          insideDialog: Boolean(mediaDialogFor(composer))
        });
        const ok = await sendEncrypted(composer, caption, {
          sendTarget: send,
          acceptDispatchedSend: true,
          keepCipherOnFailure: true
        });
        if (!ok) throw new Error("secure-document caption encryption/send failed");
      } else {
        bypassNextSendClick = true;
        send.dispatchEvent(new MouseEvent("click", {
          bubbles: true,
          cancelable: true,
          composed: true,
          view: window
        }));
      }

      // The network guard remains armed via timestamps while async upload work
      // finishes, but this attachment should not hijack a later unrelated Send.
      activeMedia = [];
      mediaCandidates = [];
      toast(caption.trim() ? "فایل و کپشن رمزنگاری‌شده ارسال شدند" : "فایل رمزنگاری‌شده ارسال شد");
    } catch (err) {
      console.error("[Bale E2EE] secure-document send blocked; plaintext fallback forbidden:", err);
      toast("ارسال امن فایل/کپشن کامل نشد؛ برای امنیت، ارسال متوقف شد.", true);
    } finally {
      mediaReplayInProgress = false;
    }
  }

  function commandTextFromEvent(event) {
    if (!enabled || !(event.target instanceof Element)) return null;
    const target = event.target.closest(
      '[data-entity-type="bot_command"], [data-entity-type="bot-command"], .bot-command, .bot_command, a, span'
    );
    if (!target) return null;
    const text = String(target.innerText || target.textContent || "").trim();
    if (!/^\/[A-Za-z0-9_]+(?:@[A-Za-z0-9_]+)?(?:\s+[^\r\n]*)?$/.test(text)) return null;

    // For generic <a>/<span>, require either command-ish semantics or a clean
    // command-only visible token so normal Bale navigation links are untouched.
    const semantic = target.matches(
      '[data-entity-type="bot_command"], [data-entity-type="bot-command"], .bot-command, .bot_command'
    ) || /(?:bot|command|mention)/i.test(target.className || "");
    if (!semantic && !text.startsWith("/")) return null;
    return text;
  }

  function interceptCommandClick(event) {
    if (processedCommandEvents.has(event)) return false;
    const command = commandTextFromEvent(event);
    if (!command) return false;
    processedCommandEvents.add(event);

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation?.();
    const composer = findComposerFrom(document.activeElement || event.target);
    if (!composer) {
      toast("کادر پیام بله پیدا نشد؛ کامند ارسال نشد.", true);
      return true;
    }
    const existingDraft = getText(composer);
    void sendEncrypted(composer, command, { displayText: existingDraft, restoreText: existingDraft });
    return true;
  }

  async function blobHasMagic(blob) {
    if (!(blob instanceof Blob) || blob.size < FILE_MAGIC.length) return false;
    const head = new Uint8Array(await blob.slice(0, FILE_MAGIC.length).arrayBuffer());
    if (head.length !== FILE_MAGIC.length) return false;
    for (let i = 0; i < FILE_MAGIC.length; i += 1) if (head[i] !== FILE_MAGIC[i]) return false;
    return true;
  }

  function likelyFileResponse(response, input) {
    try {
      const url = typeof input === "string" ? input : input?.url || response.url || "";
      const ct = (response.headers.get("content-type") || "").toLowerCase();
      const cd = (response.headers.get("content-disposition") || "").toLowerCase();
      if (cd.includes("attachment")) return true;
      if (ct.includes("application/octet-stream")) return true;
      return /(nasim|download|\/files?\/|fileurl|file-url|cdn)/i.test(url);
    } catch (_) {
      return false;
    }
  }

  function safeFilename(name) {
    return String(name || "decrypted-file").replace(/[\r\n"\\]/g, "_");
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

  function asciiAt(bytes, offset, text) {
    if (!bytes || bytes.length < offset + text.length) return false;
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

  function getKnownOriginalFilename(encName) {
    if (!encName) return "";
    if (filenameDisplayMap.has(encName)) return filenameDisplayMap.get(encName);
    try {
      const stored = sessionStorage.getItem("bale_fn_" + encName);
      if (stored) {
        filenameDisplayMap.set(encName, stored);
        return stored;
      }
    } catch (_) {}
    return "";
  }

  function resolveProperFilename(blob, meta, fallbackName = "", headBytes = null) {
    let name = String(meta?.name || "").trim();
    const outer = String(fallbackName || "").trim();

    const knownOriginal = getKnownOriginalFilename(outer) || getKnownOriginalFilename(name);
    if (knownOriginal) {
      name = knownOriginal;
    } else if (outer && (!name || /^(file|attachment-)/i.test(name))) {
      const knownOuter = getKnownOriginalFilename(outer);
      if (knownOuter) name = knownOuter;
    }

    let declaredMime = String(meta?.type || blob?.type || "").toLowerCase();
    if (headBytes instanceof Uint8Array) {
      const inferred = inferMimeFromHead(headBytes, name);
      if (inferred) declaredMime = inferred;
    }
    const ext = EXTENSION_MAP[declaredMime] || "";

    const isGenericOrBin = !name ||
      /^(file|decrypted_file|photo|video|audio|document)(?:\.(bin|enc|dat|octet-stream))?$/i.test(name) ||
      /^attachment-[0-9a-f]{4,64}\.bin$/i.test(name) ||
      GENERIC_ATTACHMENT_RE.test(name);

    if (isGenericOrBin) {
      const stem = declaredMime.startsWith("image/") ? "photo"
        : declaredMime.startsWith("video/") ? "video"
        : declaredMime.startsWith("audio/") ? "audio"
        : declaredMime === "application/pdf" ? "document"
        : declaredMime.includes("android") ? "app"
        : "file";
      name = `${stem}${ext || (declaredMime.startsWith("image/") ? ".jpg" : "")}`;
    } else if (/\.(bin|enc|dat)$/i.test(name)) {
      if (ext && ext !== ".bin") {
        name = name.replace(/\.(bin|enc|dat)$/i, ext);
      }
    } else if (!name.includes(".") && ext) {
      name = `${name}${ext}`;
    }
    return safeFilename(name);
  }

  function contentDispositionFilename(headers) {
    try {
      const cd = headers?.get?.("content-disposition") || "";
      const star = cd.match(/filename\*=UTF-8''([^;]+)/i);
      if (star) return decodeURIComponent(star[1].replace(/^"|"$/g, ""));
      const plain = cd.match(/filename\s*=\s*"([^"]+)"/i) || cd.match(/filename\s*=\s*([^;]+)/i);
      return plain ? plain[1].trim().replace(/^"|"$/g, "") : "";
    } catch (_) {
      return "";
    }
  }

  function rememberDecryptedFilename(outerName, originalName) {
    if (!outerName || !originalName || outerName === originalName) return;
    filenameDisplayMap.set(outerName, originalName);
    try { sessionStorage.setItem("bale_fn_" + outerName, originalName); } catch (_) {}
    setTimeout(() => filenameDisplayMap.delete(outerName), 60 * 60 * 1000);
    processFilenameRoot(document.body || document.documentElement);
  }

  function processFilenameTextNode(node) {
    if (!(node instanceof Text) || !node.nodeValue) return;
    let next = node.nodeValue;
    for (const [outer, original] of filenameDisplayMap) {
      if (next.includes(outer)) {
        next = next.split(outer).join(original);
        if (node.parentElement) {
          node.parentElement.setAttribute("data-bale-e2ee-outer-name", outer);
          node.parentElement.setAttribute("data-bale-e2ee-original-name", original);
          const card = node.parentElement.closest('a.h7PFux, a[class*="h7PFux"]');
          if (card) {
            card.setAttribute("data-bale-e2ee-outer-name", outer);
            card.setAttribute("data-bale-e2ee-original-name", original);
          }
        }
      }
    }
    if (next !== node.nodeValue) node.nodeValue = next;
  }

  function processFilenameRoot(root) {
    if (!root) return;
    if (root instanceof Text) {
      processFilenameTextNode(root);
      return;
    }
    if (!(root instanceof Node)) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) processFilenameTextNode(node);
  }

  function showDecryptedMediaPreview(blob, meta) {
    const type = String(meta?.type || blob.type || "");
    if (!/^(image|video|audio)\//i.test(type)) return false;
    ensureE2EEUiStyles();
    document.querySelector('[data-bale-e2ee-preview="true"]')?.remove();
    const url = originalCreateObjectURL(blob);
    const overlay = document.createElement("div");
    overlay.className = "bee11-viewer";
    overlay.setAttribute("data-bale-e2ee-preview", "true");
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");

    const card = document.createElement("div");
    card.className = "bee11-viewer-card";
    let media;
    if (type.startsWith("image/")) {
      media = document.createElement("img");
      media.src = url;
      media.alt = meta?.name || "decrypted image";
    } else if (type.startsWith("video/")) {
      media = document.createElement("video");
      media.src = url;
      media.controls = true;
      media.autoplay = false;
      media.playsInline = true;
    } else {
      media = document.createElement("audio");
      media.src = url;
      media.controls = true;
      media.autoplay = false;
    }
    media.className = "bee11-viewer-media";

    const bar = document.createElement("div");
    bar.className = "bee11-viewer-bar";
    bar.setAttribute("dir", "auto");
    const secure = document.createElement("span");
    secure.className = "bee11-secure-badge";
    secure.title = "End-to-end encrypted";
    secure.appendChild(makeUiIcon("secure", 14));
    const name = document.createElement("span");
    name.className = "bee11-viewer-name";
    name.setAttribute("dir", "auto");
    name.textContent = meta?.name || "decrypted-file";
    const download = document.createElement("button");
    download.className = "bee11-download-pill";
    download.type = "button";
    download.title = "دانلود نسخه اصلی";
    download.setAttribute("aria-label", "Download decrypted file");
    const dlIcon = makeUiIcon("download", 16);
    const dlText = document.createElement("span");
    dlText.textContent = `دانلود (${formatFileSize(blob.size)})`;
    download.append(dlIcon, dlText);
    const close = document.createElement("button");
    close.className = "bee11-icon-button";
    close.type = "button";
    close.title = "Close";
    close.setAttribute("aria-label", "Close");
    close.appendChild(makeUiIcon("close", 18));

    download.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      saveDecryptedBlob(blob, meta?.name || "decrypted-file");
    });
    const topClose = document.createElement("button");
    topClose.className = "bee11-viewer-top-close";
    topClose.type = "button";
    topClose.title = "بستن";
    topClose.setAttribute("aria-label", "Close");
    topClose.appendChild(makeUiIcon("close", 20));

    const dispose = (event) => {
      event?.preventDefault?.();
      event?.stopPropagation?.();
      overlay.remove();
      setTimeout(() => { try { URL.revokeObjectURL(url); } catch (_) {} }, 1000);
    };

    topClose.addEventListener("click", dispose);
    topClose.addEventListener("touchend", dispose);
    close.addEventListener("click", dispose);
    close.addEventListener("touchend", dispose);
    overlay.addEventListener("click", (event) => { if (event.target === overlay) dispose(event); });
    overlay.addEventListener("touchend", (event) => { if (event.target === overlay) dispose(event); });
    document.addEventListener("keydown", function esc(event) {
      if (event.key !== "Escape" || !overlay.isConnected) return;
      document.removeEventListener("keydown", esc, true);
      dispose(event);
    }, true);

    bar.append(secure, name, download, close);
    card.append(media, bar);
    overlay.append(topClose, card);
    document.documentElement.append(overlay);
    return true;
  }

  async function maybeDecryptResponse(response, input) {
    if (!enabled || !response?.ok || !likelyFileResponse(response, input)) return response;
    try {
      const blob = await response.clone().blob();
      if (!(await blobHasMagic(blob))) return response;
      const outerName = contentDispositionFilename(response.headers) || pendingAttachmentClick?.outerName || "";
      const { blob: plainBlob, meta } = await requestDecryptBlob(blob);
      let head = null;
      try { head = new Uint8Array(await plainBlob.slice(0, 64).arrayBuffer()); } catch (_) {}
      const properName = resolveProperFilename(plainBlob, meta, outerName, head);
      if (outerName && properName) rememberDecryptedFilename(outerName, properName);
      
      if (properName) decryptedBlobCache.set(properName, { blob: plainBlob, meta, outerName: properName });
      if (meta?.name) decryptedBlobCache.set(meta.name, { blob: plainBlob, meta, outerName: properName });
      if (outerName) decryptedBlobCache.set(outerName, { blob: plainBlob, meta, outerName: properName });
      if (pendingAttachmentClick?.outerName) {
        decryptedBlobCache.set(pendingAttachmentClick.outerName, { blob: plainBlob, meta, outerName: properName });
      }

      renderPendingAttachment(plainBlob, meta, outerName);
      console.log("[Bale E2EE] transparently decrypted fetched attachment", meta);

      // Return original response so Bale's download manager receives expected ciphertext size
      // without throwing "File size doesn't match!"
      return response;
    } catch (err) {
      console.warn("[Bale E2EE] attachment response looked encrypted but decryption failed", err);
      return response;
    }
  }

  function sanitizedUploadHeaders(headersInit, body) {
    const headers = new Headers(headersInit || undefined);
    // CRITICAL: Preserve multipart/form-data for chunk / final confirmation requests to Nasim server
    const origType = headers.get("content-type") || "";
    if (body instanceof FormData) {
      // Browser must generate the multipart boundary itself.
      headers.delete("content-type");
    } else if (headers.has("chunk") || headers.has("no") || /^multipart\/form-data\b/i.test(origType)) {
      // Nasim upload API requires multipart/form-data on chunks and final confirmation!
      headers.set("content-type", "multipart/form-data");
    } else if (
      body instanceof Blob || body instanceof ArrayBuffer || ArrayBuffer.isView(body) ||
      (typeof ReadableStream !== "undefined" && body instanceof ReadableStream)
    ) {
      headers.set("content-type", "application/octet-stream");
    }
    if (headers.has("content-disposition")) {
      headers.set("content-disposition", `attachment; filename="${currentOuterFilename()}"`);
    }
    return headers;
  }

  window.fetch = async function baleE2EEFetch(input, init) {
    const url = typeof input === "string" || input instanceof URL ? String(input) : input?.url || "";
    let nextInput = input;
    let nextInit = init;

    try {
      if (enabled && init && Object.prototype.hasOwnProperty.call(init, "body")) {
        // Fast path for already-armed files, then the v8 upload-boundary guard
        // for Bale-created crop/resize Blobs that were not known at selection.
        let replaced = replaceArmedBody(init.body);
        replaced = await prepareUploadBody(replaced, url, "fetch");
        if (replaced !== init.body || (uploadGuardActive() && looksLikeUploadUrl(url))) {
          nextInit = { ...init, body: replaced, headers: sanitizedUploadHeaders(init.headers, replaced) };
          if (replaced !== init.body) console.log("[Bale E2EE] fetch upload body redirected to ciphertext", url);
          console.log("[Bale E2EE] fetch upload headers sanitized", url);
        }
      } else if (enabled && input instanceof Request && uploadGuardActive() && looksLikeUploadUrl(url) && !["GET", "HEAD"].includes(input.method.toUpperCase())) {
        // Covers fetch(new Request(...)) where init.body is not visible to us.
        const cloned = input.clone();
        const bodyBlob = await cloned.blob();
        if (bodyBlob.size) {
          const encrypted = await ensureEncryptedUploadBlob(bodyBlob, "fetch:Request");
          const headers = new Headers(input.headers);
          headers.set("content-type", encrypted.type || "application/octet-stream");
          headers.delete("content-length");
          nextInput = new Request(input, { body: encrypted, headers });
          console.log("[Bale E2EE] fetch Request body encrypted at upload boundary", url);
        }
      }
    } catch (err) {
      console.error("[Bale E2EE] fetch media upload blocked; plaintext fallback forbidden:", err);
      toast("آپلود فایل خام شناسایی شد ولی رمزنگاری امن آن ممکن نشد؛ ارسال متوقف شد.", true);
      throw err;
    }

    const response = await originalFetch(nextInput, nextInit);
    return maybeDecryptResponse(response, nextInput);
  };

  XMLHttpRequest.prototype.open = function baleE2EEXhrOpen(method, url, ...rest) {
    xhrRequestMeta.set(this, { method: String(method || "GET").toUpperCase(), url: String(url || ""), headers: new Map() });
    return originalXhrOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.setRequestHeader = function baleE2EEXhrSetRequestHeader(name, value) {
    const meta = xhrRequestMeta.get(this) || { method: "", url: "", headers: new Map() };
    if (!meta.headers) meta.headers = new Map();
    const lower = String(name || "").toLowerCase();
    let safeValue = String(value ?? "");
    if (enabled && Date.now() <= secureDocumentModeUntil && looksLikeUploadUrl(meta.url)) {
      if (lower === "content-type" && !/^multipart\/form-data\b/i.test(safeValue)) {
        safeValue = "multipart/form-data";
      }
      if (lower === "content-disposition") safeValue = `attachment; filename="${currentOuterFilename()}"`;
    }
    meta.headers.set(lower, safeValue);
    xhrRequestMeta.set(this, meta);
    return originalXhrSetRequestHeader.call(this, name, safeValue);
  };

  XMLHttpRequest.prototype.send = function baleE2EEXhrSend(body) {
    const xhr = this;
    const meta = xhrRequestMeta.get(xhr) || { method: "", url: "" };
    const syncReplaced = enabled ? replaceArmedBody(body) : body;

    if (enabled && pendingAttachmentClick && ["GET", "HEAD", ""].includes(String(meta.method || "").toUpperCase())) {
      xhr.addEventListener("load", () => {
        try {
          const value = xhr.response;
          let blob = null;
          if (value instanceof Blob) blob = value;
          else if (value instanceof ArrayBuffer) blob = new Blob([value], { type: xhr.getResponseHeader?.("content-type") || "application/octet-stream" });
          if (blob) void inspectDownloadedBlobForPendingPreview(blob, pendingAttachmentClick?.outerName || "");
        } catch (_) {}
      }, { once: true });
    }

    if (!uploadGuardActive() || !looksLikeUploadUrl(meta.url) || body == null) {
      if (syncReplaced !== body) console.log("[Bale E2EE] XHR upload body redirected to ciphertext", meta.url);
      return originalXhrSend.call(xhr, syncReplaced);
    }

    // XHR.send itself is synchronous, but the network request does not need to
    // start synchronously. Delay the native send until AES-GCM completes.
    void prepareUploadBody(syncReplaced, meta.url, "XHR")
      .then((prepared) => {
        if (prepared !== body) console.log("[Bale E2EE] XHR final upload body encrypted", meta.url);
        originalXhrSend.call(xhr, prepared);
      })
      .catch((err) => {
        console.error("[Bale E2EE] XHR media upload blocked; plaintext fallback forbidden:", err);
        toast("آپلود فایل خام شناسایی شد ولی رمزنگاری امن آن ممکن نشد؛ ارسال متوقف شد.", true);
        try { xhr.abort(); } catch (_) {}
      });
    return undefined;
  };

  function attachmentOuterNameFromAnchor(anchor) {
    if (!(anchor instanceof Element)) return "";
    const samples = [
      anchor.getAttribute("download") || "",
      anchor.getAttribute("title") || "",
      anchor.getAttribute("aria-label") || "",
      String(anchor.textContent || ""),
      String(anchor.parentElement?.textContent || ""),
      (() => {
        try { return decodeURIComponent(String(anchor.getAttribute("href") || anchor.href || "")); }
        catch (_) { return String(anchor.getAttribute("href") || anchor.href || ""); }
      })()
    ];
    for (const sample of samples) {
      const match = String(sample).match(GENERIC_ATTACHMENT_RE);
      if (match) return match[0];
    }
    // Our own outgoing card may already have had its visible generic filename
    // replaced with the decrypted/original display name. Keep the outer name
    // recoverable for auto-preview from the temporary mapping.
    for (const [outer, original] of filenameDisplayMap) {
      if (samples.some((sample) => String(sample).includes(outer) || String(sample).includes(original))) return outer;
    }
    return "";
  }

  function looksLikeEncryptedAttachmentAnchor(anchor) {
    if (!(anchor instanceof HTMLAnchorElement) || !anchor.href) return false;
    return Boolean(attachmentOuterNameFromAnchor(anchor));
  }

  function findCardByOuterName(outerName) {
    if (!outerName) return null;
    const originalName = filenameDisplayMap.get(outerName) || "";
    const cards = [...document.querySelectorAll('a.h7PFux, a[class*="h7PFux"]')];
    for (const card of cards) {
      if (isReplyOrQuoteElement(card)) continue;
      if (card.matches?.('.message-item, .message-block, [class*="message-block"], [class*="message-item"]')) continue;

      if (card.getAttribute("data-bale-e2ee-outer-name") === outerName) {
        return card;
      }
      if (card.textContent?.includes(outerName)) {
        return card;
      }
      if (originalName && card.textContent?.includes(originalName)) {
        return card;
      }
    }
    return null;
  }

  function findAttachmentSurface(anchor, outerName) {
    if (!(anchor instanceof Element)) return null;
    // CRITICAL: Reject reply / quote containers immediately!
    if (isReplyOrQuoteElement(anchor)) {
      return null;
    }
    // Surface MUST be the attachment link/card itself (a.h7PFux), NEVER the parent bubble (div.k7VAKr)
    // which contains the caption and timestamp!
    const specificCard = anchor.closest?.('a.h7PFux, a[class*="h7PFux"]');
    if (specificCard && !isReplyOrQuoteElement(specificCard)) return specificCard;

    // If anchor is inside a card container, look for an a.h7PFux inside it:
    const k7 = anchor.closest?.('div.k7VAKr');
    if (k7) {
      const innerCard = k7.querySelector('a.h7PFux, a[class*="h7PFux"]');
      if (innerCard && !isReplyOrQuoteElement(innerCard)) return innerCard;
    }

    const directAnchor = anchor.closest?.('a[href], a[download]');
    if (directAnchor && !directAnchor.matches?.('.message-item, .message-block, div.k7VAKr') && !isReplyOrQuoteElement(directAnchor)) {
      return directAnchor;
    }

    return null;
  }

  function cleanupDetachedInlinePreviewUrls() {
    for (const [node, url] of inlinePreviewUrls) {
      if (node.isConnected) continue;
      try { URL.revokeObjectURL(url); } catch (_) {}
      inlinePreviewUrls.delete(node);
    }
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

  function renderInlineDecryptedMediaAtSurface(surface, plainBlob, meta, outerName) {
    if (!(surface instanceof Element) || !surface.isConnected) return false;
    // CRITICAL: If surface is inside a reply or quote, NEVER render there!
    if (isReplyOrQuoteElement(surface)) {
      console.warn("[Bale E2EE] Prevented renderInlineDecryptedMediaAtSurface inside reply/quote container:", surface);
      return false;
    }
    // Surface MUST be the specific attachment card (a.h7PFux)
    if (!surface.matches?.('a.h7PFux, a[class*="h7PFux"]')) {
      const inner = surface.querySelector?.('a.h7PFux, a[class*="h7PFux"]');
      if (inner && !isReplyOrQuoteElement(inner)) {
        surface = inner;
      } else {
        const realCard = findCardByOuterName(outerName);
        if (realCard && realCard !== surface && !isReplyOrQuoteElement(realCard)) {
          surface = realCard;
        } else {
          console.warn("[Bale E2EE] Refusing to render media at non-attachment surface:", surface);
          return false;
        }
      }
    }
    ensureE2EEUiStyles();

    // DEDUPLICATION: If this message bubble already has a decrypted card, NEVER render a second one!
    const existingInBubble = surface.parentElement?.querySelector?.('.bee11-secure-card') ||
                             surface.closest?.('.message-item')?.querySelector?.('.bee11-secure-card');
    if (existingInBubble) {
      attachSecureIndicatorToTimestamp(existingInBubble);
      return true;
    }

    const type = String(meta?.type || plainBlob.type || "application/octet-stream").toLowerCase();
    const kind = type.startsWith("image/") ? "image"
      : type.startsWith("video/") ? "video"
      : type.startsWith("audio/") ? "audio"
      : "file";

    const token = outerName || `encrypted-${kind}-${meta?.name || plainBlob.size}`;
    const previous = surface.previousElementSibling;
    if (previous?.getAttribute?.("data-bale-e2ee-inline-for") === token) return true;

    const wrapper = document.createElement("div");
    wrapper.className = "bee11-secure-card";
    wrapper.setAttribute("data-bale-e2ee-inline-media", "true");
    wrapper.setAttribute("data-bale-e2ee-inline-for", token);
    wrapper.setAttribute("dir", "auto");

    let url = "";
    let media = null;
    if (kind !== "file") {
      url = originalCreateObjectURL(plainBlob);
      if (kind === "image") {
        media = document.createElement("img");
        media.loading = "lazy";
        media.decoding = "async";
        media.alt = meta?.name || "decrypted image";
        media.className = "bee11-secure-media bee11-secure-image";
      } else if (kind === "video") {
        media = document.createElement("video");
        media.controls = true;
        media.preload = "metadata";
        media.playsInline = true;
        media.className = "bee11-secure-media";
      } else {
        media = document.createElement("audio");
        media.controls = true;
        media.preload = "metadata";
        media.className = "bee11-secure-media bee11-secure-audio";
      }
      media.src = url;
      wrapper.appendChild(media);
    }

    const footer = document.createElement("div");
    footer.className = "bee11-secure-footer";
    footer.setAttribute("dir", "rtl");

    const properName = resolveProperFilename(plainBlob, meta, outerName);
    if (outerName && properName) {
      rememberDecryptedFilename(outerName, properName);
    }

    let iconName = kind === "file" ? "file" : kind;
    let iconCls = "";
    const lowerName = properName.toLowerCase();
    if (lowerName.endsWith(".apk")) {
      iconName = "apk";
      iconCls = "bee11-icon-apk";
    } else if (lowerName.endsWith(".pdf")) {
      iconName = "file";
      iconCls = "bee11-icon-pdf";
    } else if (lowerName.endsWith(".zip") || lowerName.endsWith(".rar") || lowerName.endsWith(".7z") || lowerName.endsWith(".tar") || lowerName.endsWith(".gz")) {
      iconName = "file";
      iconCls = "bee11-icon-zip";
    } else if (kind !== "file") {
      iconCls = "bee11-icon-media";
    }

    const fileIcon = document.createElement("span");
    fileIcon.className = `bee11-secure-file-icon ${iconCls}`.trim();
    fileIcon.setAttribute("aria-hidden", "true");
    fileIcon.appendChild(makeUiIcon(iconName, 20));

    const metaBox = document.createElement("div");
    metaBox.className = "bee11-secure-meta";
    metaBox.title = kind === "file" ? "Open / download" : "Download";
    metaBox.style.cursor = "pointer";
    const nameEl = document.createElement("div");
    nameEl.className = "bee11-secure-name";
    nameEl.setAttribute("dir", "auto");
    nameEl.textContent = properName;
    const sub = document.createElement("div");
    sub.className = "bee11-secure-sub";
    sub.setAttribute("dir", "rtl");

    let typeFarsi = "فایل";
    if (kind === "image") typeFarsi = "تصویر";
    else if (kind === "video") typeFarsi = "ویدیو";
    else if (kind === "audio") typeFarsi = "صوت";
    else if (lowerName.endsWith(".apk")) typeFarsi = "برنامه APK";
    else if (lowerName.endsWith(".pdf")) typeFarsi = "سند PDF";
    else if (lowerName.endsWith(".zip") || lowerName.endsWith(".rar") || lowerName.endsWith(".7z")) typeFarsi = "فایل فشرده";
    sub.textContent = `${formatFileSize(plainBlob.size)} · ${typeFarsi}`;
    metaBox.append(nameEl, sub);

    const secure = document.createElement("span");
    secure.className = "bee11-secure-badge";
    secure.title = "End-to-end encrypted";
    secure.setAttribute("aria-label", "End-to-end encrypted");
    secure.appendChild(makeUiIcon("secure", 14));

    const download = document.createElement("button");
    download.type = "button";
    download.className = "bee11-download-btn";
    download.title = "دانلود نسخه اصلی";
    download.setAttribute("aria-label", "Download");
    download.appendChild(makeUiIcon("download", 16));

    const doDownload = (event) => {
      event?.preventDefault?.();
      event?.stopPropagation?.();
      saveDecryptedBlob(plainBlob, properName);
    };
    download.addEventListener("click", doDownload);
    metaBox.addEventListener("click", doDownload);

    // For images and videos, omit redundant thumbnail file icon to maximize clean space!
    if (kind === "file" || kind === "audio") {
      footer.append(fileIcon);
    }
    footer.append(metaBox, download);
    wrapper.appendChild(footer);

    const oldDisplay = surface.style.getPropertyValue("display");
    const oldDisplayPriority = surface.style.getPropertyPriority("display");
    const restoreSurface = () => {
      if (!oldDisplay && !oldDisplayPriority) surface.style.removeProperty("display");
      else surface.style.setProperty("display", oldDisplay, oldDisplayPriority);
    };

    if (media) {
      media.addEventListener("error", () => {
        restoreSurface();
        wrapper.remove();
        try { URL.revokeObjectURL(url); } catch (_) {}
        inlinePreviewUrls.delete(wrapper);
      }, { once: true });
      if (kind === "image") {
        media.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          showDecryptedMediaPreview(plainBlob, meta);
        });
      }
    } else {
      wrapper.style.cursor = "default";
    }

    surface.insertAdjacentElement("beforebegin", wrapper);
    surface.style.setProperty("display", "none", "important");
    attachSecureIndicatorToTimestamp(wrapper);

    // SAFETY: Ensure that any sibling caption or text in the message bubble (div.k7VAKr)
    // is 100% visible and NEVER hidden!
    const parentBubble = surface.parentElement;
    if (parentBubble) {
      if (parentBubble.style.display === "none") {
        parentBubble.style.removeProperty("display");
      }
      const captions = parentBubble.querySelectorAll('.KTwPFW, [class*="DZJJ42"], [class*="caption" i]');
      for (const cap of captions) {
        cap.style.removeProperty("display");
      }
    }

    if (url) inlinePreviewUrls.set(wrapper, url);
    if (outerName && meta?.name) rememberDecryptedFilename(outerName, meta.name);
    console.log(`[Bale E2EE] inline decrypted ${kind} card rendered`, {
      name: meta?.name || "<unknown>",
      type,
      size: plainBlob.size
    });
    return true;
  }

  function renderInlineDecryptedMedia(anchor, plainBlob, meta, outerName) {
    if (!(anchor instanceof Element) || !anchor.isConnected) return false;
    const surface = findAttachmentSurface(anchor, outerName) || anchor;
    return renderInlineDecryptedMediaAtSurface(surface, plainBlob, meta, outerName);
  }

  function attachmentInfoFromTarget(target) {
    if (!(target instanceof Element)) return null;
    // CRITICAL: Reject reply / quote containers immediately!
    if (isReplyOrQuoteElement(target)) {
      return null;
    }

    // 1. Locate the attachment anchor or card (MUST be a.h7PFux, never a bare button or reply)
    const card = target.closest?.('a.h7PFux, a[class*="h7PFux"]') ||
                 target.closest?.('div.k7VAKr')?.querySelector('a.h7PFux, a[class*="h7PFux"]');
    if (!card || isReplyOrQuoteElement(card)) {
      return null;
    }

    const surface = card;

    // 2. Check explicit data attribute
    const explicitOuter = surface.getAttribute("data-bale-e2ee-outer-name") ||
                          card.getAttribute("data-bale-e2ee-outer-name") ||
                          target.getAttribute("data-bale-e2ee-outer-name");
    if (explicitOuter) {
      return { surface, outerName: explicitOuter };
    }

    // 3. Check for generic attachment pattern (attachment-...bin or *.enc)
    const cardText = String(card.textContent || "") + " " + String(card.getAttribute("download") || "") + " " + String(card.getAttribute("href") || "");
    const match = cardText.match(GENERIC_ATTACHMENT_RE);
    if (match) {
      return { surface, outerName: match[0] };
    }

    // 4. Check filenameDisplayMap (when outerName was replaced with originalName e.g. 442613.jpg)
    for (const [outer, original] of filenameDisplayMap) {
      if (cardText.includes(original) || cardText.includes(outer)) {
        surface.setAttribute("data-bale-e2ee-outer-name", outer);
        return { surface, outerName: outer };
      }
    }

    // 5. Check decryptedBlobCache
    for (const [cachedOuter, cachedEntry] of decryptedBlobCache) {
      const origName = cachedEntry?.meta?.name;
      if (cardText.includes(cachedOuter) || (origName && cardText.includes(origName))) {
        surface.setAttribute("data-bale-e2ee-outer-name", cachedOuter);
        return { surface, outerName: cachedOuter };
      }
    }

    const text = String(target.textContent || "");
    const textMatch = text.match(GENERIC_ATTACHMENT_RE);
    if (textMatch) {
      return { surface, outerName: textMatch[0] };
    }
    return null;
  }

  function renderPendingAttachment(plainBlob, meta, outerName = "") {
    const pending = pendingAttachmentClick;
    const actualOuter = outerName || pending?.outerName || "";
    let surface = pending?.surface;
    if (!surface?.isConnected || isReplyOrQuoteElement(surface)) {
      surface = findCardByOuterName(actualOuter);
    }
    if (!surface?.isConnected) {
      const active = document.querySelector('[data-bale-e2ee-decrypting="true"]');
      if (active && !isReplyOrQuoteElement(active)) surface = active;
    }
    if (!surface?.isConnected && meta?.name) {
      surface = findCardByOuterName(meta.name);
    }
    if (!surface?.isConnected || isReplyOrQuoteElement(surface)) return false;
    clearCardDecryptingState(surface);
    const rendered = renderInlineDecryptedMediaAtSurface(surface, plainBlob, meta, actualOuter || meta?.name || "");
    if (rendered) pendingAttachmentClick = null;
    return rendered;
  }

  async function inspectDownloadedBlobForPendingPreview(blob, outerName = "") {
    try {
      if (!(blob instanceof Blob) || !(await blobHasMagic(blob))) return false;
      const { blob: plainBlob, meta } = await requestDecryptBlob(blob);
      if (outerName && meta?.name) rememberDecryptedFilename(outerName, meta.name);
      return renderPendingAttachment(plainBlob, meta, outerName);
    } catch (err) {
      console.debug("[Bale E2EE] pending attachment decrypt failed", err);
      return false;
    }
  }

  async function loadAndDecryptAttachmentForPreview(href) {
    let existing = autoPreviewByHref.get(href);
    if (existing) return existing;
    const task = (async () => {
      const response = await originalFetch(
        href,
        isNasimProxyDownloadUrl(href)
          ? { mode: "cors", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" }
          : { credentials: "include" }
      );
      if (!response.ok) throw new Error(`preview download HTTP ${response.status}`);
      const encryptedBlob = await response.blob();
      if (!(await blobHasMagic(encryptedBlob))) return null;
      return requestDecryptBlob(encryptedBlob);
    })().catch((err) => {
      autoPreviewByHref.delete(href);
      throw err;
    });
    autoPreviewByHref.set(href, task);
    setTimeout(() => autoPreviewByHref.delete(href), 5 * 60 * 1000);
    return task;
  }

  async function autoDecryptInlineAttachment(anchor) {
    if (!enabled || !(anchor instanceof HTMLAnchorElement) || autoPreviewAnchors.has(anchor)) return;
    const outerName = attachmentOuterNameFromAnchor(anchor);
    if (!outerName) return;
    autoPreviewAnchors.add(anchor);
    anchor.setAttribute("data-bale-e2ee-auto-preview", "pending");
    try {
      const result = await loadAndDecryptAttachmentForPreview(anchor.href);
      if (!result) {
        anchor.setAttribute("data-bale-e2ee-auto-preview", "not-e2ee");
        return;
      }
      const { blob: plainBlob, meta } = result;
      if (outerName && meta?.name) rememberDecryptedFilename(outerName, meta.name);
      const rendered = renderInlineDecryptedMedia(anchor, plainBlob, meta, outerName);
      anchor.setAttribute("data-bale-e2ee-auto-preview", rendered ? "ready" : "unsupported");
    } catch (err) {
      anchor.setAttribute("data-bale-e2ee-auto-preview", "failed");
      autoPreviewAnchors.delete(anchor);
      console.debug("[Bale E2EE] inline encrypted attachment preview unavailable", err);
      setTimeout(() => { if (anchor.isConnected) scheduleAutoPreviewScan(0); }, 2500);
    }
  }

  function downloadUrlFromSurface(surface) {
    if (!(surface instanceof Element)) return "";
    const nodes = [surface, ...surface.querySelectorAll?.('a[href], [data-href], [data-url], [data-download-url]') || []];
    for (const el of nodes) {
      for (const attr of ["href", "data-href", "data-url", "data-download-url"]) {
        const raw = el.getAttribute?.(attr);
        if (!raw) continue;
        try {
          const url = new URL(raw, location.href);
          if (["http:", "https:", "blob:"].includes(url.protocol)) return url.href;
        } catch (_) {}
      }
    }
    return "";
  }

  function extractBlobOrUrlFromCard(el) {
    if (!(el instanceof Element)) return null;
    let fiber = null;
    for (const k in el) {
      if (k.startsWith("__reactFiber")) { fiber = el[k]; break; }
    }
    if (!fiber) {
      const child = el.querySelector?.('.vMR6Iw, svg, span, p');
      if (child) {
        for (const k in child) {
          if (k.startsWith("__reactFiber")) { fiber = child[k]; break; }
        }
      }
    }
    if (!fiber) return null;

    let cur = fiber;
    while (cur) {
      let h = cur.memoizedState;
      while (h) {
        const s = h.memoizedState;
        if (s instanceof Blob || s instanceof File) {
          return { blob: s };
        }
        if (typeof s === "string" && s.startsWith("blob:")) {
          return { url: s };
        }
        if (Array.isArray(s)) {
          for (const item of s) {
            if (item instanceof Blob || item instanceof File) return { blob: item };
            if (typeof item === "string" && item.startsWith("blob:")) return { url: item };
          }
        }
        if (s && typeof s === "object") {
          if (s.file instanceof Blob || s.file instanceof File) return { blob: s.file };
          if (typeof s.url === "string" && s.url.startsWith("blob:")) return { url: s.url };
        }
        h = h.next;
      }
      cur = cur.return;
    }
    return null;
  }

  async function autoDecryptLoadedBlob(surface, blob, outerName) {
    if (!(surface instanceof Element) || !surface.isConnected || !blob) return;
    const state = surface.getAttribute("data-bale-e2ee-auto-preview");
    if (state === "pending" || state === "ready") return;
    surface.setAttribute("data-bale-e2ee-auto-preview", "pending");

    try {
      let plainBlob = blob;
      let meta = { name: outerName || "decrypted-file" };

      if (await blobHasMagic(blob)) {
        const dec = await requestDecryptBlob(blob);
        plainBlob = dec.blob;
        meta = dec.meta || meta;
      } else {
        const head = new Uint8Array(await blob.slice(0, 16).arrayBuffer());
        const isJpg = head[0] === 0xff && head[1] === 0xd8;
        const isPng = head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47;
        const isGif = head[0] === 0x47 && head[1] === 0x49 && head[2] === 0x46;
        const isWebp = head[8] === 0x57 && head[9] === 0x45 && head[10] === 0x42 && head[11] === 0x50;
        const isMp4 = (head[4] === 0x66 && head[5] === 0x74 && head[6] === 0x79 && head[7] === 0x70) ||
                      (head[0] === 0x00 && head[1] === 0x00 && head[2] === 0x00);
        const isAudio = (head[0] === 0x49 && head[1] === 0x44 && head[2] === 0x33) ||
                        (head[0] === 0xff && (head[1] & 0xe0) === 0xe0) ||
                        (head[0] === 0x4f && head[1] === 0x67 && head[2] === 0x67 && head[3] === 0x53);
        const isMedia = isJpg || isPng || isGif || isWebp || isMp4 || isAudio;
        if (!isMedia) {
          surface.setAttribute("data-bale-e2ee-auto-preview", "not-media");
          return;
        }
      }

      if (outerName && meta?.name) rememberDecryptedFilename(outerName, meta.name);
      decryptedBlobCache.set(outerName, { blob: plainBlob, meta, outerName });
      const rendered = renderInlineDecryptedMediaAtSurface(surface, plainBlob, meta, outerName);
      surface.setAttribute("data-bale-e2ee-auto-preview", rendered ? "ready" : "document-ready");
      console.log("[Bale E2EE] auto-decrypted loaded media from fiber:", outerName);
    } catch (err) {
      surface.setAttribute("data-bale-e2ee-auto-preview", "failed");
      console.debug("[Bale E2EE] auto-decrypt loaded blob failed:", err);
    }
  }

  async function autoDecryptInlineSurface(surface, outerName, href) {
    if (!(surface instanceof Element) || !surface.isConnected || !href) return;
    if (surface.getAttribute("data-bale-e2ee-auto-preview") === "pending" || surface.getAttribute("data-bale-e2ee-auto-preview") === "ready") return;
    surface.setAttribute("data-bale-e2ee-auto-preview", "pending");
    try {
      const result = await loadAndDecryptAttachmentForPreview(href);
      if (!result) { surface.setAttribute("data-bale-e2ee-auto-preview", "not-e2ee"); return; }
      const { blob: plainBlob, meta } = result;
      if (outerName && meta?.name) rememberDecryptedFilename(outerName, meta.name);
      const rendered = renderInlineDecryptedMediaAtSurface(surface, plainBlob, meta, outerName);
      surface.setAttribute("data-bale-e2ee-auto-preview", rendered ? "ready" : "document-ready");
    } catch (err) {
      surface.setAttribute("data-bale-e2ee-auto-preview", "failed");
      console.debug("[Bale E2EE] generic attachment surface auto-preview unavailable", err);
    }
  }

  function findClickableAttachmentSurface(surface) {
    if (!(surface instanceof Element)) return null;
    let current = surface;
    for (let depth = 0; depth < 6 && current; depth += 1, current = current.parentElement) {
      if (current.matches?.('a, button, [role="button"], [tabindex="0"]')) return current;
      const cls = typeof current.className === "string" ? current.className : "";
      if (/(attachment|document|file|download)/i.test(cls)) return current;
    }
    return surface;
  }

  function ensureManualDecryptButton(surface, outerName) {
    if (!(surface instanceof Element) || !surface.isConnected || !enabled) return;
    const clickable = findClickableAttachmentSurface(surface);
    const host = clickable instanceof Element ? clickable : (surface.parentElement || surface);
    if (!(host instanceof Element)) return;
    markEncryptedAttachmentSurface(host);

    // v12 intentionally avoids the old visible "tap this file" helper text.
    // When a direct URL exists, provide only a compact icon button. When Bale
    // exposes the URL solely after its own trusted click, the lock badge is the
    // only UI addition and the normal Bale card remains the interaction target.
    const href = downloadUrlFromSurface(surface) || downloadUrlFromSurface(host);
    if (!href || host.querySelector?.('[data-bale-e2ee-manual-open="true"]')) return;

    ensureE2EEUiStyles();
    const button = document.createElement("button");
    button.type = "button";
    button.className = "bee11-icon-button";
    button.setAttribute("data-bale-e2ee-manual-open", "true");
    button.setAttribute("aria-label", "Open encrypted attachment");
    button.title = "Open encrypted attachment";
    button.appendChild(makeUiIcon("secure", 15));
    Object.assign(button.style, { position: "absolute", insetInlineEnd: "6px", insetBlockEnd: "6px", zIndex: "3", background: "rgba(20,24,28,.72)", color: "white" });
    host.setAttribute("data-bale-e2ee-encrypted-card", "true");
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation?.();
      pendingAttachmentClick = { surface, outerName, trusted: true, expires: Date.now() + 30000 };
      const fakeAnchor = document.createElement("a");
      fakeAnchor.href = href;
      fakeAnchor.download = outerName || "attachment.bin";
      void directDecryptDownload(fakeAnchor, href);
    }, true);
    host.appendChild(button);
  }

  function primeHrefLessAutoPreview(surface, outerName) {
    if (!(surface instanceof Element) || !surface.isConnected || !enabled) return;
    markEncryptedAttachmentSurface(surface);
    const state = surface.getAttribute("data-bale-e2ee-auto-preview");
    if (["pending-click", "pending", "ready", "document-ready", "not-e2ee"].includes(state || "")) return;
    const clickable = findClickableAttachmentSurface(surface);
    if (!(clickable instanceof HTMLElement)) return;
    surface.setAttribute("data-bale-e2ee-auto-preview", "pending-click");
    pendingAttachmentClick = { surface, outerName, trusted: false, expires: Date.now() + 20000 };
    // Bale mobile often resolves a private CDN URL only after the document card
    // is clicked. A synthetic click lets its own authenticated fetch/XHR run; our
    // response hooks verify BEE3FILE then replace the card with decrypted media.
    setTimeout(() => {
      if (!surface.isConnected || !enabled) return;
      try { clickable.click(); } catch (err) {
        surface.setAttribute("data-bale-e2ee-auto-preview", "failed");
        ensureManualDecryptButton(surface, outerName);
        console.debug("[Bale E2EE] href-less auto-preview click failed", err);
      }
    }, 80);
    setTimeout(() => {
      if (!surface.isConnected || !enabled) return;
      const stateNow = surface.getAttribute("data-bale-e2ee-auto-preview");
      if (stateNow === "pending-click" || stateNow === "failed") {
        surface.setAttribute("data-bale-e2ee-auto-preview", "failed");
        ensureManualDecryptButton(surface, outerName);
      }
    }, 3500);
  }

  function updateReplyPreviewLabels() {
    if (!enabled) return;
    const previews = document.querySelectorAll('.BAsWs0, [data-sentry-component="Preview"]');
    for (const preview of previews) {
      const span = preview.querySelector('.EdJ5y8 span, [class*="EdJ5y8"] span');
      if (!span || span.getAttribute("data-bale-e2ee-preview-updated") === "true") continue;
      const text = span.textContent || "";
      const match = text.match(GENERIC_ATTACHMENT_RE);
      if (match) {
        const outerName = match[0];
        const originalName = filenameDisplayMap.get(outerName);
        const cached = decryptedBlobCache.get(outerName);
        const displayName = originalName || cached?.meta?.name;
        if (displayName) {
          span.setAttribute("data-bale-e2ee-preview-updated", "true");
          span.textContent = displayName;
        }
      }
    }
  }

  function scanEncryptedAttachmentCards() {
    autoPreviewScanTimer = null;
    cleanupDetachedInlinePreviewUrls();
    if (!enabled || !document.documentElement) return;

    // Safety cleanup: If any reply/quote container has an erroneous bee11-secure-card, remove it and restore bubble!
    const bubbles = document.querySelectorAll('.Pkz3db, .OlfEl_');
    for (const b of bubbles) {
      const preview = b.querySelector('.BAsWs0, [data-sentry-component="Preview"]');
      const hasRealAttachment = b.querySelector('a.h7PFux, a[class*="h7PFux"]');
      if (preview && !hasRealAttachment) {
        const strays = b.querySelectorAll('.bee11-secure-card');
        for (const s of strays) {
          try { s.remove(); } catch (_) {}
        }
        const k7 = b.querySelector('.k7VAKr');
        if (k7 && k7.style.display === "none") {
          k7.style.removeProperty("display");
        }
      }
    }

    for (const anchor of document.querySelectorAll('a[href]')) {
      if (isReplyOrQuoteElement(anchor)) continue;
      if (looksLikeEncryptedAttachmentAnchor(anchor)) {
        markEncryptedAttachmentSurface(anchor);
        void autoDecryptInlineAttachment(anchor);
      }
    }

    // Find encrypted document cards in Bale Web - ONLY real attachment cards (a.h7PFux)
    const cards = document.querySelectorAll('a.h7PFux, a[class*="h7PFux"]');
    for (const card of cards) {
      if (isReplyOrQuoteElement(card)) continue;
      if (card.matches?.('.message-item, .message-block, [class*="message-block"], [class*="message-item"]')) continue;

      const surface = card;
      const text = String(surface.textContent || "");
      const match = text.match(GENERIC_ATTACHMENT_RE);
      const outerName = surface.getAttribute("data-bale-e2ee-outer-name") || (match ? match[0] : "");
      if (!outerName) continue;

      markEncryptedAttachmentSurface(surface);
      attachSecureIndicatorToTimestamp(surface);

      // If already decrypted in this session, render from cache:
      if (decryptedBlobCache.has(outerName)) {
        const cached = decryptedBlobCache.get(outerName);
        renderInlineDecryptedMediaAtSurface(surface, cached.blob, cached.meta, outerName);
        continue;
      }
    }

    updateReplyPreviewLabels();
  }

  function scheduleAutoPreviewScan(delay = 120) {
    if (autoPreviewScanTimer !== null) return;
    autoPreviewScanTimer = setTimeout(scanEncryptedAttachmentCards, delay);
  }

  if (originalAnchorClick && globalThis.HTMLAnchorElement?.prototype) {
    HTMLAnchorElement.prototype.click = function baleE2EEAnchorClick() {
      try {
        if (this.hasAttribute?.("data-bale-e2ee-safe-download")) {
          return originalAnchorClick.call(this);
        }
        const href = String(this.href || "");
        const downloadAttr = this.getAttribute("download") || "";
        if (enabled && (isEncryptedAttachmentUrlOrName(href) || isEncryptedAttachmentUrlOrName(downloadAttr))) {
          console.debug("[Bale E2EE] intercepted native .bin anchor click:", href, downloadAttr);
          void directDecryptDownload(this, href);
          return undefined;
        }
      } catch (_) {}
      return originalAnchorClick.call(this);
    };
  }

  async function directDecryptDownload(anchor, href) {
    try {
      let plainBlob = null;
      let meta = null;
      const outerName = (anchor instanceof Element ? anchor.getAttribute("download") : "") ||
                        (anchor instanceof Element ? String(anchor.textContent || "").trim() : "") ||
                        pendingAttachmentClick?.outerName || "";

      updateCardStage(outerName || anchor, "در حال اتصال به سرور...");

      if (isNasimProxyDownloadUrl(href)) {
        const res = await requestResolvedNasimDownload(href, (progress) => {
          const target = outerName || anchor;
          if (progress.stage === "connecting") {
            updateCardStage(target, "در حال اتصال به سرور نسیم...");
          } else if (progress.stage === "retrying") {
            updateCardStage(target, `تلاش مجدد برای ارتباط (${progress.attempt || 1})...`);
          } else if (progress.stage === "downloading") {
            if (progress.percent > 0) updateCardStage(target, `در حال دانلود فایل (${progress.percent}٪)...`);
            else if (progress.loaded > 0) updateCardStage(target, `در حال دانلود فایل (${formatFileSize(progress.loaded)})...`);
            else updateCardStage(target, "در حال دانلود فایل رمزشده...");
          } else if (progress.stage === "decrypting") {
            updateCardStage(target, "در حال رمزگشایی سرتاسری...");
          } else if (progress.stage === "rendering") {
            updateCardStage(target, "در حال آماده‌سازی و ذخیره...");
          }
        });
        plainBlob = res.blob;
        meta = res.meta;
      } else {
        updateCardStage(outerName || anchor, "در حال دانلود فایل رمزشده...");
        const response = await originalFetch(href, { credentials: "include" });
        if (!response.ok) throw new Error(`download HTTP ${response.status}`);
        const blob = await response.blob();
        if (!(await blobHasMagic(blob))) {
          let head = null;
          try { head = new Uint8Array(await blob.slice(0, 64).arrayBuffer()); } catch (_) {}
          const properName = resolveProperFilename(blob, null, outerName, head);
          if (outerName && properName) rememberDecryptedFilename(outerName, properName);
          await saveDecryptedBlob(blob, properName);
          return;
        }
        updateCardStage(outerName || anchor, "در حال رمزگشایی سرتاسری...");
        const dec = await requestDecryptBlob(blob, (progress) => {
          if (progress.stage === "decrypting") updateCardStage(outerName || anchor, "در حال رمزگشایی سرتاسری...");
        });
        plainBlob = dec.blob;
        meta = dec.meta;
      }

      let head = null;
      try { head = new Uint8Array(await plainBlob.slice(0, 64).arrayBuffer()); } catch (_) {}
      const properName = resolveProperFilename(plainBlob, meta, outerName, head);

      if (outerName && properName) {
        decryptedBlobCache.set(outerName, { blob: plainBlob, meta, outerName: properName });
        rememberDecryptedFilename(outerName, properName);
      }
      if (properName) {
        decryptedBlobCache.set(properName, { blob: plainBlob, meta, outerName: properName });
      }

      const type = String(meta?.type || plainBlob.type || "").toLowerCase();
      const isMedia = type.startsWith("image/") || type.startsWith("video/") || type.startsWith("audio/");
      if (isMedia) {
        renderPendingAttachment(plainBlob, meta, outerName);
      }

      await saveDecryptedBlob(plainBlob, properName);
    } catch (err) {
      const target = anchor instanceof Element ? anchor : null;
      if (target) updateCardStage(target, "خطا در دریافت فایل (برای تلاش مجدد کلیک کنید)", true);
      console.warn("[Bale E2EE] direct encrypted download interception failed", err);
      toast("خطا در دانلود فایل رمزگشایی شده", true);
    }
  }

  function interceptNativeNasimNavigation(rawUrl, source) {
    if (!enabled) return false;
    if (!isEncryptedAttachmentUrlOrName(rawUrl) && !isNasimProxyDownloadUrl(rawUrl)) return false;
    console.debug(`[Bale E2EE] suppressed Bale native download navigation via ${source}:`, rawUrl);
    void handleResolvedNasimUrl(String(rawUrl), source);
    return true;
  }

  // Real Bale Web resolves a signed Nasim URL over GetNasimFileUrls, then
  // starts a cross-site Document navigation in an iframe. Intercept the final
  // navigation as a second independent hook so the browser download manager
  // never receives the encrypted .bin when we have an armed E2EE card.
  if (iframeSrcDescriptor?.get && iframeSrcDescriptor?.set && globalThis.HTMLIFrameElement) {
    try {
      Object.defineProperty(HTMLIFrameElement.prototype, "src", {
        configurable: iframeSrcDescriptor.configurable,
        enumerable: iframeSrcDescriptor.enumerable,
        get: iframeSrcDescriptor.get,
        set(value) {
          if (interceptNativeNasimNavigation(value, "iframe.src")) {
            return iframeSrcDescriptor.set.call(this, "about:blank");
          }
          return iframeSrcDescriptor.set.call(this, value);
        }
      });
    } catch (err) {
      console.debug("[Bale E2EE] iframe.src navigation hook unavailable", err);
    }
  }

  Element.prototype.setAttribute = function baleE2EESetAttribute(name, value) {
    try {
      if (
        this instanceof HTMLIFrameElement &&
        String(name || "").toLowerCase() === "src" &&
        interceptNativeNasimNavigation(value, "iframe setAttribute(src)")
      ) {
        return originalElementSetAttribute.call(this, name, "about:blank");
      }
    } catch (_) {}
    return originalElementSetAttribute.call(this, name, value);
  };

  if (originalWindowOpen) {
    try {
      globalThis.open = function baleE2EEWindowOpen(url, target, features) {
        if (interceptNativeNasimNavigation(url, "window.open")) return null;
        return originalWindowOpen(url, target, features);
      };
    } catch (_) {}
  }

  document.addEventListener("keydown", (event) => {
    if (
      event.key !== "Enter" || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey ||
      event.isComposing
    ) return;

    // v8 secure-document attachments are already ciphertext before Bale sees
    // them; Enter only needs to encrypt the dialog/main caption before replay.
    if (enabled && secureDocumentSendPending()) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation?.();
      void replaySecureDocumentSend(findSendButtonNear(event.target) || event.target);
      return;
    }

    // Legacy staged-media guard for an unexpected raw Blob path.
    if (enabled && activeMedia.length) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation?.();
      void replaySendAfterMediaReady(findSendButtonNear(event.target) || findSendButton() || event.target);
      return;
    }

    const composer = findComposerFrom(event.target);
    intercept(event, composer);
  }, true);

  let stagedNativeEditorFile = null;
  let stagedNativeEditorTime = 0;

  async function executeEncryptedNativeMediaSend(modal, sendBtn) {
    try {
      toast("در حال رمزنگاری عکس و کپشن...", false);
      sendBtn.style.pointerEvents = "none";
      sendBtn.style.opacity = "0.5";

      // 1. Extract caption from textarea
      const captionEl = modal.querySelector('textarea, div[contenteditable="true"]');
      const captionText = captionEl ? (captionEl.value || captionEl.innerText || "").trim() : "";

      // 2. Extract media blob:
      // Look for the preview image in the modal (which reflects any crops/edits made by the user)
      const img = modal.querySelector('.media-wrapper img, .ReactModal__Overlay img');
      let mediaBlob = null;
      if (img?.src && (img.src.startsWith("blob:") || img.src.startsWith("data:"))) {
        try {
          const res = await originalFetch(img.src);
          mediaBlob = await res.blob();
        } catch (err) {
          console.warn("[Bale E2EE] failed to fetch blob from preview img, falling back to staged file", err);
        }
      }
      if (!mediaBlob && stagedNativeEditorFile) {
        mediaBlob = stagedNativeEditorFile;
      }
      if (!mediaBlob) {
        throw new Error("No media file found in editor");
      }

      const originalName = stagedNativeEditorFile?.name || "photo.jpg";
      const originalType = mediaBlob.type || stagedNativeEditorFile?.type || "image/jpeg";
      const plainFile = new File([mediaBlob], originalName, { type: originalType, lastModified: Date.now() });

      // 3. Find React fiber props for uploadDocument & peer
      let modalProps = null;
      let cur = sendBtn;
      while (cur && !modalProps) {
        for (const k in cur) {
          if (k.startsWith("__reactFiber")) {
            let f = cur[k];
            while (f) {
              if (f.memoizedProps?.uploadDocument) {
                modalProps = f.memoizedProps;
                break;
              }
              f = f.return;
            }
            break;
          }
        }
        cur = cur.parentElement;
      }

      // 4. Encrypt media into BEE3FILE container
      const encryptedFile = await requestEncryptFile(plainFile);
      if (!(encryptedFile instanceof File)) {
        throw new Error("Encryption failed to produce File object");
      }

      // 5. Encrypt caption into E2:... if present
      let encryptedCaption = "";
      if (captionText) {
        const items = await requestEncrypt(captionText);
        encryptedCaption = items?.[0]?.cipher || "";
      }

      // 6. Close the native modal cleanly
      if (typeof modalProps?.close === "function") {
        modalProps.close();
      } else {
        window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", code: "Escape", bubbles: true }));
        const closeBtn = modal.querySelector('.yR3jyx, button, [class*="close" i]');
        closeBtn?.click?.();
      }

      // Cache the plaintext blob locally so our UI renders instantly when outgoing message appears
      decryptedBlobCache.set(encryptedFile.name, {
        blob: plainFile,
        meta: { name: originalName, type: originalType, size: plainFile.size }
      });
      decryptedBlobCache.set(originalName, {
        blob: plainFile,
        meta: { name: originalName, type: originalType, size: plainFile.size }
      });
      rememberDecryptedFilename(encryptedFile.name, originalName);

      // 7. Dispatch send via uploadDocument or document input fallback
      if (modalProps?.uploadDocument && modalProps.peer) {
        modalProps.uploadDocument([{ file: encryptedFile, caption: encryptedCaption }], 1, modalProps.peer);
        console.log("[Bale E2EE] native media editor send executed as encrypted document", {
          originalName,
          outerName: encryptedFile.name,
          hasCaption: Boolean(encryptedCaption)
        });
      } else {
        // Fallback: route through document input
        const input = document.getElementById("_r_8_");
        if (input) {
          dispatchEncryptedInputChange(input, [encryptedFile], input);
        }
      }

      toast(captionText ? "عکس و کپشن رمزنگاری‌شده ارسال شدند" : "عکس رمزنگاری‌شده ارسال شد");
    } catch (err) {
      console.error("[Bale E2EE] native media send failed; plaintext fallback strictly forbidden:", err);
      toast("خطا در رمزنگاری؛ برای جلوگیری از نشت اطلاعات ارسال متوقف شد.", true);
    } finally {
      stagedNativeEditorFile = null;
      stagedNativeEditorTime = 0;
    }
  }

  function triggerCardCircleClick(card) {
    if (!(card instanceof Element)) return false;
    const circle = card.querySelector?.('.vMR6Iw, [class*="vMR6Iw"], [data-sentry-component="renderCircleContent"]');
    if (!circle) return false;
    let circleFiber = null;
    for (const k in circle) { if (k.startsWith('__reactFiber')) { circleFiber = circle[k]; break; } }
    if (typeof circleFiber?.memoizedProps?.onClick === 'function') {
      try {
        const fakeEvt = {
          preventDefault() {},
          stopPropagation() {},
          stopImmediatePropagation() {},
          bubbles: true,
          cancelable: true
        };
        circleFiber.memoizedProps.onClick(fakeEvt);
        return true;
      } catch (_) {}
    }
    try {
      circle.click();
      return true;
    } catch (_) {}
    return false;
  }

  function triggerAudioControllerClick(controllerBtn) {
    if (!(controllerBtn instanceof Element)) return false;
    let fiber = null;
    for (const k in controllerBtn) { if (k.startsWith('__reactFiber')) { fiber = controllerBtn[k]; break; } }
    if (typeof fiber?.memoizedProps?.onClick === 'function') {
      try {
        fiber.memoizedProps.onClick({ preventDefault(){}, stopPropagation(){}, stopImmediatePropagation(){} });
        return true;
      } catch (_) {}
    }
    const child = controllerBtn.querySelector('div, svg, button');
    if (child) {
      let childFiber = null;
      for (const k in child) { if (k.startsWith('__reactFiber')) { childFiber = child[k]; break; } }
      if (typeof childFiber?.memoizedProps?.onClick === 'function') {
        try {
          childFiber.memoizedProps.onClick({ preventDefault(){}, stopPropagation(){}, stopImmediatePropagation(){} });
          return true;
        } catch (_) {}
      }
    }
    try {
      controllerBtn.click();
      return true;
    } catch (_) {}
    return false;
  }

  function triggerBaleCardDownload(card) {
    if (!(card instanceof Element)) return false;
    let fiber = null;
    for (const k in card) { if (k.startsWith('__reactFiber')) { fiber = card[k]; break; } }
    if (!fiber) {
      const child = card.querySelector?.('.vMR6Iw, svg, span, p');
      if (child) {
        for (const k in child) { if (k.startsWith('__reactFiber')) { fiber = child[k]; break; } }
      }
    }
    if (!fiber) return false;

    let cur = fiber;
    while (cur) {
      let h = cur.memoizedState;
      while (h) {
        const s = h.memoizedState;
        if (Array.isArray(s) && typeof s[0] === 'function' && s[0].toString().includes('downloadAsset')) {
          try {
            s[0]({ showToastOnError: true, force: true });
            return true;
          } catch (_) {}
        }
        h = h.next;
      }
      cur = cur.return;
    }

    const icon = card.querySelector?.('.vMR6Iw, [class*="vMR6Iw"]');
    if (icon) {
      let iconFiber = null;
      for (const k in icon) { if (k.startsWith('__reactFiber')) { iconFiber = icon[k]; break; } }
      if (typeof iconFiber?.memoizedProps?.onClick === 'function') {
        try {
          iconFiber.memoizedProps.onClick({ preventDefault(){}, stopPropagation(){} });
          return true;
        } catch (_) {}
      }
    }
    return false;
  }

  function handleCapturedClick(event) {
    if (processedClickEvents.has(event)) return;
    processedClickEvents.add(event);

    // 0. Intercept the Send button inside Bale's native media editor modal!
    const modalOverlay = event.target.closest?.('.ReactModal__Overlay');
    if (enabled && modalOverlay) {
      const sendBtn = event.target.closest?.('.NeF5wn, div[aria-label="send-button"], button[aria-label="send-button"]');
      if (sendBtn) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation?.();
        void executeEncryptedNativeMediaSend(modalOverlay, sendBtn);
        return;
      }
    }

    // Intercept direct bot-command clicks before Bale's own handler can send raw text.
    if (interceptCommandClick(event)) return;

    if (bypassNextSendClick && isSendTarget(event.target)) {
      bypassNextSendClick = false;
      return;
    }

    if (isSendTarget(event.target)) {
      if (enabled && secureDocumentSendPending()) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation?.();
        void replaySecureDocumentSend(event.target);
        return;
      }
      if (enabled && activeMedia.length) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation?.();
        void replaySendAfterMediaReady(event.target);
        return;
      }
      const composer = findComposerForSendTarget(event.target);
      intercept(event, composer);
      return;
    }

    if (!enabled || !(event.target instanceof Element)) return;

    // Reject clicks inside reply / quote containers
    if (isReplyOrQuoteElement(event.target)) return;

    // Intercept clicks on Audio / Voice message text / container so clicking anywhere plays/downloads:
    const audioContainer = event.target.closest?.(
      '[data-sentry-source-file="NewAudioMessage.tsx"], [data-sentry-source-file="NewVoiceMessage.tsx"], [class*="NewAudioMessage"], [class*="NewVoiceMessage"], [data-sentry-component="NewVoiceMessage"]'
    );
    if (audioContainer && !isReplyOrQuoteElement(audioContainer)) {
      const isMoreMenu = event.target.closest?.('[data-sentry-element="MoreMenu"], [class*="icon_container"], button');
      const controllerBtn = audioContainer.querySelector?.(
        '[data-sentry-element="AudioControllerButton"], [class*="AudioControllerButton"]'
      );
      if (controllerBtn && !isMoreMenu && !controllerBtn.contains(event.target)) {
        console.debug("[Bale E2EE] forward audio text/container click to AudioControllerButton");
        event.preventDefault();
        event.stopPropagation();
        triggerAudioControllerClick(controllerBtn);
        return;
      }
    }

    // In Bale Web React, an attachment card is always an a.h7PFux
    const cardContainer = event.target.closest?.('a.h7PFux, a[class*="h7PFux"]');
    if (cardContainer && !isReplyOrQuoteElement(cardContainer)) {
      const circleIcon = cardContainer.querySelector?.('.vMR6Iw, [class*="vMR6Iw"], [data-sentry-component="renderCircleContent"]');
      const isDirectCircleClick = circleIcon && (event.target === circleIcon || circleIcon.contains(event.target));
      const attachmentInfo = attachmentInfoFromTarget(cardContainer);

      if (attachmentInfo) {
        const surface = attachmentInfo.surface || cardContainer;
        if (isReplyOrQuoteElement(surface)) return;
        pendingAttachmentClick = { ...attachmentInfo, surface, trusted: Boolean(event.isTrusted), expires: Date.now() + 90000 };
        console.debug("[Bale E2EE] trusted encrypted attachment click armed before Bale handler", attachmentInfo.outerName);

        const cached = decryptedBlobCache.get(attachmentInfo.outerName) ||
                       (filenameDisplayMap.has(attachmentInfo.outerName) ? decryptedBlobCache.get(filenameDisplayMap.get(attachmentInfo.outerName)) : null) ||
                       decryptedBlobCache.get(surface?.getAttribute("data-bale-e2ee-original-name"));
        if (cached) {
          console.log("[Bale E2EE] rendering from cache instantly", attachmentInfo.outerName);
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation?.();
          renderInlineDecryptedMediaAtSurface(surface, cached.blob, cached.meta, attachmentInfo.outerName);
          const type = String(cached.meta?.type || cached.blob?.type || "").toLowerCase();
          if (!type.startsWith("image/") && !type.startsWith("video/") && !type.startsWith("audio/")) {
            saveDecryptedBlob(cached.blob, cached.meta?.name || "decrypted-file");
          }
          return;
        }

        // Check if card's React fiber already has the Blob loaded in memory:
        const fiberData = extractBlobOrUrlFromCard(surface);
        if (fiberData?.blob) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation?.();
          void autoDecryptLoadedBlob(surface, fiberData.blob, attachmentInfo.outerName);
          return;
        }
        if (fiberData?.url) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation?.();
          void autoDecryptInlineSurface(surface, attachmentInfo.outerName, fiberData.url);
          return;
        }

        showCardDecryptingState(surface, attachmentInfo.outerName, "در حال دریافت لینک فایل...");

        // If clicked on text, file size, or padding, forward to circle click and trigger download:
        if (!isDirectCircleClick && circleIcon) {
          event.preventDefault();
          event.stopPropagation();
          triggerBaleCardDownload(surface);
          triggerCardCircleClick(cardContainer);
          return;
        }

        // Trigger Bale download directly via fiber hook or click:
        const triggered = triggerBaleCardDownload(surface);
        if (!triggered && circleIcon && !isDirectCircleClick) {
          triggerCardCircleClick(cardContainer);
        }
        return;
      } else {
        // Unencrypted card (plain audio/document). If user tapped the text, size or margin, trigger circle click!
        if (!isDirectCircleClick && circleIcon) {
          console.debug("[Bale E2EE] forward plain document card text click to circle icon");
          event.preventDefault();
          event.stopPropagation();
          triggerCardCircleClick(cardContainer);
          return;
        }
      }
    }

    const anchor = event.target.closest("a[href]");
    if (anchor) {
      if (anchor.hasAttribute?.("data-bale-e2ee-safe-download")) return;
      const href = anchor.href;
      const downloadAttr = anchor.getAttribute("download") || "";
      if (isEncryptedAttachmentUrlOrName(href) || isEncryptedAttachmentUrlOrName(downloadAttr)) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation?.();
        void directDecryptDownload(anchor, href);
        return;
      }
    }
  }

  // Arm encrypted document cards as early as possible on touch/pointer input.
  const armAttachmentFromTrustedPointer = (event) => {
    if (!enabled || !(event.target instanceof Element)) return;
    if (isReplyOrQuoteElement(event.target)) return;
    const cardContainer = event.target.closest?.('a.h7PFux, a[class*="h7PFux"]');
    if (!cardContainer || isReplyOrQuoteElement(cardContainer)) return;
    const info = attachmentInfoFromTarget(cardContainer);
    if (info && !isReplyOrQuoteElement(info.surface)) {
      pendingAttachmentClick = { ...info, trusted: Boolean(event.isTrusted), expires: Date.now() + 60000 };
      // Do not mutate DOM on pointerdown/touchstart to avoid aborting mobile touch-to-click gestures!
    }
  };
  window.addEventListener("pointerdown", armAttachmentFromTrustedPointer, true);
  window.addEventListener("touchstart", armAttachmentFromTrustedPointer, true);

  // window capture runs before document capture. Registering at document_start
  // means direct Bale click handlers do not get a chance to send /commands raw.
  window.addEventListener("click", handleCapturedClick, true);
  document.addEventListener("click", handleCapturedClick, true);

  function handleAttachmentChange(event) {
    if (processedAttachmentEvents.has(event) || event.__baleE2EEForwarded) return;
    processedAttachmentEvents.add(event);
    if (!enabled) return;

    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type !== "file") return;
    const files = fileListToArray(input.files);
    if (!files.length) return;

    // If this selection is for photos/videos (triggered by "Photo and Video" menu or media picker),
    // allow Bale's native editor modal to open! The user gets to preview, crop/rotate, and write a caption.
    // The Send button in that modal will be intercepted and encrypted before any data leaves the client.
    const isMediaSelection = looksLikeMediaPicker(input) || (input.accept && /(image|video)/i.test(input.accept));
    if (isMediaSelection && files.some(isVisualAttachment)) {
      stagedNativeEditorFile = files[0];
      stagedNativeEditorTime = Date.now();
      console.log("[Bale E2EE] allowed native media editor modal to open for", files[0].name);
      return;
    }

    // For generic documents/files, maintain instant encryption and routing:
    event.preventDefault?.();
    event.stopPropagation();
    event.stopImmediatePropagation?.();
    try { input.value = ""; } catch (_) {}
    void routeInputSelectionAsEncryptedDocument(input, files).catch((err) => {
      console.error("[Bale E2EE] attachment selection blocked; plaintext fallback forbidden:", err);
      toast("رمزنگاری پیوست ناموفق بود؛ فایل خام به بله تحویل داده نشد.", true);
      try { input.value = ""; } catch (_) {}
    });
  }

  function handleAttachmentTransfer(event, source, transfer) {
    if (processedAttachmentEvents.has(event) || event.__baleE2EEForwarded || !enabled) return;
    const files = mediaListFromTransfer(transfer);
    if (!files.length) return;
    processedAttachmentEvents.add(event);
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation?.();
    void routeTransferAsEncryptedDocument(event, files, source).catch((err) => {
      console.error(`[Bale E2EE] ${source} blocked; plaintext fallback forbidden:`, err);
      toast("رمزنگاری پیوست ناموفق بود؛ فایل خام ارسال نشد.", true);
    });
  }

  // window capture is deliberately first: Bale/React never receives the original
  // FileList. Register on document too for builds that attach unusual handlers.
  window.addEventListener("change", handleAttachmentChange, true);
  document.addEventListener("change", handleAttachmentChange, true);
  window.addEventListener("drop", (event) => handleAttachmentTransfer(event, "drop", event.dataTransfer), true);
  document.addEventListener("drop", (event) => handleAttachmentTransfer(event, "drop", event.dataTransfer), true);
  window.addEventListener("paste", (event) => handleAttachmentTransfer(event, "clipboard-paste", event.clipboardData), true);
  document.addEventListener("paste", (event) => handleAttachmentTransfer(event, "clipboard-paste", event.clipboardData), true);

  document.addEventListener("click", (event) => {
    if (!enabled || !(event.target instanceof Element)) return;
    const info = attachmentInfoFromTarget(event.target);
    if (!info) return;
    pendingAttachmentClick = { ...info, trusted: Boolean(event.isTrusted), expires: Date.now() + 20000 };
    console.debug("[Bale E2EE] encrypted attachment interaction armed for transparent decrypt", info.outerName);
  }, true);

  const filenameObserver = new MutationObserver((mutations) => {
    if (!filenameDisplayMap.size) return;
    for (const mutation of mutations) {
      if (mutation.type === "characterData") processFilenameTextNode(mutation.target);
      for (const node of mutation.addedNodes) processFilenameRoot(node);
    }
  });
  filenameObserver.observe(document.documentElement, { subtree: true, childList: true, characterData: true });

  const autoPreviewObserver = new MutationObserver((mutations) => {
    let relevant = false;
    for (const mutation of mutations) {
      if (mutation.type === "childList" && mutation.addedNodes.length) { relevant = true; break; }
      if (mutation.type === "characterData" || mutation.type === "attributes") { relevant = true; break; }
    }
    if (relevant) scheduleAutoPreviewScan();
    cleanupDetachedInlinePreviewUrls();
  });
  autoPreviewObserver.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ["href", "download", "title", "aria-label"]
  });
  scheduleAutoPreviewScan(0);

  window.__baleE2EE_status = () => ({ enabled, version: "12.14.0", pendingAttachmentClick });

  let hookReadyAttempts = 0;
  const hookReadyInterval = setInterval(() => {
    hookReadyAttempts += 1;
    if (enabled || hookReadyAttempts > 30) {
      clearInterval(hookReadyInterval);
      return;
    }
    const localPass = localStorage.getItem("bale_e2ee_passphrase") || localStorage.getItem("bale_e2ee_key") || "";
    post("HOOK_READY", { localPass });
  }, 400);

  post("HOOK_READY", { localPass: localStorage.getItem("bale_e2ee_passphrase") || "" });
  console.log("[Bale E2EE] v12 MAIN-world direct GetNasimFileUrls interception + compact text + encrypted attachments + inline decrypted media ready.");
})();
