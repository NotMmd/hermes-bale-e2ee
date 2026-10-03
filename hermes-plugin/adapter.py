"""
Bale (بله) Platform Adapter for Hermes Agent with E2EE.

Features:
- Pure aiohttp async long-polling and HTTP calls.
- End-to-End Encryption (AES-256-GCM) with Zero-Leakage:
  When BALE_ENCRYPTION_KEY is configured:
  * All outgoing texts and media are encrypted.
  * Inbound plain text messages are rejected/alerted.
  * Inbound encrypted messages are decrypted and passed seamlessly to Hermes core.
- Transparent forwarding of all commands (/start, /new, /model, etc.) to Hermes core.
- Interactive buttons for Clarify and Approvals.
- Full media send & receive support using Hermes media_urls/media_types cache contract.
"""

import asyncio
import datetime
import inspect
import json
import logging
import mimetypes
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import aiohttp

from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

# Hermes 2026+ exposes the unified media cache helper used by built-in adapters.
# Keep a compatibility fallback so the plugin can still load on slightly older builds.
try:
    from gateway.platforms.base import cache_media_bytes_async
except ImportError:  # pragma: no cover - compatibility with older Hermes builds
    cache_media_bytes_async = None
from gateway.config import Platform
from .crypto import (
    derive_key,
    encrypt_text,
    encrypt_text_v2,
    encrypt_text_v2_chunks,
    encrypt_text_compact,
    encrypt_text_chunks,
    decrypt_text,
    is_encrypted_text,
    parse_text_chunk_header,
    encrypt_bytes,
    decrypt_bytes,
    TEXT_PREFIX,
    TEXT_V2_PREFIX,
    TEXT_CHUNK_PREFIX,
    TEXT_WIRE_SAFE_LIMIT,
    MEDIA_MAGIC,
)

logger = logging.getLogger(__name__)

BALE_API_BASE = "https://tapi.bale.ai/bot"
BALE_FILE_BASE = "https://tapi.bale.ai/file/bot"

# Logical plaintext budget exposed to Hermes. This adapter performs its own
# transport chunking after compression/encryption, so the real Bale wire cap
# is enforced by TEXT_WIRE_SAFE_LIMIT below rather than by premature gateway
# splitting of compressible plaintext.
MAX_MESSAGE_LENGTH = 65536
SAFE_E2EE_MESSAGE_LENGTH = TEXT_WIRE_SAFE_LIMIT
# Bale document captions have a much smaller limit than normal messages. Keep
# encrypted captions comfortably below the documented 1024-character ceiling;
# longer logical captions are sent as regular encrypted follow-up bubbles.
SAFE_E2EE_CAPTION_LENGTH = 900
TEXT_CHUNK_TTL_SECONDS = 120
CALLBACK_TOKEN_TTL_SECONDS = 15 * 60


def _get_max_media_size() -> int:
    """Return maximum allowed file transfer size in bytes (default: 20MB, configurable via env)."""
    try:
        val = os.getenv("BALE_MAX_FILE_SIZE_MB", "20").strip()
        return int(float(val) * 1024 * 1024)
    except Exception:
        return 20 * 1024 * 1024


MAX_MEDIA_SIZE = _get_max_media_size()

_WAITING_TEXT_CHUNK = object()


def _outer_attachment_name() -> str:
    """Return the only filename Bale should see for encrypted attachments."""
    return f"attachment-{secrets.token_hex(8)}.bin"


def _sniff_mime(data: bytes, fallback: str = "application/octet-stream") -> str:
    """Best-effort MIME sniffing for Hermes-generated media when no filename is available."""
    head = data[:64]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "application/zip"
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return "audio/mpeg"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "video/mp4"
    return fallback


def _extension_for_mime(mime_type: str) -> str:
    preferred = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "video/mp4": ".mp4",
        "audio/ogg": ".ogg",
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav",
        "application/pdf": ".pdf",
        "application/zip": ".zip",
    }
    return preferred.get((mime_type or "").lower()) or mimetypes.guess_extension(mime_type or "") or ""


def _normalize_original_filename(filename: str, mime_type: str, fallback_stem: str = "file") -> str:
    """Keep the real name inside BEE3FILE; synthesize a useful extension only when missing."""
    name = Path(filename or "").name.strip() or fallback_stem
    if not Path(name).suffix:
        ext = _extension_for_mime(mime_type)
        if ext:
            name += ext
    return name


def _message_type_from_cached_kind(kind: str) -> MessageType:
    return {
        "image": MessageType.PHOTO,
        "video": MessageType.VIDEO,
        "audio": MessageType.AUDIO,
        "document": MessageType.DOCUMENT,
    }.get(kind, MessageType.DOCUMENT)


class BaleAdapter(BasePlatformAdapter):
    """Async Bale platform adapter with E2EE."""

    def __init__(self, config, **kwargs):
        platform = Platform("bale")
        super().__init__(config=config, platform=platform)

        self.token = os.getenv("BALE_BOT_TOKEN", "").strip()
        self.base_url = f"{BALE_API_BASE}{self.token}"
        self.file_url = f"{BALE_FILE_BASE}{self.token}"

        # Encryption Key Setup
        raw_key = os.getenv("BALE_ENCRYPTION_KEY", "").strip()
        self._crypto_key: Optional[bytes] = derive_key(raw_key) if raw_key else None
        self.e2ee_enabled = self._crypto_key is not None

        # Access Control
        allowed_env = os.getenv("BALE_ALLOWED_USERS", "").strip()
        self._allowed_users: set = set()
        if allowed_env:
            self._allowed_users = {
                uid.strip() for uid in allowed_env.split(",") if uid.strip()
            }
        self._allow_all = (
            os.getenv("BALE_ALLOW_ALL_USERS", "").strip().lower()
            in {"1", "true", "yes"}
        )

        # Runtime state
        self._session: Optional[aiohttp.ClientSession] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._offset: int = 0
        self._running = False
        # E2EE text chunk reassembly and opaque callback-token state.
        self._text_chunks: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._callback_tokens: Dict[str, Tuple[float, str]] = {}
        self._slash_confirm_state: Dict[str, str] = {}
        self._approval_state: Dict[str, str] = {}
        self._clarify_state: Dict[str, Dict[str, Any]] = {}
        self._choice_picker_state: Dict[str, Dict[str, Any]] = {}
        self._model_picker_state: Dict[str, Dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "Bale"

    # ── Connection lifecycle ──────────────────────────────────────────────

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        """Verify token and start polling."""
        if not self.token:
            logger.error("Bale: BALE_BOT_TOKEN is not configured")
            self._set_fatal_error(
                "config_missing",
                "BALE_BOT_TOKEN is not configured",
                retryable=False,
            )
            return False

        try:
            me = await self._api_get("getMe")
            if not me.get("ok"):
                raise RuntimeError(f"getMe failed: {me}")
            bot_info = me.get("result", {})
            logger.info(
                "Bale: connected as @%s (E2EE: %s)",
                bot_info.get("username", "unknown"),
                "ENABLED (AES-256-GCM)" if self.e2ee_enabled else "DISABLED",
            )
        except Exception as e:
            logger.error("Bale: getMe verification failed: %s", e)
            self._set_fatal_error("auth_failed", str(e), retryable=False)
            return False

        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        )
        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())

        self._mark_connected()
        return True

    async def disconnect(self) -> None:
        """Stop polling and close session."""
        self._running = False
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass

        if self._session and not self._session.closed:
            try:
                await self._session.close()
            except Exception:
                pass

        self._session = None
        self._mark_disconnected()
        logger.info("Bale: adapter disconnected")

    # ── Polling loop ──────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Long-polling update listener."""
        backoff = 1
        while self._running:
            try:
                updates = await self._get_updates()
                backoff = 1
                for update in updates:
                    try:
                        await self._handle_update(update)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception("Bale: error handling update")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("Bale: polling error: %s — retrying in %ds", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def _get_updates(self) -> List[dict]:
        """Fetch updates with offset acknowledgment."""
        params: Dict[str, Any] = {
            "timeout": 30,
            "offset": self._offset,
        }
        data = await self._api_get("getUpdates", params)
        if not data.get("ok"):
            raise RuntimeError(f"getUpdates failed: {data}")

        results = data.get("result", [])
        if results:
            self._offset = results[-1].get("update_id", self._offset) + 1
        return results


    def _cleanup_ephemeral_state(self) -> None:
        now = time.monotonic()
        for key, state in list(self._text_chunks.items()):
            if now - float(state.get("created", now)) > TEXT_CHUNK_TTL_SECONDS:
                self._text_chunks.pop(key, None)
        for token, (created, _value) in list(self._callback_tokens.items()):
            if now - created > CALLBACK_TOKEN_TTL_SECONDS:
                self._callback_tokens.pop(token, None)

    def _tokenize_keyboard(self, keyboard: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Return a Bale keyboard with opaque callback_data in E2EE mode.

        Bale must see callback_data to route button clicks, so the original Hermes
        command/session payload is replaced by a short random token kept only in
        this adapter's memory.  URL/web_app buttons are left unchanged.
        """
        if not keyboard:
            return keyboard
        self._cleanup_ephemeral_state()
        # JSON round-trip is a convenient deep copy for keyboard-shaped data.
        try:
            safe = json.loads(json.dumps(keyboard, ensure_ascii=False))
        except Exception:
            safe = keyboard
        if not self.e2ee_enabled or not isinstance(safe, dict):
            return safe
        for row in safe.get("inline_keyboard", []) or []:
            if not isinstance(row, list):
                continue
            for button in row:
                if not isinstance(button, dict) or "callback_data" not in button:
                    continue
                original = str(button.get("callback_data") or "")
                token = "e2:" + secrets.token_hex(8)
                self._callback_tokens[token] = (time.monotonic(), original)
                button["callback_data"] = token
        return safe

    def _resolve_callback_token(self, value: str) -> str:
        self._cleanup_ephemeral_state()
        entry = self._callback_tokens.pop(value, None)
        return entry[1] if entry else value

    def _callback_allowed(self, chat_id: str, user_id: str) -> bool:
        if self._allow_all or not self._allowed_users:
            return True
        return str(chat_id) in self._allowed_users or str(user_id) in self._allowed_users

    async def _await_callback(self, callback, *args):
        result = callback(*args)
        if inspect.isawaitable(result):
            return await result
        return result

    def _decrypt_or_buffer_text(
        self,
        chat_id: str,
        cipher_text: str,
        *,
        media_urls: Optional[List[str]] = None,
        media_types: Optional[List[str]] = None,
        message_type: Optional[MessageType] = None,
    ):
        """Decrypt one wire message and reassemble either supported chunk framing.

        Supported chunk modes:
        - experimental E2C wire framing (header itself authenticated via AAD)
        - Extension v9 ENC2 framing, where BEE2CHUNK metadata lives *inside*
          authenticated plaintext.

        Returns:
          tuple(...)   completed logical message
          _WAITING_TEXT_CHUNK  valid fragment waiting for siblings
          None         corrupt/unreadable ciphertext
        """
        if not self._crypto_key:
            return None
        ok, piece = decrypt_text(cipher_text, self._crypto_key)
        if not ok:
            return None

        msg_id: Optional[str] = None
        idx = 0
        total = 1
        zero_based = False
        body = piece

        # Old/experimental compact E2C wire header.
        outer = parse_text_chunk_header(cipher_text)
        if outer is not None:
            msg_id, idx, total = outer
        # v9 browser framing is inside AES-GCM plaintext.
        elif piece.startswith(TEXT_CHUNK_PREFIX):
            first, sep, body = piece.partition("\n")
            if not sep:
                return None
            m = re.fullmatch(r"BEE2CHUNK:([0-9a-f]{8,32}):(\d{1,4}):(\d{1,4})", first)
            if not m:
                return None
            msg_id, idx_s, total_s = m.groups()
            idx, total = int(idx_s), int(total_s)
            zero_based = True
            if total < 2 or total > 256 or idx < 0 or idx >= total:
                return None

        if msg_id is None:
            return piece, list(media_urls or []), list(media_types or []), message_type or MessageType.TEXT

        if not zero_based and (total < 1 or total > 1000 or idx < 1 or idx > total):
            return None

        self._cleanup_ephemeral_state()
        key = (str(chat_id), str(msg_id))
        state = self._text_chunks.get(key)
        if state is None or int(state.get("total", -1)) != total or bool(state.get("zero_based")) != zero_based:
            state = {
                "created": time.monotonic(),
                "total": total,
                "zero_based": zero_based,
                "parts": {},
                "media_urls": [],
                "media_types": [],
                "message_type": MessageType.TEXT,
            }
            self._text_chunks[key] = state
        state["parts"][idx] = body
        if media_urls:
            state["media_urls"] = list(media_urls)
            state["media_types"] = list(media_types or [])
            state["message_type"] = message_type or MessageType.DOCUMENT

        if len(state["parts"]) < total:
            logger.debug("Bale: buffered encrypted text chunk %s %s/%s", msg_id, idx, total)
            return _WAITING_TEXT_CHUNK

        order = range(0, total) if zero_based else range(1, total + 1)
        try:
            plain = "".join(state["parts"][i] for i in order)
        except KeyError:
            return _WAITING_TEXT_CHUNK
        self._text_chunks.pop(key, None)
        return (
            plain,
            list(state.get("media_urls") or media_urls or []),
            list(state.get("media_types") or media_types or []),
            state.get("message_type") or message_type or MessageType.TEXT,
        )

    async def _handle_update(self, update: dict) -> None:
        """Process incoming message or callback."""
        # Handle inline callback queries (e.g. clarify or approval buttons)
        if "callback_query" in update:
            await self._handle_callback_query(update["callback_query"])
            return

        message = update.get("message")
        if not message:
            return

        chat = message.get("chat", {})
        chat_id = str(chat.get("id", ""))
        if not chat_id:
            return

        # Access check
        if not self._allow_all and self._allowed_users:
            if chat_id not in self._allowed_users:
                logger.debug("Bale: ignoring unauthorized chat %s", chat_id)
                return

        from_obj = message.get("from", {})
        user_id = str(from_obj.get("id", ""))
        user_name = from_obj.get("first_name", from_obj.get("username", user_id))
        chat_type_raw = chat.get("type", "private")
        chat_type = "dm" if chat_type_raw == "private" else "group"
        chat_name = chat.get("title") or chat.get("username", "") or chat_id
        message_id = str(message.get("message_id", ""))

        # Bale uses `text` for normal messages and `caption` for document/photo media.
        # Keep the distinction until after E2EE validation so a media caption can never
        # bypass the strict ENC: requirement.
        raw_text = message.get("text", "") or ""
        raw_caption = message.get("caption", "") or ""
        text = raw_text or raw_caption
        message_type = MessageType.TEXT
        media_urls: List[str] = []
        media_types: List[str] = []

        # Handle inbound documents / media files. In modern Hermes the normalized
        # MessageEvent media contract is *local cached paths* in media_urls/media_types,
        # not an ad-hoc `event.media_bytes` attribute.
        doc = message.get("document") or message.get("photo") or message.get("audio") or message.get("video")
        if doc:
            default_kind = "document"
            if message.get("photo"):
                default_kind = "image"
            elif message.get("video"):
                default_kind = "video"
            elif message.get("audio"):
                default_kind = "audio"

            if isinstance(doc, list):
                # Native photo sizes array, take the highest-resolution entry. Encrypted
                # extension traffic should normally arrive as `document`, but this keeps
                # the adapter robust with legacy clients.
                doc = doc[-1] if doc else {}

            file_id = doc.get("file_id") if isinstance(doc, dict) else None
            if file_id:
                raw_file = await self._download_file(file_id)
                if raw_file is None:
                    logger.warning("Bale: failed to download inbound media file_id=%s", file_id)
                    if self.e2ee_enabled:
                        await self.send(chat_id, "درخواست نامعتبر است.")
                        return
                else:
                    media_data = raw_file
                    media_meta: Dict[str, Any] = {}
                    if self.e2ee_enabled and self._crypto_key is not None:
                        ok, dec_file, media_meta = decrypt_bytes(raw_file, self._crypto_key)
                        if not ok:
                            logger.warning("Bale: rejecting unencrypted/corrupt inbound media in E2EE mode")
                            await self.send(chat_id, "درخواست نامعتبر است.")
                            return
                        media_data = dec_file

                    # BEE3FILE keeps the true filename/MIME inside its authenticated header.
                    # For non-E2EE/legacy messages fall back to Bale's document metadata.
                    original_name = str(
                        media_meta.get("name")
                        or (doc.get("file_name") if isinstance(doc, dict) else "")
                        or "file"
                    )
                    original_mime = str(
                        media_meta.get("type")
                        or (doc.get("mime_type") if isinstance(doc, dict) else "")
                        or _sniff_mime(media_data)
                    )
                    original_name = _normalize_original_filename(original_name, original_mime, fallback_stem=default_kind)

                    cached = None
                    if cache_media_bytes_async is not None:
                        cached = await cache_media_bytes_async(
                            media_data,
                            filename=original_name,
                            mime_type=original_mime,
                            default_kind=default_kind,
                        )
                    else:  # Compatibility path for older Hermes builds.
                        try:
                            from gateway.platforms.base import (
                                cache_image_from_bytes,
                                cache_audio_from_bytes,
                                cache_video_from_bytes,
                                cache_document_from_bytes,
                            )
                            ext = Path(original_name).suffix or _extension_for_mime(original_mime)
                            if original_mime.startswith("image/") or default_kind == "image":
                                path = await asyncio.to_thread(cache_image_from_bytes, media_data, ext or ".jpg")
                                kind = "image"
                            elif original_mime.startswith("video/") or default_kind == "video":
                                path = await asyncio.to_thread(cache_video_from_bytes, media_data, ext or ".mp4")
                                kind = "video"
                            elif original_mime.startswith("audio/") or default_kind == "audio":
                                path = await asyncio.to_thread(cache_audio_from_bytes, media_data, ext or ".ogg")
                                kind = "audio"
                            else:
                                path = await asyncio.to_thread(cache_document_from_bytes, media_data, original_name)
                                kind = "document"
                            cached = type("Cached", (), {
                                "path": path,
                                "media_type": original_mime or "application/octet-stream",
                                "kind": kind,
                                "display_name": original_name,
                            })()
                        except Exception:
                            logger.exception("Bale: failed to cache decrypted inbound media")
                            await self.send(chat_id, "درخواست نامعتبر است.")
                            return

                    if cached is None:
                        logger.warning("Bale: decrypted inbound media could not be cached/validated")
                        await self.send(chat_id, "درخواست نامعتبر است.")
                        return

                    media_urls.append(cached.path)
                    media_types.append(cached.media_type)
                    message_type = _message_type_from_cached_kind(cached.kind)
                    logger.info(
                        "Bale: decrypted inbound %s cached for Hermes as %s (%s)",
                        cached.kind,
                        cached.path,
                        cached.media_type,
                    )

        # Handle inbound text / caption E2EE validation.  Compact E2C messages may
        # span multiple Bale messages; do not dispatch to Hermes until every
        # authenticated chunk is present.  Media attached to the first chunk is
        # retained in the reassembly state.
        if self.e2ee_enabled and self._crypto_key is not None:
            if text:
                if not is_encrypted_text(text):
                    logger.warning("Bale: received unencrypted text/caption in E2EE mode from %s", chat_id)
                    await self.send(chat_id, "درخواست نامعتبر است.")
                    return

                assembled = self._decrypt_or_buffer_text(
                    chat_id,
                    text,
                    media_urls=media_urls,
                    media_types=media_types,
                    message_type=message_type,
                )
                if assembled is _WAITING_TEXT_CHUNK:
                    return
                if assembled is None:
                    logger.warning("Bale: decryption failed for message from %s", chat_id)
                    await self.send(chat_id, "درخواست نامعتبر است.")
                    return
                text, media_urls, media_types, message_type = assembled
            elif not media_urls:
                return

        source = self.build_source(
            chat_id=chat_id,
            chat_name=chat_name,
            chat_type=chat_type,
            user_id=user_id,
            user_name=user_name,
            message_id=message_id,
        )

        event = MessageEvent(
            text=text,
            message_type=message_type,
            source=source,
            message_id=message_id,
            user_id=user_id,
            user_name=user_name,
            raw_message=message,
            media_urls=media_urls,
            media_types=media_types,
            timestamp=datetime.datetime.now(),
        )

        # Dispatch to Hermes core directly (commands, agent reasoning, tools)
        await self.handle_message(event)

    async def _handle_callback_query(self, callback_query: dict) -> None:
        """Route Bale inline buttons into Hermes' native resolvers/callbacks."""
        query_id = str(callback_query.get("id", "") or "")
        data = self._resolve_callback_token(str(callback_query.get("data", "") or ""))
        message = callback_query.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = str(chat.get("id", "") or "")
        from_obj = callback_query.get("from") or {}
        user_id = str(from_obj.get("id", "") or "")

        async def answer(text: str = "") -> None:
            if not query_id:
                return
            payload: Dict[str, Any] = {"callback_query_id": query_id}
            if text:
                payload["text"] = text[:180]
            try:
                await self._api_post("answerCallbackQuery", payload)
            except Exception:
                logger.debug("Bale: answerCallbackQuery failed", exc_info=True)

        if not self._callback_allowed(chat_id, user_id):
            await answer("⛔ مجاز نیستید.")
            return

        # Slash confirmations: sc:<once|always|cancel>:<confirm_id>
        if data.startswith("sc:"):
            parts = data.split(":", 2)
            if len(parts) != 3:
                await answer("Invalid callback")
                return
            choice, confirm_id = parts[1], parts[2]
            session_key = self._slash_confirm_state.pop(confirm_id, None)
            if not session_key:
                await answer("این درخواست منقضی شده.")
                return
            try:
                from tools import slash_confirm
                result_text = await slash_confirm.resolve(session_key, confirm_id, choice)
                await answer({
                    "once": "✅ تایید شد",
                    "always": "🔒 همیشه تایید",
                    "cancel": "❌ لغو شد",
                }.get(choice, "انجام شد"))
                if result_text:
                    await self.send(chat_id, str(result_text))
            except Exception:
                logger.exception("Bale: slash-confirm callback failed")
                await answer("خطا در تایید")
            return

        # Exec approval: ea:<once|session|always|deny>:<short-id>
        if data.startswith("ea:"):
            parts = data.split(":", 2)
            if len(parts) != 3:
                await answer("Invalid callback")
                return
            choice, approval_id = parts[1], parts[2]
            session_key = self._approval_state.pop(approval_id, None)
            if not session_key:
                await answer("این تایید منقضی شده.")
                return
            try:
                from tools.approval import resolve_gateway_approval
                count = resolve_gateway_approval(session_key, choice)
                if inspect.isawaitable(count):
                    count = await count
                await answer("✅ انجام شد" if count else "⌛ منقضی شده")
            except Exception:
                logger.exception("Bale: exec approval callback failed")
                await answer("خطا در تایید")
            return

        # Clarify: cl:<token>:<index|other>
        if data.startswith("cl:"):
            parts = data.split(":", 2)
            state = self._clarify_state.get(parts[1]) if len(parts) == 3 else None
            if not state:
                await answer("این سوال منقضی شده.")
                return
            token, choice_token = parts[1], parts[2]
            clarify_id = state["clarify_id"]
            if choice_token == "other":
                try:
                    from tools.clarify_gateway import mark_awaiting_text
                    ok = mark_awaiting_text(clarify_id)
                    if inspect.isawaitable(ok):
                        ok = await ok
                    await answer("✏️ پاسخ را تایپ کنید" if ok else "منقضی شده")
                except Exception:
                    logger.exception("Bale: clarify free-text callback failed")
                    await answer("خطا")
                return
            try:
                idx = int(choice_token)
                response = str(state["choices"][idx])
            except (ValueError, IndexError, TypeError):
                await answer("گزینه نامعتبر")
                return
            self._clarify_state.pop(token, None)
            try:
                from tools.clarify_gateway import resolve_gateway_clarify
                ok = resolve_gateway_clarify(clarify_id, response)
                if inspect.isawaitable(ok):
                    ok = await ok
                await answer(f"✓ {response[:80]}" if ok else "منقضی شده")
            except Exception:
                logger.exception("Bale: clarify callback failed")
                await answer("خطا")
            return

        # Flat choice picker: cp:<token>:<index>
        if data.startswith("cp:"):
            parts = data.split(":", 2)
            state = self._choice_picker_state.get(parts[1]) if len(parts) == 3 else None
            if not state:
                await answer("Picker expired")
                return
            try:
                choice = state["choices"][int(parts[2])]
                value = str(choice.get("value") if isinstance(choice, dict) else choice)
                result = await self._await_callback(state["callback"], chat_id, value)
                self._choice_picker_state.pop(parts[1], None)
                await answer("✓ انتخاب شد")
                if result:
                    await self.send(chat_id, str(result))
            except Exception:
                logger.exception("Bale: choice picker callback failed")
                await answer("خطا")
            return

        # Model picker: mp:<token>:p:<provider-index> / mp:<token>:m:<model-index>
        if data.startswith("mp:"):
            parts = data.split(":", 3)
            state = self._model_picker_state.get(parts[1]) if len(parts) == 4 else None
            if not state:
                await answer("Picker expired")
                return
            token, stage, raw_idx = parts[1], parts[2], parts[3]
            if stage == "p":
                try:
                    provider = state["providers"][int(raw_idx)]
                except (ValueError, IndexError):
                    await answer("Provider invalid")
                    return
                state["provider"] = provider
                models = list(provider.get("models") or [])[:48]
                state["models"] = models
                rows = []
                for i, model in enumerate(models):
                    model_id = str(model.get("id") or model.get("model") or model) if isinstance(model, dict) else str(model)
                    label = str(model.get("name") or model_id) if isinstance(model, dict) else model_id
                    rows.append([{"text": label.split("/")[-1][:42], "callback_data": f"mp:{token}:m:{i}"}])
                await answer("مدل را انتخاب کنید")
                if rows:
                    provider_name = str(provider.get("name") or provider.get("slug") or "Provider")
                    await self.send(chat_id, f"**{provider_name}**\nمدل را انتخاب کنید:", keyboard={"inline_keyboard": rows})
                return
            if stage == "m":
                try:
                    model = state["models"][int(raw_idx)]
                    model_id = str(model.get("id") or model.get("model") or model) if isinstance(model, dict) else str(model)
                    provider_slug = str(state["provider"].get("slug") or state["provider"].get("name") or "")
                    result = await self._await_callback(state["callback"], chat_id, model_id, provider_slug)
                    self._model_picker_state.pop(token, None)
                    await answer("✓ مدل عوض شد")
                    if result:
                        await self.send(chat_id, str(result))
                except Exception:
                    logger.exception("Bale: model picker callback failed")
                    await answer("خطا")
                return

        await answer()

    # ── Outbound sending (with strict E2EE) ───────────────────────────────

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        keyboard: Optional[Dict] = None,
    ) -> SendResult:
        """Send text with compressed E2/E2C and final-wire-size-aware chunking."""
        raw = str(content)
        if self.e2ee_enabled:
            if not self._crypto_key:
                logger.error("Bale: E2EE enabled but no crypto key found — aborting send")
                return SendResult(success=False, error="E2EE key missing", retryable=False)
            try:
                # E2/E2C uses compressed plaintext + AES-GCM + a 12-bit Unicode
                # transport alphabet.  We split by the *final wire length*, not
                # plaintext characters, so Persian/emoji cannot overflow Bale.
                wire_chunks = encrypt_text_chunks(raw, self._crypto_key, SAFE_E2EE_MESSAGE_LENGTH)
            except Exception as exc:
                logger.error("Bale: text encryption/chunking failed: %s", exc)
                return SendResult(success=False, error=str(exc), retryable=False)
        else:
            wire_chunks = [raw[i:i + SAFE_E2EE_MESSAGE_LENGTH] for i in range(0, len(raw), SAFE_E2EE_MESSAGE_LENGTH)] or [""]

        safe_keyboard = self._tokenize_keyboard(keyboard)
        last_result: Optional[SendResult] = None
        for idx, wire_text in enumerate(wire_chunks):
            # Reply anchor belongs to the first bubble; controls only to the final
            # bubble so a long response cannot duplicate approval buttons.
            chunk_reply = reply_to if idx == 0 else None
            chunk_keyboard = safe_keyboard if idx == len(wire_chunks) - 1 else None
            last_result = await self._raw_send(
                chat_id, wire_text, reply_to=chunk_reply, keyboard=chunk_keyboard
            )
            if not last_result.success:
                return last_result
        return last_result or SendResult(success=True)

    async def _raw_send(
        self,
        chat_id: str,
        text: str,
        reply_to: Optional[str] = None,
        keyboard: Optional[Dict] = None,
    ) -> SendResult:
        """Direct Bale sendMessage with reply_markup compatibility retry."""
        try:
            params: Dict[str, Any] = {"chat_id": str(chat_id), "text": text}
            if reply_to:
                params["reply_to_message_id"] = str(reply_to)
            if keyboard:
                # Bale deployments are inconsistent here: the Bot API accepts a
                # JSON-serialized reply_markup reliably, while some wrappers also
                # accept a nested object. Use the serialized form first so Hermes'
                # native approval/clarify buttons do not silently fall back to text.
                params["reply_markup"] = json.dumps(
                    keyboard, ensure_ascii=False, separators=(",", ":")
                )

            data = await self._api_post("sendMessage", params)
            if not data.get("ok") and keyboard:
                logger.warning(
                    "Bale: serialized reply_markup rejected (%s); retrying object form",
                    data.get("description", data),
                )
                retry_params = dict(params)
                retry_params["reply_markup"] = keyboard
                retry = await self._api_post("sendMessage", retry_params)
                if retry.get("ok"):
                    data = retry
                else:
                    logger.warning("Bale: inline keyboard rejected in both encodings: %s", retry)
                    return SendResult(success=False, error=str(retry.get("description", retry)))
            elif not data.get("ok"):
                return SendResult(success=False, error=str(data.get("description", data)))

            res = data.get("result", {})
            return SendResult(
                success=True,
                message_id=str(res.get("message_id", "")),
                raw_response=data,
            )
        except Exception as e:
            logger.error("Bale: send failed: %s", e)
            return SendResult(success=False, error=str(e), retryable=True)

    async def _send_encrypted_attachment_bytes(
        self,
        chat_id: str,
        payload: bytes,
        *,
        original_filename: str,
        mime_type: str,
        caption: str = "",
        reply_to: Optional[str] = None,
    ) -> SendResult:
        """Encrypt one attachment as BEE3FILE and send it as a generic document.

        A short caption is carried as compact E2 text inside Bale's caption field.
        The encrypted wire caption is capped below Bale's ~1024-character caption
        ceiling. If it does not fit, media is sent first with no caption and the
        logical caption follows as authenticated E2/E2C text bubbles.
        """
        if not self._crypto_key:
            return SendResult(success=False, error="E2EE key missing", retryable=False)

        max_size = _get_max_media_size()
        if len(payload) > max_size:
            limit_mb = max_size / (1024 * 1024)
            curr_mb = len(payload) / (1024 * 1024)
            return SendResult(
                success=False,
                error=f"File exceeds maximum size limit ({curr_mb:.1f}MB > {limit_mb:.0f}MB). Adjust BALE_MAX_FILE_SIZE_MB if needed.",
                retryable=False,
            )

        mime_type = mime_type or _sniff_mime(payload)
        original_filename = _normalize_original_filename(
            original_filename, mime_type, fallback_stem="file"
        )
        enc_bytes = encrypt_bytes(
            payload,
            self._crypto_key,
            filename=original_filename,
            mime_type=mime_type,
        )
        caption_chunks = encrypt_text_chunks(caption, self._crypto_key, SAFE_E2EE_CAPTION_LENGTH) if caption else []
        out_caption = caption_chunks[0] if len(caption_chunks) == 1 else ""

        url = f"{self.base_url}/sendDocument"
        max_attempts = 3
        last_error = None
        upload_timeout = aiohttp.ClientTimeout(total=180, connect=30, sock_read=90)

        for attempt in range(1, max_attempts + 1):
            data = aiohttp.FormData()
            data.add_field("chat_id", str(chat_id))
            data.add_field(
                "document",
                enc_bytes,
                filename=_outer_attachment_name(),
                content_type="application/octet-stream",
            )
            if out_caption:
                data.add_field("caption", out_caption)
            if reply_to:
                data.add_field("reply_to_message_id", str(reply_to))

            try:
                session = self._session
                close_session = False
                if session is None or session.closed:
                    session = aiohttp.ClientSession()
                    close_session = True
                try:
                    async with session.post(url, data=data, timeout=upload_timeout) as resp:
                        if resp.status >= 500:
                            last_error = f"Server returned HTTP {resp.status}"
                            if attempt < max_attempts:
                                logger.warning("Bale: upload 5xx congestion (attempt %d/%d), retrying...", attempt, max_attempts)
                                await asyncio.sleep(attempt * 2)
                                continue
                        res = await resp.json()
                        if not res.get("ok"):
                            return SendResult(success=False, error=str(res.get("description", res)))
                        msg = res.get("result", {})
                        result = SendResult(
                            success=True,
                            message_id=str(msg.get("message_id", "")),
                            raw_response=res,
                        )
                        if caption and len(caption_chunks) > 1:
                            follow = await self.send(chat_id, caption, reply_to=result.message_id or None)
                            if not follow.success:
                                logger.warning("Bale: media sent but long encrypted caption follow-up failed: %s", follow.error)
                        return result
                finally:
                    if close_session:
                        await session.close()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = str(e)
                logger.warning("Bale: encrypted attachment send attempt %d/%d failed (congestion/timeout): %s", attempt, max_attempts, e)
                if attempt < max_attempts:
                    await asyncio.sleep(attempt * 2.5)
            except Exception as e:
                logger.error("Bale: encrypted attachment send fatal error: %s", e)
                return SendResult(success=False, error=str(e), retryable=False)

        logger.error("Bale: encrypted attachment send failed after %d attempts: %s", max_attempts, last_error)
        return SendResult(success=False, error=f"Upload timed out / failed after {max_attempts} attempts: {last_error}", retryable=True)

    async def _send_plain_document_bytes(
        self,
        chat_id: str,
        payload: bytes,
        *,
        filename: str,
        mime_type: str = "application/octet-stream",
        caption: str = "",
        reply_to: Optional[str] = None,
    ) -> SendResult:
        data = aiohttp.FormData()
        data.add_field("chat_id", str(chat_id))
        data.add_field("document", payload, filename=filename, content_type=mime_type)
        if caption:
            data.add_field("caption", caption)
        if reply_to:
            data.add_field("reply_to_message_id", str(reply_to))
        try:
            async with self._session.post(f"{self.base_url}/sendDocument", data=data) as resp:
                res = await resp.json()
                if not res.get("ok"):
                    return SendResult(success=False, error=str(res.get("description", res)))
                msg = res.get("result", {})
                return SendResult(success=True, message_id=str(msg.get("message_id", "")), raw_response=res)
        except Exception as e:
            logger.error("Bale: document send failed: %s", e)
            return SendResult(success=False, error=str(e), retryable=True)

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send a document/file using the current Hermes `file_path=` contract."""
        if not file_path or not os.path.exists(file_path):
            return SendResult(success=False, error=f"File not found: {file_path}")
        try:
            payload = await asyncio.to_thread(Path(file_path).read_bytes)
            original_name = file_name or os.path.basename(file_path) or "file"
            mime_type = mimetypes.guess_type(original_name)[0] or _sniff_mime(payload)
            if self.e2ee_enabled:
                return await self._send_encrypted_attachment_bytes(
                    chat_id,
                    payload,
                    original_filename=original_name,
                    mime_type=mime_type,
                    caption=caption or "",
                    reply_to=reply_to,
                )
            return await self._send_plain_document_bytes(
                chat_id,
                payload,
                filename=original_name,
                mime_type=mime_type,
                caption=caption or "",
                reply_to=reply_to,
            )
        except Exception as e:
            logger.error("Bale: send_document failed: %s", e, exc_info=True)
            return SendResult(success=False, error=str(e), retryable=True)

    async def send_file(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Compatibility alias used by some Hermes delivery paths (e.g. /btw)."""
        return await self.send_document(
            chat_id=chat_id,
            file_path=file_path,
            caption=caption,
            file_name=file_name,
            reply_to=reply_to,
            metadata=metadata,
            **kwargs,
        )

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Fetch a remote image and preserve its real MIME/name inside BEE3FILE."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(image_url) as resp:
                    if resp.status != 200:
                        return SendResult(success=False, error=f"Failed to fetch image: HTTP {resp.status}")
                    payload = await resp.read()
                    mime_type = (resp.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
                    if not mime_type.startswith("image/"):
                        mime_type = _sniff_mime(payload, "image/jpeg")
                    url_name = Path(unquote(urlparse(image_url).path)).name
                    original_name = _normalize_original_filename(url_name, mime_type, fallback_stem="image")
            return await self.send_photo(
                chat_id,
                payload,
                caption=caption or "",
                reply_to=reply_to,
                filename=original_name,
                mime_type=mime_type,
                metadata=metadata,
            )
        except Exception as e:
            logger.error("Bale: send_image from url failed: %s", e, exc_info=True)
            return SendResult(success=False, error=str(e), retryable=True)

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send a local image while preserving its true metadata inside BEE3FILE."""
        if not image_path or not os.path.exists(image_path):
            return SendResult(success=False, error=f"File not found: {image_path}")
        try:
            payload = await asyncio.to_thread(Path(image_path).read_bytes)
            original_name = os.path.basename(image_path) or "image"
            mime_type = mimetypes.guess_type(original_name)[0] or _sniff_mime(payload, "image/jpeg")
            return await self.send_photo(
                chat_id,
                payload,
                caption=caption or "",
                reply_to=reply_to,
                filename=original_name,
                mime_type=mime_type,
                metadata=metadata,
            )
        except Exception as e:
            logger.error("Bale: send_image_file failed: %s", e, exc_info=True)
            return SendResult(success=False, error=str(e), retryable=True)

    async def send_photo(
        self,
        chat_id: str,
        photo: bytes,
        caption: str = "",
        reply_to: Optional[str] = None,
        *,
        filename: str = "",
        mime_type: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send photo; E2EE mode deliberately routes it as an encrypted document."""
        mime_type = mime_type or _sniff_mime(photo, "image/jpeg")
        filename = _normalize_original_filename(filename, mime_type, fallback_stem="photo")
        if self.e2ee_enabled:
            return await self._send_encrypted_attachment_bytes(
                chat_id,
                photo,
                original_filename=filename,
                mime_type=mime_type,
                caption=caption,
                reply_to=reply_to,
            )

        data = aiohttp.FormData()
        data.add_field("chat_id", str(chat_id))
        data.add_field("photo", photo, filename=filename, content_type=mime_type)
        if caption:
            data.add_field("caption", caption)
        if reply_to:
            data.add_field("reply_to_message_id", str(reply_to))
        try:
            async with self._session.post(f"{self.base_url}/sendPhoto", data=data) as resp:
                res = await resp.json()
                if not res.get("ok"):
                    return SendResult(success=False, error=str(res.get("description", res)))
                msg = res.get("result", {})
                return SendResult(success=True, message_id=str(msg.get("message_id", "")), raw_response=res)
        except Exception as e:
            logger.error("Bale: send_photo failed: %s", e, exc_info=True)
            return SendResult(success=False, error=str(e), retryable=True)

    async def send_video(
        self,
        chat_id: str,
        video_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """E2EE video is sent through the same secure document envelope."""
        if not video_path or not os.path.exists(video_path):
            return SendResult(success=False, error=f"File not found: {video_path}")
        payload = await asyncio.to_thread(Path(video_path).read_bytes)
        original_name = os.path.basename(video_path) or "video.mp4"
        mime_type = mimetypes.guess_type(original_name)[0] or _sniff_mime(payload, "video/mp4")
        if self.e2ee_enabled:
            return await self._send_encrypted_attachment_bytes(
                chat_id,
                payload,
                original_filename=original_name,
                mime_type=mime_type,
                caption=caption or "",
                reply_to=reply_to,
            )
        # Use document fallback for broad Bale compatibility in plaintext mode too.
        return await self._send_plain_document_bytes(
            chat_id,
            payload,
            filename=original_name,
            mime_type=mime_type,
            caption=caption or "",
            reply_to=reply_to,
        )

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send Hermes voice/audio output as an encrypted generic attachment in E2EE mode."""
        if not audio_path or not os.path.exists(audio_path):
            return SendResult(success=False, error=f"File not found: {audio_path}")
        payload = await asyncio.to_thread(Path(audio_path).read_bytes)
        original_name = os.path.basename(audio_path) or "audio.ogg"
        mime_type = mimetypes.guess_type(original_name)[0] or _sniff_mime(payload, "audio/ogg")
        if self.e2ee_enabled:
            return await self._send_encrypted_attachment_bytes(
                chat_id,
                payload,
                original_filename=original_name,
                mime_type=mime_type,
                caption=caption or "",
                reply_to=reply_to,
            )
        return await self._send_plain_document_bytes(
            chat_id,
            payload,
            filename=original_name,
            mime_type=mime_type,
            caption=caption or "",
            reply_to=reply_to,
        )

    async def send_animation(
        self,
        chat_id: str,
        animation_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Match Hermes' animation_url contract; E2EE still transports GIF as a secure document."""
        target = str(animation_url or "").strip()
        if target.startswith(("http://", "https://")):
            return await self.send_image(
                chat_id=chat_id,
                image_url=target,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
                **kwargs,
            )
        if target.startswith("file://"):
            target = unquote(urlparse(target).path)
        if target and os.path.exists(target):
            return await self.send_image_file(
                chat_id=chat_id,
                image_path=target,
                caption=caption,
                reply_to=reply_to,
                metadata=metadata,
                **kwargs,
            )
        return SendResult(success=False, error=f"Animation not found or unsupported URL: {animation_url}")

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Send chat action typing."""
        try:
            await self._api_post("sendChatAction", {"chat_id": str(chat_id), "action": "typing"})
        except Exception:
            pass

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "dm", "chat_id": str(chat_id)}

    # ── Interactive Helpers (Clarify / Approvals) ─────────────────────────

    # ── Interactive Helpers (Clarify / Approvals / Model Picker) ──────────

    async def send_choice_picker(
        self,
        chat_id: str,
        title: str,
        choices: list,
        session_key: str,
        on_choice_selected,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        token = secrets.token_hex(4)
        self._choice_picker_state[token] = {
            "choices": list(choices),
            "session_key": session_key,
            "callback": on_choice_selected,
        }
        rows = []
        for i, choice in enumerate(choices):
            if isinstance(choice, dict):
                label = str(choice.get("label") or choice.get("value") or "")
                if choice.get("is_current"):
                    label = f"✓ {label}"
            else:
                label = str(choice)
            rows.append([{"text": label[:48], "callback_data": f"cp:{token}:{i}"}])
        result = await self.send(chat_id, title, keyboard={"inline_keyboard": rows})
        if not result.success:
            self._choice_picker_state.pop(token, None)
        return result

    async def send_model_picker(
        self,
        chat_id: str,
        providers: list,
        current_model: str,
        current_provider: str,
        session_key: str,
        on_model_selected,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        token = secrets.token_hex(4)
        provider_list = list(providers)
        self._model_picker_state[token] = {
            "providers": provider_list,
            "session_key": session_key,
            "callback": on_model_selected,
            "current_model": current_model,
            "current_provider": current_provider,
        }
        rows = []
        for i, provider in enumerate(provider_list[:48]):
            label = str(provider.get("name") or provider.get("slug") or "provider")
            if provider.get("is_current"):
                label = f"✓ {label}"
            rows.append([{"text": label[:48], "callback_data": f"mp:{token}:p:{i}"}])
        text = (
            "⚙️ **Model Configuration**\n\n"
            f"Current: `{current_model or 'unknown'}`\n"
            f"Provider: `{current_provider or 'unknown'}`\n\n"
            "Select a provider:"
        )
        result = await self.send(chat_id, text, keyboard={"inline_keyboard": rows})
        if not result.success:
            self._model_picker_state.pop(token, None)
        return result

    async def send_clarify(
        self,
        chat_id: str,
        question: str,
        choices: Optional[List[str]],
        clarify_id: str,
        session_key: str,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        choice_list = list(choices or [])
        token = secrets.token_hex(4)
        self._clarify_state[token] = {
            "clarify_id": clarify_id,
            "session_key": session_key,
            "choices": choice_list,
        }
        rows = [
            [{"text": str(choice)[:48], "callback_data": f"cl:{token}:{idx}"}]
            for idx, choice in enumerate(choice_list)
        ]
        if choice_list:
            rows.append([{"text": "✏️ Other", "callback_data": f"cl:{token}:other"}])
        result = await self.send(
            chat_id,
            f"❓ {question}",
            keyboard={"inline_keyboard": rows} if rows else None,
        )
        if not result.success:
            self._clarify_state.pop(token, None)
        return result

    async def send_exec_approval(
        self,
        chat_id: str,
        command: str,
        session_key: str,
        description: str = "dangerous command",
        metadata: Optional[Dict[str, Any]] = None,
        allow_permanent: bool = True,
        allow_session: bool = True,
        smart_denied: bool = False,
        **kwargs,
    ) -> SendResult:
        approval_id = secrets.token_hex(4)
        self._approval_state[approval_id] = session_key
        buttons = [{"text": "✅ Allow Once", "callback_data": f"ea:once:{approval_id}"}]
        if not smart_denied and allow_session:
            buttons.append({"text": "✅ Session", "callback_data": f"ea:session:{approval_id}"})
            if allow_permanent:
                buttons.append({"text": "🔒 Always", "callback_data": f"ea:always:{approval_id}"})
        buttons.append({"text": "❌ Deny", "callback_data": f"ea:deny:{approval_id}"})
        rows = [buttons[i:i + 2] for i in range(0, len(buttons), 2)]
        text = f"⚠️ **Command Approval Required**\n\n```\n{command}\n```"
        if description:
            text += f"\n\n{description}"
        result = await self.send(chat_id, text, keyboard={"inline_keyboard": rows})
        if not result.success:
            self._approval_state.pop(approval_id, None)
        return result

    async def send_slash_confirm(
        self,
        chat_id: str,
        title: str,
        message: str,
        session_key: str,
        confirm_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Native Bale confirmation for /new, /reset, /undo and similar commands."""
        confirm_id = str(confirm_id)
        self._slash_confirm_state[confirm_id] = session_key
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve Once", "callback_data": f"sc:once:{confirm_id}"},
                    {"text": "🔒 Always Approve", "callback_data": f"sc:always:{confirm_id}"},
                ],
                [{"text": "❌ Cancel", "callback_data": f"sc:cancel:{confirm_id}"}],
            ]
        }
        result = await self.send(chat_id, message or title, keyboard=keyboard)
        if not result.success:
            self._slash_confirm_state.pop(confirm_id, None)
        return result

    # ── Internal HTTP Helpers ─────────────────────────────────────────────

    async def _download_file(self, file_id: str) -> Optional[bytes]:
        """Download file content from Bale using file_id with retry on congestion/timeout."""
        max_attempts = 3
        dl_timeout = aiohttp.ClientTimeout(total=180, connect=30, sock_read=90)
        for attempt in range(1, max_attempts + 1):
            try:
                info = await self._api_get("getFile", {"file_id": file_id})
                if not info.get("ok"):
                    return None
                path = info.get("result", {}).get("file_path")
                if not path:
                    return None
                url = f"{self.file_url}/{path}"
                session = self._session
                close_session = False
                if session is None or session.closed:
                    session = aiohttp.ClientSession()
                    close_session = True
                try:
                    async with session.get(url, timeout=dl_timeout) as resp:
                        if resp.status == 200:
                            return await resp.read()
                        elif resp.status >= 500 and attempt < max_attempts:
                            logger.warning("Bale: download 5xx server error, retrying attempt %d/%d...", attempt, max_attempts)
                            await asyncio.sleep(attempt * 2)
                            continue
                finally:
                    if close_session:
                        await session.close()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning("Bale: download file %s attempt %d/%d failed (congestion/timeout): %s", file_id, attempt, max_attempts, e)
                if attempt < max_attempts:
                    await asyncio.sleep(attempt * 2.5)
            except Exception as e:
                logger.error("Bale: error downloading file %s: %s", file_id, e)
                return None
        return None

    async def _api_get(self, method: str, params: Optional[Dict] = None) -> dict:
        url = f"{self.base_url}/{method}"
        if self._session and not self._session.closed:
            async with self._session.get(url, params=params) as resp:
                return await resp.json()
        async with aiohttp.ClientSession() as s:
            async with s.get(url, params=params) as resp:
                return await resp.json()

    async def _api_post(self, method: str, json_data: Optional[Dict] = None) -> dict:
        url = f"{self.base_url}/{method}"
        if self._session and not self._session.closed:
            async with self._session.post(url, json=json_data) as resp:
                return await resp.json()
        async with aiohttp.ClientSession() as s:
            async with s.post(url, json=json_data) as resp:
                return await resp.json()


# ── Hooks ─────────────────────────────────────────────────────────────────

def check_requirements() -> bool:
    try:
        import aiohttp  # noqa: F401
        import cryptography  # noqa: F401
        return bool(os.getenv("BALE_BOT_TOKEN", "").strip())
    except ImportError:
        return False


def validate_config(config) -> bool:
    return bool(os.getenv("BALE_BOT_TOKEN", "").strip())


def is_connected(config) -> bool:
    return bool(os.getenv("BALE_BOT_TOKEN", "").strip())


def _env_enablement() -> Optional[dict]:
    token = os.getenv("BALE_BOT_TOKEN", "").strip()
    if token:
        return {"token": token, "enabled": True}
    return None


async def _standalone_send(chat_id: str, text: str, **kwargs) -> dict:
    """Cron/notification sender using the same wire-safe E2EE transport as the live adapter."""
    token = os.getenv("BALE_BOT_TOKEN", "").strip()
    if not token:
        return {"error": "BALE_BOT_TOKEN not set"}
    raw_key = os.getenv("BALE_ENCRYPTION_KEY", "").strip()
    raw = str(text)
    if raw_key:
        k = derive_key(raw_key)
        try:
            chunks = encrypt_text_chunks(raw, k, SAFE_E2EE_MESSAGE_LENGTH)
        except Exception as exc:
            return {"ok": False, "error": f"E2EE text encode failed: {exc}"}
    else:
        chunks = [raw[i:i + SAFE_E2EE_MESSAGE_LENGTH] for i in range(0, len(raw), SAFE_E2EE_MESSAGE_LENGTH)] or [""]

    last: dict = {"ok": True}
    async with aiohttp.ClientSession() as s:
        url = f"{BALE_API_BASE}{token}/sendMessage"
        for chunk in chunks:
            async with s.post(url, json={"chat_id": str(chat_id), "text": chunk}) as r:
                try:
                    last = await r.json()
                except Exception:
                    return {"ok": False, "error": f"HTTP {r.status}"}
                if not last.get("ok"):
                    return last
    return last


def interactive_setup() -> None:
    pass
