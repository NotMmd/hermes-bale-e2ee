const ext = globalThis.browser ?? globalThis.chrome;
const KEY = "bale_e2ee_passphrase";

function storageGet(keys) {
  if (globalThis.browser?.storage?.local) return globalThis.browser.storage.local.get(keys);
  return new Promise((resolve, reject) => {
    ext.storage.local.get(keys, (result) => {
      const err = globalThis.chrome?.runtime?.lastError;
      if (err) reject(err); else resolve(result || {});
    });
  });
}

function storageSet(value) {
  if (globalThis.browser?.storage?.local) return globalThis.browser.storage.local.set(value);
  return new Promise((resolve, reject) => {
    ext.storage.local.set(value, () => {
      const err = globalThis.chrome?.runtime?.lastError;
      if (err) reject(err); else resolve();
    });
  });
}

function storageRemove(key) {
  if (globalThis.browser?.storage?.local) return globalThis.browser.storage.local.remove(key);
  return new Promise((resolve, reject) => {
    ext.storage.local.remove(key, () => {
      const err = globalThis.chrome?.runtime?.lastError;
      if (err) reject(err); else resolve();
    });
  });
}

async function fingerprint(value) {
  if (!value) return "—";
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  const hex = Array.from(digest.slice(0, 6), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`;
}

function setState(active) {
  const state = document.getElementById("state");
  const text = document.getElementById("stateText");
  state.classList.toggle("active", active);
  text.textContent = active ? "فعال" : "بدون کلید";
}

function showNotice(text, type = "ok") {
  const notice = document.getElementById("notice");
  notice.className = `notice ${type}`;
  notice.textContent = text;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => { notice.className = "notice"; }, 2600);
}

async function refreshMeta(value) {
  setState(Boolean(value));
  document.getElementById("fingerprint").textContent = await fingerprint(value);
}

document.addEventListener("DOMContentLoaded", async () => {
  const input = document.getElementById("passphrase");
  const save = document.getElementById("saveBtn");
  const clear = document.getElementById("clearBtn");
  const toggle = document.getElementById("toggleVisibility");
  const eyeOpen = document.getElementById("eyeOpen");
  const eyeClosed = document.getElementById("eyeClosed");

  try {
    const data = await storageGet([KEY]);
    const value = typeof data[KEY] === "string" ? data[KEY] : "";
    input.value = value;
    await refreshMeta(value.trim());
  } catch (_) {
    showNotice("خواندن تنظیمات ناموفق بود", "error");
  }

  toggle.addEventListener("click", () => {
    const visible = input.type === "text";
    input.type = visible ? "password" : "text";
    eyeOpen.hidden = !visible;
    eyeClosed.hidden = visible;
    toggle.title = visible ? "نمایش رمز" : "مخفی کردن رمز";
    toggle.setAttribute("aria-label", toggle.title);
    input.focus();
  });

  input.addEventListener("input", async () => {
    document.getElementById("fingerprint").textContent = await fingerprint(input.value.trim());
  });

  save.addEventListener("click", async () => {
    const value = input.value.trim();
    if (!value) {
      showNotice("اول یک Passphrase وارد کن", "error");
      return;
    }
    try {
      await storageSet({ [KEY]: value });
      await refreshMeta(value);
      showNotice("کلید ذخیره شد و همان لحظه اعمال شد");
    } catch (_) {
      showNotice("ذخیره کلید ناموفق بود", "error");
    }
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") save.click();
  });

  clear.addEventListener("click", async () => {
    try {
      await storageRemove(KEY);
      input.value = "";
      input.type = "password";
      eyeOpen.hidden = false;
      eyeClosed.hidden = true;
      await refreshMeta("");
      showNotice("کلید محلی پاک شد");
    } catch (_) {
      showNotice("پاک کردن کلید ناموفق بود", "error");
    }
  });
});
