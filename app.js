const API_URL = "/image-api";

const uploadForm = document.getElementById("uploadForm");
const uploadFile = document.getElementById("uploadFile");
const fileLabel = document.getElementById("fileLabel");

const fetchForm = document.getElementById("fetchForm");
const fetchUrl = document.getElementById("fetchUrl");

const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const errorBox = document.getElementById("errorBox");

const previewImg = document.getElementById("previewImg");
const directUrl = document.getElementById("directUrl");
const pageUrl = document.getElementById("pageUrl");
const directOpen = document.getElementById("directOpen");
const pageOpen = document.getElementById("pageOpen");
const meta = document.getElementById("meta");
const apiLabel = document.getElementById("apiLabel");

apiLabel.textContent = API_URL;

function setStatus(kind, text) {
  statusEl.className = `status ${kind}`;
  statusEl.textContent = text;
}

function showError(err) {
  resultEl.classList.add("hidden");
  errorBox.classList.remove("hidden");
  errorBox.textContent = typeof err === "string" ? err : JSON.stringify(err, null, 2);
  setStatus("err", "Error");
}

function showResult(data) {
  errorBox.classList.add("hidden");
  resultEl.classList.remove("hidden");

  directUrl.value = data.direct_url || "";
  pageUrl.value = data.page_url || "";

  directOpen.href = data.direct_url || "#";
  pageOpen.href = data.page_url || "#";

  previewImg.src = data.direct_url || "";

  const bits = [];
  if (data.id) bits.push(`id: ${data.id}`);
  if (data.mime) bits.push(`type: ${data.mime}`);
  if (typeof data.size_bytes === "number") bits.push(`size: ${formatBytes(data.size_bytes)}`);
  meta.textContent = bits.join(" • ");

  setStatus("ok", "Done");
}

function formatBytes(n) {
  if (!Number.isFinite(n)) return "";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const id = btn.getAttribute("data-copy");
  const el = document.getElementById(id);
  if (!el) return;
  try {
    await navigator.clipboard.writeText(el.value || "");
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = "Copy"), 900);
  } catch {
    btn.textContent = "Copy failed";
    setTimeout(() => (btn.textContent = "Copy"), 900);
  }
});

uploadFile.addEventListener("change", () => {
  const f = uploadFile.files && uploadFile.files[0];
  fileLabel.textContent = f ? f.name : "Choose an image…";
});

uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = uploadFile.files && uploadFile.files[0];
  if (!f) return;

  setStatus("busy", "Uploading…");
  errorBox.classList.add("hidden");

  const fd = new FormData();
  fd.append("file", f);

  try {
    const res = await fetch(`${API_URL}/upload`, { method: "POST", body: fd });
    const text = await res.text();
    if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
    const data = JSON.parse(text);
    showResult(data);
  } catch (err) {
    showError(err?.message || String(err));
  }
});

fetchForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = (fetchUrl.value || "").trim();
  if (!url) return;

  setStatus("busy", "Fetching…");
  errorBox.classList.add("hidden");

  const body = new URLSearchParams();
  body.set("url", url);

  try {
    const res = await fetch(`${API_URL}/fetch`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
    const data = JSON.parse(text);
    showResult(data);
  } catch (err) {
    showError(err?.message || String(err));
  }
});

setStatus("idle", "Idle");
