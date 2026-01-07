const isAdminUi =
  location.pathname.startsWith("/admin") ||
  location.pathname.includes("admin-dashboard")

const API_URL = isAdminUi ? "/image-api" : "/user-image-api"

const uploadForm = document.getElementById("uploadForm")
const uploadFile = document.getElementById("uploadFile")
const fileLabel = document.getElementById("fileLabel")

const fetchForm = document.getElementById("fetchForm")
const fetchUrl = document.getElementById("fetchUrl")

const statusEl = document.getElementById("status")
const resultEl = document.getElementById("result")
const errorBox = document.getElementById("errorBox")

const previewImg = document.getElementById("previewImg")
const directUrl = document.getElementById("directUrl")
const pageUrl = document.getElementById("pageUrl")
const directOpen = document.getElementById("directOpen")
const pageOpen = document.getElementById("pageOpen")
const meta = document.getElementById("meta")
const apiLabel = document.getElementById("apiLabel")

if (apiLabel) apiLabel.textContent = API_URL

function setStatus(kind, text) {
  if (!statusEl) return
  statusEl.className = `status ${kind}`
  statusEl.textContent = text
}

function formatBytes(n) {
  if (!Number.isFinite(n)) return ""
  const units = ["B", "KB", "MB", "GB"]
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`
}

function showError(err) {
  if (resultEl) resultEl.classList.add("hidden")
  if (errorBox) {
    errorBox.classList.remove("hidden")
    errorBox.textContent = typeof err === "string" ? err : JSON.stringify(err, null, 2)
  }
  setStatus("err", "Error")
}

function showResult(data) {
  if (errorBox) errorBox.classList.add("hidden")
  if (resultEl) resultEl.classList.remove("hidden")

  if (directUrl) directUrl.value = data.direct_url || ""
  if (pageUrl) pageUrl.value = data.page_url || ""

  if (directOpen) directOpen.href = data.direct_url || "#"
  if (pageOpen) pageOpen.href = data.page_url || "#"

  if (previewImg) previewImg.src = data.direct_url || ""

  const bits = []
  if (data.id) bits.push(`id: ${data.id}`)
  if (data.mime) bits.push(`type: ${data.mime}`)
  if (typeof data.size_bytes === "number") bits.push(`size: ${formatBytes(data.size_bytes)}`)
  if (meta) meta.textContent = bits.join(" • ")

  setStatus("ok", "Done")
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy]")
  if (!btn) return
  const id = btn.getAttribute("data-copy")
  const el = document.getElementById(id)
  if (!el) return
  try {
    await navigator.clipboard.writeText(el.value || "")
    btn.textContent = "Copied"
    setTimeout(() => (btn.textContent = "Copy"), 900)
  } catch {
    btn.textContent = "Copy failed"
    setTimeout(() => (btn.textContent = "Copy"), 900)
  }
})

if (uploadFile) {
  uploadFile.addEventListener("change", () => {
    const f = uploadFile.files && uploadFile.files[0]
    if (fileLabel) fileLabel.textContent = f ? f.name : "Choose an image…"
  })
}

if (uploadForm) {
  uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const f = uploadFile && uploadFile.files && uploadFile.files[0]
    if (!f) return

    setStatus("busy", "Uploading…")
    if (errorBox) errorBox.classList.add("hidden")

    const fd = new FormData()
    fd.append("file", f)

    try {
      const res = await fetch(`${API_URL}/upload`, {
        method: "POST",
        body: fd,
        credentials: "include"
      })

      const text = await res.text()
      if (!res.ok) throw new Error(`HTTP ${res.status}\n${text}`)

      let data
      try {
        data = JSON.parse(text)
      } catch {
        throw new Error(`Expected JSON but got:\n${text}`)
      }

      showResult(data)
    } catch (err) {
      showError(err?.message || String(err))
    }
  })
}

if (fetchForm) {
  fetchForm.addEventListener("submit", async (e) => {
    e.preventDefault()
    const url = (fetchUrl && fetchUrl.value ? fetchUrl.value : "").trim()
    if (!url) return

    setStatus("busy", "Fetching…")
    if (errorBox) errorBox.classList.add("hidden")

    const body = new URLSearchParams()
    body.set("url", url)

    try {
      const res = await fetch(`${API_URL}/fetch`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        credentials: "include"
      })

      const text = await res.text()
      if (!res.ok) throw new Error(`HTTP ${res.status}\n${text}`)

      let data
      try {
        data = JSON.parse(text)
      } catch {
        throw new Error(`Expected JSON but got:\n${text}`)
      }

      showResult(data)
    } catch (err) {
      showError(err?.message || String(err))
    }
  })
}

setStatus("idle", "Idle")
