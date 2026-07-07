// Thin API client for the FastAPI backend (proxied through Vite at /api).

export async function getSamples() {
  const res = await fetch("/api/samples");
  if (!res.ok) throw new Error("failed to load samples");
  return res.json();
}

export async function getRules() {
  const res = await fetch("/api/rules");
  if (!res.ok) throw new Error("failed to load rules");
  return res.json();
}

export async function analyzeSample(source) {
  const res = await fetch(`/api/analyze?source=${encodeURIComponent(source)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "analysis failed");
  }
  return res.json();
}

export async function analyzeUpload(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/analyze", { method: "POST", body: form });
  if (!res.ok) throw new Error("upload analysis failed");
  return res.json();
}
