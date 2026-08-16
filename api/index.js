// =====================================================================
// Fox Brain — دروازه مدل زبانی
//
// نقش:
//   کلیدهای مدل اینجا نگهداری می‌شوند، نه روی سرور ایران.
//   سرور فقط به این دروازه وصل می‌شود و دروازه به مدل‌ها.
//
// چرا لازم است:
//   سرور ایران به سرویس‌های مدل دسترسی ندارد ولی به vercel.app دارد.
//
// امنیت:
//   بدون کلید مشترک هیچ درخواستی پذیرفته نمی‌شود، وگرنه هر کسی
//   می‌تواند سهمیه رایگان را مصرف کند.
// =====================================================================

export const config = { runtime: "edge" };

const HARD_TIMEOUT_MS = 45000;

// ترتیب تلاش. اگر یکی سهمیه‌اش تمام شد، بعدی امتحان می‌شود.
// نام مدل‌ها با متغیر محیطی قابل تغییر است.
// دلیل: ارائه‌دهندگان مرتب مدل‌ها را بازنشسته می‌کنند و اگر نام در کد
// ثابت باشد، روزی بی‌صدا از کار می‌افتد. تجربه واقعی: یک نام مدل
// یک‌ساله «no longer available» شد و فقط زنجیره جایگزین نجاتش داد.
const PROVIDERS = [
  {
    name: "gemini",
    envKey: "GEMINI_API_KEY",
    url: "https://generativelanguage.googleapis.com/v1beta/models/MODEL:generateContent",
    // اگر این نام هم منسوخ شد، متغیر GEMINI_MODEL را تنظیم کن.
    // فهرست زنده: مسیر /models را صدا بزن.
    model: process.env.GEMINI_MODEL || "gemini-3.5-flash",
    style: "gemini",
    good_for: "تحلیل سنگین، زمینه بزرگ، دستورپذیری بهتر"
  },
  {
    name: "groq",
    envKey: "GROQ_API_KEY",
    url: "https://api.groq.com/openai/v1/chat/completions",
    model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
    style: "openai",
    good_for: "سریع، کارهای ساده و پرتکرار"
  },
  {
    name: "openrouter",
    envKey: "OPENROUTER_API_KEY",
    url: "https://openrouter.ai/api/v1/chat/completions",
    model: process.env.OPENROUTER_MODEL || "meta-llama/llama-3.3-70b-instruct:free",
    style: "openai",
    good_for: "نظر دوم با مدل متفاوت"
  },
  {
    name: "cerebras",
    envKey: "CEREBRAS_API_KEY",
    url: "https://api.cerebras.ai/v1/chat/completions",
    model: process.env.CEREBRAS_MODEL || "llama-3.3-70b",
    style: "openai",
    good_for: "توان بالا"
  }
];

export default async function handler(req) {
  const url = new URL(req.url);

  if (url.pathname === "/health" || url.pathname === "/") {
    const ready = PROVIDERS
      .filter(p => Boolean(process.env[p.envKey]))
      .map(p => p.name);
    return json({
      ok: true,
      service: "fox-brain",
      providers_ready: ready,
      providers_missing: PROVIDERS.filter(p => !process.env[p.envKey]).map(p => p.name),
      models: Object.fromEntries(PROVIDERS.filter(p => process.env[p.envKey]).map(p => [p.name, p.model])),
      auth_required: Boolean(process.env.BRAIN_KEY)
    });
  }

  // فهرست زنده مدل‌های در دسترس — برای وقتی نام مدلی منسوخ شد
  if (url.pathname === "/models") {
    const key = process.env.GEMINI_API_KEY;
    if (!key) return json({ ok: false, error: "GEMINI_API_KEY not set" }, 503);
    try {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`
      );
      const d = await r.json();
      const names = (d.models || [])
        .filter(m => (m.supportedGenerationMethods || []).includes("generateContent"))
        .map(m => m.name.replace("models/", ""))
        .filter(n => n.includes("flash") || n.includes("pro"));
      const gem = PROVIDERS.find(p => p.name === "gemini");
      return json({ ok: true, current: gem ? gem.model : null, available: names });
    } catch (e) {
      return json({ ok: false, error: String(e.message || e) }, 502);
    }
  }

  if (url.pathname !== "/ask") {
    return json({ ok: false, error: "not found" }, 404);
  }

  // احراز هویت — بدون این، سهمیه رایگان قابل سوءاستفاده است
  const expected = process.env.BRAIN_KEY;
  if (!expected) return json({ ok: false, error: "BRAIN_KEY is not set" }, 503);
  if (req.headers.get("x-brain-key") !== expected) {
    return json({ ok: false, error: "unauthorized" }, 401);
  }

  if (req.method !== "POST") {
    return json({ ok: false, error: "method not allowed" }, 405);
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ ok: false, error: "invalid json" }, 400);
  }

  const system = String(body.system || "").slice(0, 20000);
  const prompt = String(body.prompt || "").slice(0, 60000);
  const prefer = body.prefer ? String(body.prefer) : null;

  if (!prompt) return json({ ok: false, error: "prompt is empty" }, 400);

  // ترتیب تلاش: اگر ارائه‌دهنده خاصی خواسته شده، اول او
  let order = PROVIDERS.filter(p => process.env[p.envKey]);
  if (prefer) {
    order = [
      ...order.filter(p => p.name === prefer),
      ...order.filter(p => p.name !== prefer)
    ];
  }

  if (order.length === 0) {
    return json({ ok: false, error: "no provider configured" }, 503);
  }

  const tried = [];

  for (const p of order) {
    try {
      const text = await callProvider(p, system, prompt);
      if (text && text.trim()) {
        return json({
          ok: true,
          provider: p.name,
          model: p.model,
          tried,
          answer: text.trim()
        });
      }
      tried.push({ provider: p.name, error: "empty answer" });
    } catch (e) {
      tried.push({ provider: p.name, error: String(e.message || e).slice(0, 200) });
    }
  }

  return json({ ok: false, error: "all providers failed", tried }, 502);
}

async function callProvider(p, system, prompt) {
  const key = process.env[p.envKey];
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), HARD_TIMEOUT_MS);

  try {
    let res;

    if (p.style === "gemini") {
      const target = p.url.replace("MODEL", p.model) + `?key=${encodeURIComponent(key)}`;
      const payload = {
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 2048 }
      };
      if (system) payload.systemInstruction = { parts: [{ text: system }] };

      res = await fetch(target, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: ctrl.signal
      });

      if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 150)}`);
      const d = await res.json();
      const parts = d?.candidates?.[0]?.content?.parts || [];
      return parts.map(x => x.text || "").join("");
    }

    // سبک سازگار با OpenAI
    const messages = [];
    if (system) messages.push({ role: "system", content: system });
    messages.push({ role: "user", content: prompt });

    res = await fetch(p.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${key}`
      },
      body: JSON.stringify({
        model: p.model,
        messages,
        temperature: 0.2,
        max_tokens: 2048
      }),
      signal: ctrl.signal
    });

    if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 150)}`);
    const d = await res.json();
    return d?.choices?.[0]?.message?.content || "";
  } finally {
    clearTimeout(timer);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });
}
