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
  // ترتیب = اولویت. اولی که کلیدش تنظیم شده باشد اول امتحان می‌شود.
  // نام مدل‌ها با متغیر محیطی قابل تغییر است، چون ارائه‌دهندگان
  // مرتب مدل‌ها را بازنشسته می‌کنند.
  {
    name: "gemini",
    envKey: "GEMINI_API_KEY",
    url: "https://generativelanguage.googleapis.com/v1beta/models/MODEL:generateContent",
    model: process.env.GEMINI_MODEL || "gemini-3.5-flash",
    style: "gemini",
    tier: "strong",
    good_for: "دستورپذیری بالا، زمینه بزرگ"
  },
  {
    name: "groq",
    envKey: "GROQ_API_KEY",
    url: "https://api.groq.com/openai/v1/chat/completions",
    model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
    style: "openai",
    tier: "fast",
    good_for: "سریع‌ترین، مناسب کار پرتکرار"
  },
  {
    name: "cerebras",
    envKey: "CEREBRAS_API_KEY",
    url: "https://api.cerebras.ai/v1/chat/completions",
    model: process.env.CEREBRAS_MODEL || "llama-3.3-70b",
    style: "openai",
    tier: "strong",
    good_for: "سهمیه توکن روزانه بسیار بالا"
  },
  {
    name: "mistral",
    envKey: "MISTRAL_API_KEY",
    url: "https://api.mistral.ai/v1/chat/completions",
    model: process.env.MISTRAL_MODEL || "mistral-large-latest",
    style: "openai",
    tier: "strong",
    good_for: "سهمیه ماهانه بزرگ"
  },
  {
    name: "nvidia",
    envKey: "NVIDIA_API_KEY",
    url: "https://integrate.api.nvidia.com/v1/chat/completions",
    model: process.env.NVIDIA_MODEL || "meta/llama-3.3-70b-instruct",
    style: "openai",
    tier: "strong",
    good_for: "نرخ درخواست بالا"
  },
  {
    name: "github",
    envKey: "GITHUB_MODELS_TOKEN",
    url: "https://models.github.ai/inference/chat/completions",
    model: process.env.GITHUB_MODEL || "openai/gpt-4o",
    style: "openai",
    tier: "strong",
    good_for: "دسترسی به مدل‌های سطح بالا"
  },
  {
    name: "openrouter",
    envKey: "OPENROUTER_API_KEY",
    url: "https://openrouter.ai/api/v1/chat/completions",
    model: process.env.OPENROUTER_MODEL || "meta-llama/llama-3.3-70b-instruct",
    style: "openai",
    tier: "varied",
    good_for: "دسترسی به مدل‌های متنوع با یک کلید"
  },
  {
    name: "zai",
    envKey: "ZAI_API_KEY",
    url: "https://api.z.ai/api/paas/v4/chat/completions",
    model: process.env.ZAI_MODEL || "glm-4.7-flash",
    style: "openai",
    tier: "fast",
    good_for: "جایگزین سبک و سریع"
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

  // ---------------------------------------------------------------
  // تست تک‌تک ارائه‌دهندگان
  // دلیل: تنظیم‌بودن کلید به معنی کارکردن نیست. نام مدل ممکن است
  // منسوخ شده باشد یا حساب دسترسی نداشته باشد.
  // ---------------------------------------------------------------
  if (url.pathname === "/test") {
    const expected = process.env.BRAIN_KEY;
    if (!expected || req.headers.get("x-brain-key") !== expected) {
      return json({ ok: false, error: "unauthorized" }, 401);
    }

    const ready = PROVIDERS.filter(p => process.env[p.envKey]);
    const started = Date.now();

    const results = await Promise.all(
      ready.map(async p => {
        const t0 = Date.now();
        try {
          const text = await callProvider(
            p,
            "پاسخ کوتاه بده.",
            "فقط عدد چهار را بنویس، بدون هیچ توضیحی."
          );
          const ms = Date.now() - t0;
          const answer = (text || "").trim();
          return {
            provider: p.name,
            model: p.model,
            ok: Boolean(answer),
            ms,
            sample: answer.slice(0, 40)
          };
        } catch (e) {
          return {
            provider: p.name,
            model: p.model,
            ok: false,
            ms: Date.now() - t0,
            error: String(e.message || e).slice(0, 160)
          };
        }
      })
    );

    const working = results.filter(r => r.ok);
    const broken = results.filter(r => !r.ok);

    return json({
      ok: true,
      total_ms: Date.now() - started,
      working: working.length,
      broken: broken.length,
      results: results.sort((a, b) => (a.ok === b.ok ? a.ms - b.ms : a.ok ? -1 : 1))
    });
  }

  if (url.pathname !== "/ask" && url.pathname !== "/consult") {
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

  // ---------------------------------------------------------------
  // ترتیب تلاش بر اساس نوع کار.
  //
  // داده واقعی از تست میدانی: سریع‌ترین ارائه‌دهنده حدود صد میلی‌ثانیه
  // و کندترین حدود چهار ثانیه پاسخ می‌دهد. ولی سریع‌ترین همیشه
  // بهترین دستورپذیری را ندارد.
  //
  // پس برای کار ساده سرعت مهم است و برای کار دقیق کیفیت.
  // ---------------------------------------------------------------
  const mode = body.mode || "balanced";

  const SPEED_ORDER   = ["groq", "mistral", "openrouter", "cerebras", "gemini", "github", "zai", "nvidia"];
  const QUALITY_ORDER = ["gemini", "github", "mistral", "cerebras", "openrouter", "groq", "nvidia", "zai"];

  const ranking = mode === "fast" ? SPEED_ORDER
                : mode === "quality" ? QUALITY_ORDER
                : ["gemini", "groq", "mistral", "openrouter", "cerebras", "github", "zai", "nvidia"];

  let order = PROVIDERS
    .filter(p => process.env[p.envKey])
    .sort((a, b) => {
      const ia = ranking.indexOf(a.name);
      const ib = ranking.indexOf(b.name);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });

  // ترجیح صریح کاربر بر همه چیز اولویت دارد
  if (prefer) {
    order = [
      ...order.filter(p => p.name === prefer),
      ...order.filter(p => p.name !== prefer)
    ];
  }

  if (order.length === 0) {
    return json({ ok: false, error: "no provider configured" }, 503);
  }

  // ---------------------------------------------------------------
  // حالت مشورت چندمدلی — برای تصمیم‌های پرریسک
  // دو ارائه‌دهنده مستقل هم‌زمان پرسیده می‌شوند و نتیجه مقایسه می‌شود.
  // اختلاف نظر مدل‌ها یک سیگنال مهم است، نه یک مزاحمت.
  // ---------------------------------------------------------------
  if (url.pathname === "/consult") {
    if (order.length < 2) {
      return json({
        ok: false,
        error: "مشورت چندمدلی به حداقل دو ارائه‌دهنده نیاز دارد",
        available: order.length
      }, 503);
    }

    // انتخاب دو مدل از دو خانواده متفاوت.
    // دو مدل هم‌خانواده معمولاً یک اشتباه را تکرار می‌کنند،
    // پس ارزش مشورت را از بین می‌برند.
    const FAMILY = {
      gemini: "google", github: "openai", groq: "llama",
      cerebras: "llama", openrouter: "llama",
      mistral: "mistral", zai: "glm", nvidia: "llama"
    };
    const first = order[0];
    const second = order.find(p => FAMILY[p.name] !== FAMILY[first.name]) || order[1];
    const picked = [first, second];
    const results = await Promise.all(
      picked.map(async p => {
        try {
          const text = await callProvider(p, system, prompt);
          return { provider: p.name, model: p.model, ok: true, answer: (text || "").trim() };
        } catch (e) {
          return { provider: p.name, model: p.model, ok: false, error: String(e.message || e).slice(0, 200) };
        }
      })
    );

    const good = results.filter(r => r.ok && r.answer);
    if (good.length === 0) {
      return json({ ok: false, error: "هیچ مدلی پاسخ نداد", results }, 502);
    }

    // استخراج دستور پیشنهادی هر مدل برای مقایسه
    const cmds = good.map(r => ({
      provider: r.provider,
      command: extractCommand(r.answer)
    }));

    let agreement = "unknown";
    if (good.length >= 2) {
      const a = normalizeCmd(cmds[0].command);
      const b = normalizeCmd(cmds[1].command);
      if (!a && !b) agreement = "no_command";
      else if (a && b && a === b) agreement = "identical";
      else if (a && b && sameTool(a, b)) agreement = "similar";
      else agreement = "different";
    } else {
      agreement = "single_response";
    }

    return json({
      ok: true,
      mode: "consult",
      agreement,
      commands: cmds,
      results: good,
      failed: results.filter(r => !r.ok)
    });
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

      if (!res.ok) throw new Error(`HTTP ${res.status} ${cleanError(await res.text())}`);
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

    if (!res.ok) throw new Error(`HTTP ${res.status} ${cleanError(await res.text())}`);
    const d = await res.json();
    return d?.choices?.[0]?.message?.content || "";
  } finally {
    clearTimeout(timer);
  }
}

// خلاصه‌کردن پیام خطا.
// برخی سرویس‌ها به‌جای JSON یک صفحه کامل HTML برمی‌گردانند که
// معمولاً یعنی درخواست اصلاً به API نرسیده و یک لایه محافظ جلویش را گرفته.
function cleanError(body) {
  if (!body) return "";
  const t = body.trim();
  if (t.startsWith("<") || t.toLowerCase().includes("<!doctype")) {
    return "پاسخ HTML به‌جای JSON — احتمالاً مسدودسازی یا نشانی اشتباه";
  }
  try {
    const j = JSON.parse(t);
    return String(j.error?.message || j.message || j.error || t).slice(0, 160);
  } catch {
    return t.slice(0, 160);
  }
}

// استخراج دستور از کادر کد پاسخ مدل
function extractCommand(answer) {
  const m = answer.match(/```(?:bash|sh)?\s*\n([\s\S]+?)```/);
  if (!m) return null;
  const lines = m[1].trim().split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"));
  return lines[0] || null;
}

// یکسان‌سازی برای مقایسه — فاصله اضافه و نقل‌قول اهمیت ندارد
function normalizeCmd(c) {
  if (!c) return null;
  return c.replace(/\s+/g, " ").replace(/['"]/g, "").trim().toLowerCase();
}

// آیا دو دستور از یک ابزار و یک زیرفرمان استفاده می‌کنند
function sameTool(a, b) {
  const pa = a.split(" ").slice(0, 2).join(" ");
  const pb = b.split(" ").slice(0, 2).join(" ");
  return pa === pb;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });
}
