#!/usr/bin/env python3
# =====================================================================
# Foxy1 Ask — دیباگ گفت‌وگومحور (فاز یک)
#
# اصول ایمنی این نسخه:
#   - فقط می‌خواند، هیچ‌چیز را اجرا یا تغییر نمی‌دهد
#   - دستورهای تشخیصی از یک لیست سفید ثابت در کد می‌آیند
#   - مقدار حساس قبل از ارسال به مدل پاک می‌شود
#   - اگر مدل دستوری پیشنهاد داد، فقط نمایش داده می‌شود
#
# استفاده:
#   python3 foxy1-ask.py "چرا ربات کند شده؟"
#   python3 foxy1-ask.py --context full "لاگ را تحلیل کن"
#   python3 foxy1-ask.py --dry "سوال" 
# =====================================================================

import json
import os
import re
import subprocess
import sys
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "foxy1-monitor.env")
LOG_FILE = os.path.join(BASE_DIR, "foxy1-ask.log")

VERSION = "1.0.0"


# ---------------------------------------------------------------------
# پیکربندی
# ---------------------------------------------------------------------
def load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")

    def g(key, default=""):
        return os.environ.get(key) or cfg.get(key) or default

    return {
        "brain_url": g("BRAIN_URL").rstrip("/"),
        "brain_key": g("BRAIN_KEY"),
        "services": [s.strip() for s in g("WATCH_SERVICES", "foxteam-bot,x-ui").split(",") if s.strip()],
        "log_service": g("LOG_GREP_SERVICE", "foxteam-bot"),
    }


# ---------------------------------------------------------------------
# پاک‌سازی مقدار حساس — قبل از هر ارسال
# ---------------------------------------------------------------------
SECRET_PATTERNS = [
    re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b"),
    re.compile(r"(?i)(token|password|passwd|secret|api[_-]?key|apitoken)\s*[=:]\s*\S+"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"(?i)x-relay-key\s*:\s*\S+"),
]


def redact(text):
    if not text:
        return text
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def run(cmd, timeout=20):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return ((res.stdout or "") + (res.stderr or "")).strip()
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------
# لیست سفید دستورهای تشخیصی
#
# قانون مهم: این فهرست در کد است، نه در پرامپت.
# مدل نمی‌تواند دستور جدیدی به آن اضافه کند.
# ---------------------------------------------------------------------
def collect_context(cfg, level="normal"):
    parts = []

    def add(title, cmd, timeout=20):
        parts.append(f"### {title}\n{run(cmd, timeout)}")

    add("زمان و مدت روشن بودن", "date '+%Y-%m-%d %H:%M:%S %Z'; uptime -p")
    add("حافظه", "free -m")
    add("دیسک", "df -h / | tail -n 2")
    add("بار سیستم", "cat /proc/loadavg")

    svc_report = []
    for s in cfg["services"]:
        state = run(f"systemctl is-active {s} 2>/dev/null")
        mem = run(f"systemctl show {s} -p MemoryCurrent --value 2>/dev/null")
        try:
            mem_mb = f"{int(mem) / 1048576:.1f} MB"
        except (ValueError, TypeError):
            mem_mb = "?"
        svc_report.append(f"{s}: {state} | حافظه: {mem_mb}")
    parts.append("### سرویس‌ها\n" + "\n".join(svc_report))

    add("پروسه‌های پرمصرف", "ps -eo comm,pcpu,rss --sort=-rss | head -n 8")
    add("پورت‌های شنونده", "ss -ltn | head -n 15")

    # --------------------------------------------------------------
    # تشخیص تازگی خطا — در کد انجام می‌شود، نه با اعتماد به مدل.
    # درس: مدل‌های سبک قانون پیچیده را کامل دنبال نمی‌کنند،
    # پس داده را طوری آماده کن که تفسیر اشتباه ممکن نباشد.
    # --------------------------------------------------------------
    svc = cfg["log_service"]
    pattern = "error|failed|خطا|critical|fatal"

    recent = run(
        f"journalctl -u {svc} --since '5 min ago' --no-pager 2>/dev/null "
        f"| grep -Ei '{pattern}' | tail -n 20", 25
    )
    recent_count = len([l for l in recent.splitlines() if l.strip()]) if "ERROR:" not in recent else 0

    if recent_count > 0:
        parts.append(
            "### وضعیت خطا: فعال\n"
            f"در ۵ دقیقه اخیر {recent_count} خطا ثبت شده است. این مشکل جاری است.\n\n"
            f"{recent}"
        )
    else:
        older = run(
            f"journalctl -u {svc} --since '2 hours ago' --no-pager 2>/dev/null "
            f"| grep -Eic '{pattern}' || echo 0", 25
        )
        parts.append(
            "### وضعیت خطا: پاک\n"
            "در ۵ دقیقه اخیر هیچ خطایی ثبت نشده است.\n"
            f"تعداد خطای قدیمی در ۲ ساعت گذشته: {older.strip()} — این‌ها رفع‌شده‌اند "
            "و نباید به‌عنوان مشکل جاری معرفی شوند."
        )

    log_lines = 25 if level == "normal" else 80
    add(
        f"آخرین خطوط لاگ {svc} (فقط برای زمینه، نه لزوماً خطا)",
        f"journalctl -u {svc} --since '10 min ago' --no-pager 2>/dev/null | tail -n {log_lines}",
        timeout=30,
    )

    if level == "full":
        add("کشته‌شدن به‌علت کمبود حافظه",
            "journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -i 'killed process\\|out of memory' | tail -n 5", 30)
        add("ری‌استارت سرویس‌ها در ۲۴ ساعت",
            "journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -i 'Started\\|Stopped' | tail -n 15", 30)
        add("خطاهای کلی اخیر",
            "journalctl -p err --since '6 hours ago' --no-pager 2>/dev/null | tail -n 20", 30)

    return redact("\n\n".join(parts))


# ---------------------------------------------------------------------
# پرامپت سامانه — شخصیت و قوانین Foxy1
# ---------------------------------------------------------------------
SYSTEM_PROMPT = """تو فاکسی 1 هستی، دستیار فنی و دیباگر سرور.

قوانین پاسخ:

۱. فارسی ساده، آرام و حرفه‌ای بنویس. کاربر را «همکار» خطاب کن.
۲. جمله فارسی و عبارت انگلیسی را در یک خط مخلوط نکن. دستور، مسیر و نام سرویس را در کادر جدا بنویس.
۳. حدس را به‌عنوان واقعیت اعلام نکن. اگر مطمئن نیستی، بگو چه تستی لازم است.
۴. فقط بر اساس داده‌ای که در متن آمده نتیجه‌گیری کن. چیزی از خودت نساز.
۵. اگر داده کافی نیست، صریح بگو چه اطلاعاتی کم است.
۶. وعده قطعی نده و اغراق نکن.

ساختار پاسخ:

وضعیت فعلی:
یک یا دو جمله کوتاه.

یافته‌ها:
فهرست کوتاه از چیزهایی که در داده دیدی.

تشخیص:
محتمل‌ترین علت، با ذکر شواهد. اگر چند احتمال هست، به ترتیب احتمال بنویس.

مرحله بعد:
این بخش باید دقیقاً این شکل باشد و هیچ شکل دیگری قابل قبول نیست:

مرحله بعد:
```bash
یک دستور خواندنی واقعی اینجا
```
نتیجه صحیح: یک جمله کوتاه.

اگر سرور سالم است و دستوری لازم نیست، باز هم یک دستور بررسی سلامت بنویس مثل:
```bash
systemctl status SERVICE --no-pager | head -n 5
```
هرگز این بخش را بدون کادر کد ننویس.

قانون تازگی خطا:

بخش «وضعیت خطا» را ببین.

- اگر نوشته «پاک» است، هیچ مشکل فعالی وجود ندارد. در بخش تشخیص بنویس که سرور سالم است. خطاهای بخش لاگ قدیمی‌اند و آن‌ها را مشکل معرفی نکن.
- اگر نوشته «فعال» است، روی همان خطاها تمرکز کن.

این تنها معیار توست. به تاریخ خطوط لاگ استناد نکن.

نکات مهم:

- تو دسترسی اجرا نداری. فقط تحلیل می‌کنی و پیشنهاد می‌دهی.
- هرگز دستور مخرب پیشنهاد نده. دستورهای زیر ممنوع‌اند: حذف، بازنویسی، ری‌استارت، تغییر تنظیمات.
- فقط دستورهای خواندنی مثل بررسی وضعیت، خواندن لاگ و اندازه‌گیری مجاز است.
- اگر همه‌چیز سالم است، همین را بگو و مشکل نتراش.
- پاسخ کوتاه باشد. حداکثر پانزده خط."""


# ---------------------------------------------------------------------
# ارتباط با دروازه
# ---------------------------------------------------------------------
def ask_brain(cfg, question, context, prefer=None):
    if not cfg["brain_url"]:
        return None, "BRAIN_URL تنظیم نشده است."
    if not cfg["brain_key"]:
        return None, "BRAIN_KEY تنظیم نشده است."

    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prompt = (
        f"زمان فعلی سرور: {now}\n"
        f"هر خط لاگ که تاریخش قدیمی‌تر از چند دقیقه است، مشکل جاری نیست.\n\n"
        f"سؤال همکار:\n{question}\n\n"
        f"وضعیت واقعی سرور در این لحظه:\n\n{context}"
    )

    payload = json.dumps({
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "prefer": prefer,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{cfg['brain_url']}/ask",
        data=payload,
        headers={
            "content-type": "application/json",
            "x-brain-key": cfg["brain_key"],
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
            return None, f"خطای دروازه ({e.code}): {body.get('error')}"
        except Exception:
            return None, f"خطای دروازه: {e.code}"
    except Exception as exc:
        return None, f"اتصال به دروازه ناموفق: {exc}"

    if not data.get("ok"):
        return None, f"مدل پاسخ نداد: {data.get('error')} | تلاش‌ها: {data.get('tried')}"

    return data, None


def log_session(question, provider, answer):
    try:
        from datetime import datetime
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"\n{'=' * 60}\n")
            fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {provider}\n")
            fh.write(f"سؤال: {question}\n{'-' * 60}\n{answer}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------
def main():
    args = [a for a in sys.argv[1:]]
    level = "normal"
    prefer = None
    dry = False

    if "--context" in args:
        i = args.index("--context")
        level = args[i + 1] if i + 1 < len(args) else "normal"
        del args[i:i + 2]

    if "--prefer" in args:
        i = args.index("--prefer")
        prefer = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]

    if "--dry" in args:
        dry = True
        args.remove("--dry")

    cfg = load_config()

    if "--health" in args:
        if not cfg["brain_url"]:
            print("BRAIN_URL تنظیم نشده است.")
            return
        try:
            with urllib.request.urlopen(f"{cfg['brain_url']}/health", timeout=20) as r:
                print(json.dumps(json.loads(r.read().decode()), ensure_ascii=False, indent=2))
        except Exception as exc:
            print(f"ناموفق: {exc}")
        return

    question = " ".join(args).strip()
    if not question:
        print("استفاده:")
        print("  python3 foxy1-ask.py \"سؤال تو\"")
        print("  python3 foxy1-ask.py --context full \"سؤال\"")
        print("  python3 foxy1-ask.py --dry \"سؤال\"      نمایش داده بدون ارسال")
        print("  python3 foxy1-ask.py --health           بررسی دروازه")
        return

    print("در حال جمع‌آوری وضعیت سرور...")
    context = collect_context(cfg, level)

    if dry:
        print("\n--- داده‌ای که ارسال می‌شد (پس از پاک‌سازی) ---\n")
        print(context)
        print(f"\n--- حجم: {len(context)} کاراکتر ---")
        return

    print("در حال پرسیدن از مدل...\n")
    data, err = ask_brain(cfg, question, context, prefer)

    if err:
        print(f"❌ {err}")
        sys.exit(1)

    print("=" * 60)
    print(data["answer"])
    print("=" * 60)
    print(f"مدل: {data['provider']} ({data['model']})")
    if data.get("tried"):
        print(f"تلاش ناموفق قبلی: {data['tried']}")

    log_session(question, data["provider"], data["answer"])


if __name__ == "__main__":
    main()
