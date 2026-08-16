# افزودن ارائه‌دهنده مدل

هشت ارائه‌دهنده پشتیبانی می‌شود. هر کدام را که کلیدش تنظیم شود، خودکار وارد زنجیره می‌گردد.

## ترتیب اولویت

```text
1. gemini      دستورپذیری بالا
2. groq        سریع‌ترین
3. cerebras    سهمیه توکن روزانه بالا
4. mistral     سهمیه ماهانه بزرگ
5. nvidia      نرخ درخواست بالا
6. github      مدل‌های سطح بالا
7. openrouter  تنوع مدل
8. zai         جایگزین سبک
```

## گرفتن کلید — همه بدون کارت اعتباری

| ارائه‌دهنده | نشانی | متغیر |
|---|---|---|
| Gemini | aistudio.google.com/apikey | `GEMINI_API_KEY` |
| Groq | console.groq.com | `GROQ_API_KEY` |
| Cerebras | cloud.cerebras.ai | `CEREBRAS_API_KEY` |
| Mistral | console.mistral.ai | `MISTRAL_API_KEY` |
| NVIDIA | build.nvidia.com | `NVIDIA_API_KEY` |
| GitHub Models | github.com/marketplace/models | `GITHUB_MODELS_TOKEN` |
| OpenRouter | openrouter.ai/keys | `OPENROUTER_API_KEY` |
| Z.AI | z.ai | `ZAI_API_KEY` |

نکته: Mistral و NVIDIA ممکن است تأیید شماره تلفن بخواهند.

برای GitHub Models از همان توکن گیت‌هاب با دسترسی `models:read` استفاده می‌شود.

## روش افزودن

در Vercel به بخش Settings و سپس Environment Variables برو و متغیر را اضافه کن. کلید `Sensitive` را روشن بگذار.

بعد از ذخیره حتماً `Redeploy` بزن، وگرنه اعمال نمی‌شود.

## بررسی

```bash
curl -s https://NAME.vercel.app/health
```

فهرست `providers_ready` باید ارائه‌دهنده جدید را نشان دهد.

## تغییر نام مدل

اگر نام مدلی منسوخ شد، فقط متغیر مربوطه را تنظیم کن:

```text
GEMINI_MODEL
GROQ_MODEL
CEREBRAS_MODEL
MISTRAL_MODEL
NVIDIA_MODEL
GITHUB_MODEL
OPENROUTER_MODEL
ZAI_MODEL
```

نیازی به تغییر کد نیست.

## حافظه گفت‌وگو

```text
/memory   دیدن حافظه فعلی
/new      پاک‌کردن و شروع تازه
```

حافظه شش نوبت آخر را نگه می‌دارد و بعد از نیم ساعت بی‌کاری خودکار پاک می‌شود.

دلیل محدودیت: حافظه بی‌نهایت مصرف توکن را بالا می‌برد، پاسخ را کند می‌کند، و خطر دارد که اطلاعات کهنه با وضعیت فعلی قاطی شود.
