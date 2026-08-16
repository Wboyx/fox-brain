#!/usr/bin/env bash
# نصب فاز دو — اجرای دستور با تأیید انسان
set -u

DIR="/opt/foxy1-monitor"
SVC="foxy1-exec"
RAW="https://raw.githubusercontent.com/Wboyx/fox-brain/main"

grn(){ printf "\033[32m%s\033[0m\n" "$1"; }
red(){ printf "\033[31m%s\033[0m\n" "$1"; }
ylw(){ printf "\033[33m%s\033[0m\n" "$1"; }

echo "======================================================"
echo " نصب فاز دو — اجرا با تأیید"
echo "======================================================"
echo

[ "$(id -u)" = "0" ] || { red "باید با root اجرا شود."; exit 1; }
[ -f "$DIR/foxy1-monitor.env" ] || { red "فاز صفر نصب نشده است."; exit 1; }
grn "فاز صفر پیدا شد."

for k in FOXY1_BOT_TOKEN FOXY1_CHAT_ID BRAIN_URL BRAIN_KEY; do
  grep -qE "^$k=." "$DIR/foxy1-monitor.env" || { red "تنظیم نشده: $k"; exit 1; }
done
grn "تنظیمات کامل است."

systemctl is-active --quiet "$SVC" 2>/dev/null && { ylw "سرویس فعال بود — متوقف شد."; systemctl stop "$SVC"; }

echo
echo "دریافت فایل..."
curl -fsSL "$RAW/foxy1-exec.py" -o "$DIR/foxy1-exec.py.new" || { red "دریافت ناموفق."; exit 1; }
python3 -c "import ast;ast.parse(open('$DIR/foxy1-exec.py.new').read())" || { red "فایل نامعتبر."; rm -f "$DIR/foxy1-exec.py.new"; exit 1; }
grn "فایل معتبر است."

[ -f "$DIR/foxy1-exec.py" ] && cp -a "$DIR/foxy1-exec.py" "$DIR/foxy1-exec.py.bak-$(date +%Y%m%d-%H%M%S)"
mv -f "$DIR/foxy1-exec.py.new" "$DIR/foxy1-exec.py"
chmod 700 "$DIR/foxy1-exec.py"

mkdir -p /root/foxy1-exec-backups && chmod 700 /root/foxy1-exec-backups

echo
echo "ساخت سرویس..."
cat > "/etc/systemd/system/$SVC.service" <<UNIT
[Unit]
Description=Foxy1 Exec - human-approved command execution
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=/usr/bin/python3 $DIR/foxy1-exec.py
Restart=always
RestartSec=20

MemoryMax=120M
CPUQuota=25%

NoNewPrivileges=yes
PrivateTmp=yes

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
grn "سرویس ساخته شد (هنوز روشن نشده)."

echo
echo "======================================================"
grn " نصب کامل شد"
echo "======================================================"
echo
echo "تست لایه ایمنی پیش از روشن‌کردن:"
echo "  python3 $DIR/foxy1-exec.py --selftest"
echo
echo "روشن‌کردن:"
echo "  systemctl enable --now $SVC"
echo
echo "قفل اضطراری از تلگرام:"
echo "  /off"
echo
echo "قفل اضطراری از ترمینال:"
echo "  touch $DIR/EXEC_DISABLED"
echo
echo "حذف کامل:"
echo "  systemctl disable --now $SVC"
echo "  rm -f $DIR/foxy1-exec.py /etc/systemd/system/$SVC.service"
echo "  systemctl daemon-reload"
echo
