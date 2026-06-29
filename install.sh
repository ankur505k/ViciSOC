#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok(){ echo -e "${GREEN}[ OK ]${NC} $1"; }
warn(){ echo -e "${YELLOW}[ WARN ]${NC} $1"; }
fail(){ echo -e "${RED}[ FAIL ]${NC} $1"; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo ./install-vicisoc.sh"

echo "=========================================="
echo "          ViciSOC Agent Installer"
echo "=========================================="

echo "[+] Checking OS..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  echo "Detected: $PRETTY_NAME"
else
  fail "Cannot detect OS"
fi

echo "[+] Checking Wazuh Agent..."
if [ ! -d /var/ossec ] || [ ! -f /var/ossec/etc/ossec.conf ]; then
  fail "Wazuh Agent is not installed. Install/register Wazuh Agent first."
fi
ok "Wazuh Agent found"

echo "[+] Checking Vicidial / Dialer..."
DIALER_OK=0
[ -d /etc/asterisk ] && DIALER_OK=1
[ -d /usr/share/astguiclient ] && DIALER_OK=1
[ -d /var/www/html/vicidial ] && DIALER_OK=1
command -v asterisk >/dev/null 2>&1 && DIALER_OK=1

if [ "$DIALER_OK" -eq 1 ]; then
  ok "Dialer/Vicidial/Asterisk detected"
else
  warn "Dialer not clearly detected. Continuing anyway."
fi

echo
read -rp "Enter Slack Webhook URL: " SLACK_WEBHOOK
read -rsp "Enter VirusTotal API Key: " VT_API_KEY
echo
read -rp "Enter Wazuh Manager IP: " MANAGER_IP
read -rp "Enter This Alma/Vicidial Server IP: " ALMA_IP
read -rp "Enter Agent Name [ALMA-SERVER]: " AGENT_NAME
AGENT_NAME=${AGENT_NAME:-ALMA-SERVER}

echo
echo "=========================================="
echo "Configuration Summary"
echo "=========================================="
echo "Manager IP : $MANAGER_IP"
echo "Server IP  : $ALMA_IP"
echo "Agent Name : $AGENT_NAME"
echo "Slack      : Configured"
echo "VirusTotal : Configured"
echo
read -rp "Proceed with configuration? (y/n): " CONFIRM
[[ "$CONFIRM" == "y" ]] || fail "Cancelled"

echo "[+] Creating backup..."
mkdir -p /opt/vicisoc/backups
cp /var/ossec/etc/ossec.conf "/opt/vicisoc/backups/ossec.conf.$(date +%F-%H%M%S)"

echo "[+] Saving ViciSOC secrets..."
mkdir -p /opt/vicisoc
cat > /opt/vicisoc/vicisoc.env << EOF
SLACK_WEBHOOK="$SLACK_WEBHOOK"
VT_API_KEY="$VT_API_KEY"
MANAGER_IP="$MANAGER_IP"
ALMA_IP="$ALMA_IP"
AGENT_NAME="$AGENT_NAME"
EOF
chmod 600 /opt/vicisoc/vicisoc.env
ok "Secrets saved"

echo "[+] Updating Wazuh manager address..."
sed -i "s|<address>.*</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf || true

echo "[+] Configuring log monitoring and FIM..."
python3 - << 'PY'
from pathlib import Path

p = Path("/var/ossec/etc/ossec.conf")
s = p.read_text()

localfiles = """
<!-- ViciSOC Log Monitoring -->
<localfile>
  <location>/var/log/secure</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/messages</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/httpd/access_log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/httpd/error_log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/asterisk/messages</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/ossec/logs/active-responses.log</location>
  <log_format>syslog</log_format>
</localfile>
"""

fim = """
  <!-- ViciSOC FIM Monitoring -->
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/ssh</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/asterisk</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/httpd</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/var/www/html</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/usr/share/astguiclient</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/var/lib/asterisk</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/var/spool/asterisk</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/root</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/home</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/sudoers</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/crontab</directories>
"""

if "ViciSOC Log Monitoring" not in s:
    s = s.replace("</ossec_config>", localfiles + "\n</ossec_config>")

if "ViciSOC FIM Monitoring" not in s:
    s = s.replace("</syscheck>", fim + "\n</syscheck>")

p.write_text(s)
PY
ok "Logs and FIM configured"

echo "[+] Preparing log files..."
mkdir -p /var/log/asterisk /var/log/httpd
touch /var/log/asterisk/messages
touch /var/log/httpd/access_log /var/log/httpd/error_log
chmod 640 /var/log/asterisk/messages || true
ok "Log files ready"

echo "[+] Installing block-ip.sh..."
cat > /var/ossec/active-response/bin/block-ip.sh << EOF
#!/bin/bash

LOG="/var/ossec/logs/active-responses.log"
SLACK_WEBHOOK="$SLACK_WEBHOOK"
BLOCK_TIME=3600

read INPUT_JSON

SRCIP=\$(echo "\$INPUT_JSON" | grep -oP '"srcip":"\K[^"]+' | head -1)

if [[ ! "\$SRCIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "\$(date) - Invalid srcip: \$SRCIP" >> "\$LOG"
  exit 0
fi

IFS='.' read -r o1 o2 o3 o4 <<< "\$SRCIP"
for o in "\$o1" "\$o2" "\$o3" "\$o4"; do
  if [ "\$o" -gt 255 ]; then
    echo "\$(date) - Invalid srcip octet: \$SRCIP" >> "\$LOG"
    exit 0
  fi
done

case "\$SRCIP" in
  127.*|10.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*)
    echo "\$(date) - Skipped private/local IP: \$SRCIP" >> "\$LOG"
    exit 0
    ;;
esac

iptables -C INPUT -s "\$SRCIP" -j DROP 2>/dev/null || iptables -I INPUT -s "\$SRCIP" -j DROP

echo "\$(date) - BLOCKED IP: \$SRCIP for \$BLOCK_TIME seconds" >> "\$LOG"

PAYLOAD=\$(printf '{"text":"🚨 *ViciSOC Active Response*\\nServer: $AGENT_NAME\\nBlocked IP: %s\\nReason: SSH brute force\\nDuration: 1 hour"}' "\$SRCIP")

curl -sS -X POST -H "Content-Type: application/json" --data "\$PAYLOAD" "\$SLACK_WEBHOOK" >> "\$LOG" 2>&1

(
  sleep "\$BLOCK_TIME"
  iptables -D INPUT -s "\$SRCIP" -j DROP 2>/dev/null
  echo "\$(date) - UNBLOCKED IP: \$SRCIP" >> "\$LOG"
) &

exit 0
EOF

chmod 750 /var/ossec/active-response/bin/block-ip.sh
ok "block-ip.sh installed"

echo "[+] Installing unblock-ip.sh..."
cat > /var/ossec/active-response/bin/unblock-ip.sh << 'EOF'
#!/bin/bash

IP="$1"
LOG="/var/ossec/logs/active-responses.log"

if [ -z "$IP" ]; then
  echo "Usage: unblock-ip.sh <IP>"
  exit 1
fi

iptables -D INPUT -s "$IP" -j DROP 2>/dev/null
echo "$(date) - MANUAL UNBLOCKED IP: $IP" >> "$LOG"
echo "Unblocked: $IP"
EOF

chmod 750 /var/ossec/active-response/bin/unblock-ip.sh
ok "unblock-ip.sh installed"

echo "[+] Restarting Wazuh Agent..."
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent
ok "Wazuh Agent restarted"

echo "[+] Sending Slack test..."
curl -sS -X POST -H "Content-Type: application/json" \
  --data "{\"text\":\"✅ ViciSOC Agent configured on $AGENT_NAME ($ALMA_IP)\"}" \
  "$SLACK_WEBHOOK" >/dev/null 2>&1 || warn "Slack test failed"

echo
echo "=========================================="
echo "      ViciSOC Installation Complete"
echo "=========================================="
echo
echo "Test failed SSH log:"
echo "logger -p authpriv.notice -t sshd \"Failed password for root from 77.77.77.77 port 5555 ssh2\""
echo
echo "Test FIM:"
echo "echo '# ViciSOC TEST' >> /etc/ssh/sshd_config"
echo "sed -i '/# ViciSOC TEST/d' /etc/ssh/sshd_config"
echo
echo "Check agent:"
echo "systemctl status wazuh-agent --no-pager"
echo