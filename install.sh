#!/bin/bash
#
# ViciSOC Security Console — hardened installer/manager
# Target: AlmaLinux / RHEL-family (Rocky, CentOS, RHEL)
#
set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
VERSION="3.0"
BASE="/opt/vicisoc"
ENV_FILE="$BASE/vicisoc.env"
LOG_DIR="$BASE/logs"
LOG_FILE="$LOG_DIR/vicisoc.log"
BACKUP_DIR="$BASE/backups"
LOCK_FILE="/var/run/vicisoc.lock"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

# Idempotency markers — every XML block ViciSOC ever writes into ossec.conf
# is wrapped in exactly one of these, so re-runs are detected and skipped
# instead of duplicated.
LOG_MARKER="<!-- ViciSOC:LOG_MONITORING -->"
FIM_MARKER="<!-- ViciSOC:FIM -->"
AR_MARKER="<!-- ViciSOC:ACTIVE_RESPONSE_PLACEHOLDER -->"
SLACK_INTEGRATION_MARKER="<!-- ViciSOC:SLACK_FIM_INTEGRATION -->"
SLACK_INTEGRATION_NAME="custom-vicisoc-slack"
SLACK_INTEGRATION_SCRIPT="/var/ossec/integrations/${SLACK_INTEGRATION_NAME}"

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

# ---------------------------------------------------------------------------
# Basic output + logging helpers
# ---------------------------------------------------------------------------
ok()   { echo -e "${GREEN}[OK]${NC} $1";   log "OK: $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; log "WARN: $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1";   log "FAIL: $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1";  log "INFO: $1"; }

log() {
    # Safe even before LOG_FILE exists
    if [ -n "${LOG_FILE:-}" ] && [ -d "$(dirname "$LOG_FILE")" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
    fi
}

pause() { echo; read -r -p "Press Enter to continue..." _; }

# ---------------------------------------------------------------------------
# Error trap — show file/line/command on any failure
# ---------------------------------------------------------------------------
on_error() {
    local exit_code=$?
    local line_no=$1
    fail "Error (exit $exit_code) at line $line_no. See $LOG_FILE for details."
    log "TRAP: command failed at line $line_no with exit code $exit_code"
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR
trap 'cleanup_on_exit' EXIT
trap 'echo; warn "Interrupted by user."; exit 130' INT TERM

TMP_FILES=()
cleanup_on_exit() {
    local rc=$?
    for f in "${TMP_FILES[@]:-}"; do
        [ -n "$f" ] && [ -f "$f" ] && rm -f "$f"
    done
    [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
    exit "$rc"
}

mktmp() {
    local t
    t="$(mktemp)"
    TMP_FILES+=("$t")
    echo "$t"
}

# ---------------------------------------------------------------------------
# Lock file — prevent concurrent runs
# ---------------------------------------------------------------------------
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid
        pid="$(cat "$LOCK_FILE" 2>/dev/null || echo "")"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            fail "Another instance is already running (PID $pid). Exiting."
            exit 1
        else
            warn "Stale lock file found. Removing."
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

# ---------------------------------------------------------------------------
# Root / filesystem checks
# ---------------------------------------------------------------------------
root_check() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root. Try: sudo $0"
        exit 1
    fi
}

writable_check() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        dir="$(dirname "$dir")"
    fi
    if [ ! -w "$dir" ]; then
        fail "$dir is not writable. Cannot continue."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
OS_ID=""
OS_VERSION=""

detect_os() {
    if [ ! -f /etc/os-release ]; then
        fail "Cannot detect OS (no /etc/os-release). Unsupported system."
        exit 1
    fi

    local id="" version_id="" pretty_name=""
    while IFS='=' read -r key val; do
        val="${val%\"}"; val="${val#\"}"
        case "$key" in
            ID) id="$val" ;;
            VERSION_ID) version_id="$val" ;;
            PRETTY_NAME) pretty_name="$val" ;;
        esac
    done < /etc/os-release

    OS_ID="${id:-unknown}"
    OS_VERSION="${version_id:-unknown}"

    case "$OS_ID" in
        almalinux|rocky|centos|rhel)
            ok "Detected supported OS: ${pretty_name:-$OS_ID} ($OS_VERSION)"
            ;;
        *)
            fail "Unsupported OS: $OS_ID. This script supports AlmaLinux/Rocky/CentOS/RHEL only."
            exit 1
            ;;
    esac

    ARCH="$(uname -m)"
    info "Architecture: $ARCH"
}

# ---------------------------------------------------------------------------
# Dependency checks (auto-install via dnf where possible)
# ---------------------------------------------------------------------------
REQUIRED_CMDS=(curl wget grep awk sed hostnamectl systemctl tar gzip xmllint)
declare -A CMD_TO_PKG=(
    [xmllint]="libxml2"
    [hostnamectl]="systemd"
)

check_dependencies() {
    local missing=()
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        ok "All required dependencies present."
        return 0
    fi

    warn "Missing dependencies: ${missing[*]}"
    read -r -p "Attempt to auto-install missing packages with dnf? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        local pkgs=()
        for cmd in "${missing[@]}"; do
            pkgs+=("${CMD_TO_PKG[$cmd]:-$cmd}")
        done
        if dnf install -y "${pkgs[@]}" >>"$LOG_FILE" 2>&1; then
            ok "Installed: ${pkgs[*]}"
        else
            fail "Failed to install some packages. Check $LOG_FILE."
            exit 1
        fi
    else
        fail "Cannot continue without required dependencies."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Init / bootstrap
# ---------------------------------------------------------------------------
init() {
    # Clean, minimal footprint on disk — no bin/ or state/ directories,
    # since ViciSOC no longer generates or installs any standalone scripts.
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
    touch "$ENV_FILE"
    chmod 700 "$BASE"
    chmod 600 "$ENV_FILE"
    chmod 700 "$LOG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    log "===== ViciSOC session started (v$VERSION) ====="
}

# ---------------------------------------------------------------------------
# Env file helpers — safe read/write, no duplicate keys, no blind sourcing.
# Nothing in this script ever executes vicisoc.env as shell code.
# ---------------------------------------------------------------------------
env_get() {
    local key="$1"
    [ -f "$ENV_FILE" ] || return 1
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d'=' -f2- | sed -e 's/^"//' -e 's/"$//'
}

env_set() {
    # Idempotent set: removes existing key, appends new value.
    local key="$1" value="$2"
    local tmp
    tmp="$(mktmp)"
    if [ -f "$ENV_FILE" ]; then
        grep -v -E "^${key}=" "$ENV_FILE" > "$tmp" || true
    fi
    printf '%s="%s"\n' "$key" "$value" >> "$tmp"
    cat "$tmp" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
}

env_has() {
    local key="$1"
    [ -f "$ENV_FILE" ] && grep -q -E "^${key}=" "$ENV_FILE"
}

json_escape() {
    # Minimal, dependency-free JSON string escaper (backslash, quote,
    # newline, carriage return). Wraps the result in quotes.
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\r'/}"
    s="${s//$'\n'/\\n}"
    printf '"%s"' "$s"
}

# send_slack: the ONE place in this installer that posts to Slack.
# Every module (Slack test, future VirusTotal alerts, etc.) should call
# this instead of building its own curl call, so there is a single
# source of truth for how messages are sent.
#
# Usage: send_slack "message text" ["webhook override"]
# If no override is given, reads SLACK_WEBHOOK live from vicisoc.env.
send_slack() {
    local message="$1"
    local webhook="${2:-}"

    if [ -z "$webhook" ]; then
        webhook="$(env_get SLACK_WEBHOOK 2>/dev/null || true)"
    fi

    if [ -z "$webhook" ]; then
        warn "SLACK_WEBHOOK not configured — cannot send Slack message."
        return 1
    fi

    local payload
    payload="$(printf '{"text": %s}' "$(json_escape "$message")")"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST -H "Content-Type: application/json" \
        -d "$payload" "$webhook" || echo "000")

    [ "$http_code" = "200" ]
}

mask_secret() {
    local s="$1"
    local len=${#s}
    if [ "$len" -le 8 ]; then
        echo "****"
    else
        echo "${s:0:4}...${s: -4}"
    fi
}

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
validate_url() {
    [[ "$1" =~ ^https://hooks\.slack\.com/services/.+ ]]
}

validate_vt_key() {
    # VirusTotal API keys are 64-char hex
    [[ "$1" =~ ^[a-fA-F0-9]{64}$ ]]
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -r -a octets <<< "$ip"
        for o in "${octets[@]}"; do
            [ "$o" -le 255 ] || return 1
        done
        return 0
    fi
    # basic IPv6 check
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]
}

validate_positive_int() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]
}

confirm() {
    local prompt="$1"
    read -r -p "$prompt [y/N]: " a
    [[ "$a" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Backup / restore for config files
# ---------------------------------------------------------------------------
backup_file() {
    local src="$1"
    [ -f "$src" ] || { fail "$src does not exist, cannot back up."; return 1; }
    local stamp
    stamp="$(date +%Y%m%d-%H%M%S)"
    local dest="$BACKUP_DIR/$(basename "$src").$stamp.bak"
    cp -p "$src" "$dest"
    chmod 600 "$dest"
    echo "$dest"
}

restore_file() {
    local backup="$1" dest="$2"
    cp -p "$backup" "$dest"
    warn "Restored $dest from $backup"
}

# ---------------------------------------------------------------------------
# XML-safe ossec.conf editing: idempotent, validated, backed up, rolled back
# on failure. Each injected block is wrapped in a unique marker comment so
# re-runs are detected and skipped instead of duplicated.
# ---------------------------------------------------------------------------
xml_block_present() {
    local marker="$1"
    [ -f "$OSSEC_CONF" ] && grep -q -F "$marker" "$OSSEC_CONF"
}

wazuh_installed() {
    [ -d /var/ossec ] && [ -f "$OSSEC_CONF" ]
}

# insert_before_tag: writes $content into $file immediately before the
# first (position=first) or last (position=last) line containing $tag.
# Never appends to end-of-file, so we never end up outside </ossec_config>.
insert_before_tag() {
    local file="$1" content="$2" tag="$3" position="${4:-last}"

    if ! grep -q -F "$tag" "$file"; then
        return 1
    fi

    local content_file
    content_file="$(mktmp)"
    printf '%s\n' "$content" > "$content_file"

    local line_no
    if [ "$position" = "first" ]; then
        line_no=$(grep -n -F "$tag" "$file" | head -1 | cut -d: -f1)
    else
        line_no=$(grep -n -F "$tag" "$file" | tail -1 | cut -d: -f1)
    fi

    local insert_at=$((line_no - 1))
    # GNU sed 'r' reads the content file in *after* the given line number,
    # i.e. right before the tag's own line — never after EOF.
    sed -i "${insert_at}r ${content_file}" "$file"
}

# commit_and_verify: validate XML, restart agent, roll back to $1 (a backup
# path) automatically if either step fails.
commit_and_verify() {
    local backup="$1"

    if ! xmllint --noout "$OSSEC_CONF" 2>>"$LOG_FILE"; then
        fail "Resulting ossec.conf is not valid XML. Rolling back."
        restore_file "$backup" "$OSSEC_CONF"
        return 1
    fi
    ok "XML validated successfully."

    if ! restart_wazuh_agent; then
        fail "Wazuh agent failed to restart with new config. Rolling back."
        restore_file "$backup" "$OSSEC_CONF"
        restart_wazuh_agent || warn "Agent still not healthy after rollback — manual check needed."
        return 1
    fi

    ok "Configuration applied and Wazuh agent verified running."
    return 0
}

# inject_xml_block: generic helper for blocks that are always safe as a
# top-level sibling (e.g. <localfile>, comments) — inserted before
# </ossec_config>.
inject_xml_block() {
    local marker="$1"
    local block="$2"

    if ! wazuh_installed; then
        fail "Wazuh is not installed (/var/ossec or ossec.conf missing)."
        return 1
    fi

    if xml_block_present "$marker"; then
        warn "This configuration block is already present. Skipping (idempotent)."
        return 0
    fi

    local backup
    backup="$(backup_file "$OSSEC_CONF")"
    ok "Backed up ossec.conf to $backup"

    local full_block
    full_block="$(printf '%s\n%s' "$marker" "$block")"

    if ! insert_before_tag "$OSSEC_CONF" "$full_block" "</ossec_config>" "last"; then
        fail "Could not find </ossec_config> in ossec.conf — refusing to edit blindly."
        return 1
    fi

    commit_and_verify "$backup"
}


# wazuh_service_name: this box may be running a full Wazuh manager/local
# install (which runs wazuh-integratord, needed for Slack alerts) or a
# plain forwarding agent (which does not). Detect whichever unit is
# actually installed rather than assuming "wazuh-agent" everywhere.
wazuh_service_name() {
    if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager\.service'; then
        echo "wazuh-manager"
    else
        echo "wazuh-agent"
    fi
}

restart_wazuh_agent() {
    local svc
    svc="$(wazuh_service_name)"
    if ! systemctl restart "$svc" 2>>"$LOG_FILE"; then
        return 1
    fi
    sleep 2
    systemctl is-active --quiet "$svc"
}

# ---------------------------------------------------------------------------
# Status dashboard
# ---------------------------------------------------------------------------
status() {
    clear
    echo "======================================"
    echo "        ViciSOC Security Console"
    echo "              Version $VERSION"
    echo "======================================"
    echo

    if wazuh_installed; then
        local svc
        svc="$(wazuh_service_name)"
        ok "Wazuh Installed ($svc)"
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            ok "Wazuh Service Running"
        else
            warn "Wazuh Installed but $svc is NOT running"
        fi
    else
        fail "Wazuh Missing"
    fi

    if [ -d /etc/asterisk ] || [ -d /var/www/html/vicidial ]; then
        ok "Vicidial/Asterisk Detected"
    else
        warn "Dialer Not Detected"
    fi

    if env_has SLACK_WEBHOOK; then
        ok "Slack Configured"
    else
        warn "Slack Not Configured"
    fi

    if env_has VT_API_KEY; then
        ok "VirusTotal Configured"
    else
        warn "VirusTotal Not Configured"
    fi

    if xml_block_present "$LOG_MARKER" 2>/dev/null; then
        ok "Log Monitoring Configured"
    else
        warn "Log Monitoring Not Configured"
    fi

    if xml_block_present "$FIM_MARKER" 2>/dev/null; then
        ok "File Integrity Monitoring Configured"
    else
        warn "File Integrity Monitoring Not Configured"
    fi

    if xml_block_present "$AR_MARKER" 2>/dev/null; then
        ok "Active Response Placeholder Present"
    else
        warn "Active Response Placeholder Not Configured"
    fi

    if xml_block_present "$SLACK_INTEGRATION_MARKER" 2>/dev/null; then
        ok "Slack FIM/Log Alerting Configured"
    else
        warn "Slack FIM/Log Alerting Not Configured"
    fi

    echo
}

# ---------------------------------------------------------------------------
# System check
# ---------------------------------------------------------------------------
system_check() {
    clear
    echo "========= SYSTEM CHECK ========="
    echo
    echo "Hostname : $(hostname)"
    echo "Kernel   : $(uname -r)"
    echo "OS       : ${OS_ID} ${OS_VERSION}"
    echo
    echo "-- Disk --"
    df -h / || true
    echo
    echo "-- Memory --"
    free -h || true
    echo
    echo "-- Load Average --"
    uptime || true
    echo
    echo "-- Firewall --"
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --state 2>/dev/null || true
    else
        warn "firewalld not active"
    fi
    echo
    echo "-- SELinux --"
    command -v getenforce >/dev/null 2>&1 && getenforce || echo "getenforce not available"
    pause
}

# ---------------------------------------------------------------------------
# Slack integration
# ---------------------------------------------------------------------------
slack() {
    clear
    echo "========= SLACK CONFIGURATION ========="
    echo

    if env_has SLACK_WEBHOOK; then
        local existing
        existing="$(env_get SLACK_WEBHOOK)"
        echo "Slack already configured: $(mask_secret "$existing")"
        if ! confirm "Replace existing webhook?"; then
            pause
            return
        fi
    fi

    read -r -p "Enter Slack Webhook URL: " WEB
    WEB="$(echo "$WEB" | xargs)" # trim whitespace

    if [ -z "$WEB" ]; then
        fail "Webhook cannot be empty."
        pause
        return
    fi
    if ! validate_url "$WEB"; then
        fail "That doesn't look like a valid Slack webhook URL (expected https://hooks.slack.com/services/...)."
        pause
        return
    fi

    info "Sending test message..."
    if send_slack "✅ ViciSOC Slack integration test — this webhook is now active." "$WEB"; then
        env_set SLACK_WEBHOOK "$WEB"
        ok "Slack webhook verified and saved. Every ViciSOC module (FIM alerts included) now uses this one webhook."
    else
        fail "Slack test failed. Webhook NOT saved."
    fi

    pause
}

# ---------------------------------------------------------------------------
# VirusTotal integration
# ---------------------------------------------------------------------------
virustotal() {
    clear
    echo "========= VIRUSTOTAL ========="
    echo

    if env_has VT_API_KEY; then
        local existing
        existing="$(env_get VT_API_KEY)"
        echo "VirusTotal already configured: $(mask_secret "$existing")"
        if ! confirm "Replace existing key?"; then
            pause
            return
        fi
    fi

    read -r -s -p "Enter VirusTotal API Key: " KEY
    echo
    KEY="$(echo "$KEY" | xargs)"

    if [ -z "$KEY" ]; then
        fail "API key cannot be empty."
        pause
        return
    fi
    if ! validate_vt_key "$KEY"; then
        fail "That doesn't look like a valid VirusTotal API key (expected 64 hex characters)."
        pause
        return
    fi

    info "Verifying key against VirusTotal API..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -H "x-apikey: $KEY" "https://www.virustotal.com/api/v3/users/${KEY:0:8}" || echo "000")

    # VT returns 200/404 for a reachable+valid key depending on endpoint; 401/403 = bad key
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        fail "VirusTotal rejected this key (HTTP $http_code). Not saved."
    elif [ "$http_code" = "000" ]; then
        warn "Could not reach VirusTotal to verify (network issue). Saving key anyway."
        env_set VT_API_KEY "$KEY"
        ok "Saved (unverified)."
    else
        env_set VT_API_KEY "$KEY"
        ok "VirusTotal key saved."
    fi

    pause
}

# ---------------------------------------------------------------------------
# Settings — general values reserved for future features (e.g. a manager-
# side Active Response rollout). Stored in the same single vicisoc.env,
# never duplicated elsewhere.
# ---------------------------------------------------------------------------
settings() {
    clear
    echo "========= SETTINGS ========="
    echo

    local cur_mgr cur_alma cur_bt
    cur_mgr="$(env_get MANAGER_IP 2>/dev/null || echo "not set")"
    cur_alma="$(env_get ALMA_SERVER_IP 2>/dev/null || echo "not set")"
    cur_bt="$(env_get BLOCK_TIME 2>/dev/null || echo "not set")"

    echo "Current values:"
    echo "  MANAGER_IP     : $cur_mgr"
    echo "  ALMA_SERVER_IP : $cur_alma"
    echo "  BLOCK_TIME     : $cur_bt (seconds — reserved for future Active Response use)"
    echo

    if ! confirm "Update settings now?"; then
        pause
        return
    fi

    read -r -p "Wazuh Manager IP [$cur_mgr]: " MGR
    MGR="$(echo "$MGR" | xargs)"
    if [ -n "$MGR" ]; then
        if validate_ip "$MGR"; then
            env_set MANAGER_IP "$MGR"
            ok "MANAGER_IP saved."
        else
            fail "Invalid IP format. MANAGER_IP not changed."
        fi
    fi

    read -r -p "AlmaLinux Server IP [$cur_alma]: " ALMA
    ALMA="$(echo "$ALMA" | xargs)"
    if [ -n "$ALMA" ]; then
        if validate_ip "$ALMA"; then
            env_set ALMA_SERVER_IP "$ALMA"
            ok "ALMA_SERVER_IP saved."
        else
            fail "Invalid IP format. ALMA_SERVER_IP not changed."
        fi
    fi

    read -r -p "Block Time in seconds [$cur_bt]: " BT
    BT="$(echo "$BT" | xargs)"
    if [ -n "$BT" ]; then
        if validate_positive_int "$BT"; then
            env_set BLOCK_TIME "$BT"
            ok "BLOCK_TIME saved."
        else
            fail "Must be a positive integer. BLOCK_TIME not changed."
        fi
    fi

    pause
}

# ---------------------------------------------------------------------------
# Log monitoring (idempotent XML injection)
# ---------------------------------------------------------------------------
logs() {
    clear
    echo "========= LOG MONITORING ========="
    echo

    if ! wazuh_installed; then
        fail "Wazuh not installed."
        pause
        return
    fi

    if xml_block_present "$LOG_MARKER"; then
        warn "Log monitoring already configured by ViciSOC. Skipping (idempotent)."
        pause
        return
    fi

    local block
    block=$(cat <<'EOF'
<localfile>
  <location>/var/log/secure</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/asterisk/messages</location>
  <log_format>syslog</log_format>
</localfile>
EOF
)
    inject_xml_block "$LOG_MARKER" "$block" && ok "Log monitoring enabled." || fail "Log monitoring not applied."
    pause
}

# ---------------------------------------------------------------------------
# File Integrity Monitoring (idempotent XML injection)
# ---------------------------------------------------------------------------
fim() {
    clear
    echo "========= FILE INTEGRITY MONITORING ========="
    echo

    if ! wazuh_installed; then
        fail "Wazuh not installed."
        pause
        return
    fi

    if xml_block_present "$FIM_MARKER"; then
        warn "FIM already configured by ViciSOC. Skipping (idempotent)."
        pause
        return
    fi

    local dirs
    dirs=$(cat <<'EOF'
  <directories realtime="yes">/etc/ssh</directories>
  <directories realtime="yes">/etc/asterisk</directories>
  <directories realtime="yes">/root</directories>
  <directories realtime="yes">/var/www/html</directories>
EOF
)

    local backup
    backup="$(backup_file "$OSSEC_CONF")"
    ok "Backed up ossec.conf to $backup"

    local inserted=false
    if grep -q -F "<syscheck>" "$OSSEC_CONF"; then
        # A <syscheck> block already exists (stock agent configs usually
        # ship with one) — merge our <directories> into it rather than
        # adding a second, potentially conflicting <syscheck> block.
        info "Existing <syscheck> block found — merging directories into it."
        local content
        content="$(printf '%s\n%s' "$FIM_MARKER" "$dirs")"
        if insert_before_tag "$OSSEC_CONF" "$content" "</syscheck>" "first"; then
            inserted=true
        fi
    else
        info "No existing <syscheck> block — creating a new one."
        local block
        block="$(printf '<syscheck>\n%s\n</syscheck>' "$dirs")"
        local content
        content="$(printf '%s\n%s' "$FIM_MARKER" "$block")"
        if insert_before_tag "$OSSEC_CONF" "$content" "</ossec_config>" "last"; then
            inserted=true
        fi
    fi

    if ! $inserted; then
        fail "Could not find a safe insertion point (</syscheck> or </ossec_config>). No changes made."
        pause
        return
    fi

    commit_and_verify "$backup" && ok "FIM enabled." || fail "FIM not applied (rolled back)."
    pause
}

# ---------------------------------------------------------------------------
# Active Response — PLACEHOLDER ONLY.
#
# This does not install, generate, or execute any scripts, and it does not
# touch iptables/firewalld/nftables. It only reserves a documented, clearly
# commented-out section inside ossec.conf so a future version of ViciSOC
# (or a manual admin) has an obvious, safe place to wire up real Active
# Response commands later — on the Wazuh manager, where that config
# actually belongs.
# ---------------------------------------------------------------------------
active_response_placeholder() {
    clear
    echo "========= ACTIVE RESPONSE (FUTURE PLACEHOLDER) ========="
    echo
    echo "This option does NOT install any scripts and does NOT touch your"
    echo "firewall. It only adds a commented-out, documented placeholder"
    echo "block to ossec.conf so real Active Response commands can be"
    echo "wired up later. Real Active Response <command>/<active-response>"
    echo "stanzas belong on the Wazuh manager, not the agent."
    echo

    if ! wazuh_installed; then
        fail "Wazuh not installed."
        pause
        return
    fi

    if xml_block_present "$AR_MARKER"; then
        warn "Active Response placeholder already present. Skipping (idempotent)."
        pause
        return
    fi

    if ! confirm "Insert the Active Response placeholder into ossec.conf?"; then
        pause
        return
    fi

    local block
    block=$(cat <<'EOF'
<!-- ============================================================== -->
<!-- ViciSOC Active Response placeholder.                            -->
<!-- Nothing below is active. No commands run from this block.       -->
<!--                                                                  -->
<!-- Example of what a real Active Response wiring looks like        -->
<!-- (this belongs on the Wazuh MANAGER, not this agent config):     -->
<!--                                                                  -->
<!--   <command>                                                     -->
<!--     <name>block-ip</name>                                       -->
<!--     <executable>block-ip.sh</executable>                        -->
<!--     <timeout_allowed>yes</timeout_allowed>                      -->
<!--   </command>                                                    -->
<!--                                                                  -->
<!--   <active-response>                                             -->
<!--     <command>block-ip</command>                                 -->
<!--     <location>local</location>                                  -->
<!--     <rules_id>5710</rules_id>                                   -->
<!--     <timeout>3600</timeout>                                     -->
<!--   </active-response>                                            -->
<!-- ============================================================== -->
EOF
)
    inject_xml_block "$AR_MARKER" "$block" \
        && ok "Active Response placeholder inserted." \
        || fail "Placeholder not applied."
    pause
}

# ---------------------------------------------------------------------------
# Slack alerting for FIM / log-monitoring alerts.
#
# This is the actual fix for "changing the webhook doesn't change FIM
# alerts": FIM notifications are generated by Wazuh's own alert pipeline
# (analysisd -> wazuh-integratord), NOT by this installer polling files.
# The only correct way to change what FIM alerts say/where they go is to
# give wazuh-integratord a script to call, which is what this installs:
#
#   1. A script at /var/ossec/integrations/custom-vicisoc-slack that
#      wazuh-integratord invokes for each matching alert. It reads
#      SLACK_WEBHOOK live from vicisoc.env on every single invocation
#      (via a strict parser, never `source`), formats the message, and
#      posts it. Change the webhook in Slack Setup and the very next
#      alert uses it — nothing else to edit.
#   2. An <integration> block in ossec.conf telling Wazuh to call that
#      script for alerts at/above a given level (default: 7, matching
#      typical FIM alert severity).
#
# IMPORTANT — read before running: wazuh-integratord (the component that
# actually calls this script) runs on a Wazuh MANAGER or a local/
# standalone install. It does NOT run on a plain forwarding agent. If
# this box only runs wazuh-agent and ships alerts to a separate manager,
# install this on the manager instead — installing it here will silently
# do nothing.
# ---------------------------------------------------------------------------
install_slack_integration_script() {
    cat > "$SLACK_INTEGRATION_SCRIPT" <<'INTEGRATION_EOF'
#!/bin/bash
#
# ViciSOC Slack integration for Wazuh alerts (FIM/log monitoring).
# Installed and owned by install.sh — do not hand-edit the env-reading
# logic below; it intentionally never sources or executes vicisoc.env.
set -uo pipefail

ALERT_FILE="${1:-}"
ENV_FILE="/opt/vicisoc/vicisoc.env"
LOG_FILE="/opt/vicisoc/logs/vicisoc-slack.log"
MIN_LEVEL="7"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || true; }

if [ -z "$ALERT_FILE" ] || [ ! -f "$ALERT_FILE" ]; then
    log "ERROR: missing/invalid alert file argument ('$ALERT_FILE')"
    exit 0
fi

# Strict, safe env read: only ever parses KEY="VALUE" lines out of a file
# that must be owned by root and mode 600/400. Never sources/executes it.
env_get_secure() {
    local key="$1"
    [ -f "$ENV_FILE" ] || return 1
    local perm owner
    perm=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo "")
    owner=$(stat -c '%U' "$ENV_FILE" 2>/dev/null || echo "")
    if [ "$owner" != "root" ] || { [ "$perm" != "600" ] && [ "$perm" != "400" ]; }; then
        log "ERROR: refusing to read $ENV_FILE (owner=$owner perm=$perm, expected root/600)"
        return 1
    fi
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d'=' -f2- | sed -e 's/^"//' -e 's/"$//'
}

WEBHOOK="$(env_get_secure SLACK_WEBHOOK || true)"
if [ -z "$WEBHOOK" ]; then
    log "SKIP: SLACK_WEBHOOK not configured in $ENV_FILE"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    log "ERROR: python3 not found, cannot parse alert JSON"
    exit 0
fi

MESSAGE="$(python3 - "$ALERT_FILE" "$MIN_LEVEL" <<'PYEOF'
import json, sys

path, min_level = sys.argv[1], int(sys.argv[2])
try:
    with open(path) as f:
        a = json.load(f)
except Exception:
    sys.exit(0)

level = int(a.get("rule", {}).get("level", 0) or 0)
if level < min_level:
    sys.exit(0)

host    = a.get("agent", {}).get("name", "unknown")
rule_id = a.get("rule", {}).get("id", "?")
desc    = a.get("rule", {}).get("description", "")
sc      = a.get("syscheck", {})
path_   = sc.get("path", a.get("full_log", "n/a"))
event   = sc.get("event", "n/a")
sha_old = sc.get("sha256_before", "")
sha_new = sc.get("sha256_after", "")
ts      = a.get("timestamp", "n/a")

lines = [
    "\U0001F4C1 File Integrity Change", "",
    f"Host: {host}",
    f"Rule: {rule_id}" + (f" ({desc})" if desc else ""),
    f"Level: {level}", "",
    "File:", path_, "",
    "Event:", event,
]
if sha_old:
    lines += ["", "Old SHA256:", sha_old]
if sha_new:
    lines += ["", "New SHA256:", sha_new]
lines += ["", "Time:", ts]

print("\n".join(lines))
PYEOF
)"

if [ -z "$MESSAGE" ]; then
    log "SKIP: alert below threshold (level < $MIN_LEVEL) or unparseable"
    exit 0
fi

PAYLOAD="$(python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1]}))' "$MESSAGE")"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST -H "Content-Type: application/json" \
    -d "$PAYLOAD" "$WEBHOOK" 2>>"$LOG_FILE" || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    log "OK: alert forwarded to Slack"
else
    log "FAIL: Slack POST returned HTTP $HTTP_CODE"
fi
exit 0
INTEGRATION_EOF

    chmod 750 "$SLACK_INTEGRATION_SCRIPT"
    chown root:root "$SLACK_INTEGRATION_SCRIPT"
}

slack_fim_alerts() {
    clear
    echo "========= SLACK ALERTS FOR FIM / LOG MONITORING ========="
    echo
    echo "Installs the actual Wazuh integration that generates FIM/log"
    echo "alert messages and sends them to Slack. The webhook is always"
    echo "read live from $ENV_FILE — nothing is hardcoded"
    echo "into ossec.conf or the integration script."
    echo
    warn "wazuh-integratord (what actually runs this) lives on a Wazuh"
    warn "MANAGER or local/standalone install — NOT on a plain forwarding"
    warn "agent. If unsure, run this on the manager, not a dialer agent box."
    echo

    if ! wazuh_installed; then
        fail "Wazuh not installed."
        pause
        return
    fi

    if ! env_has SLACK_WEBHOOK; then
        fail "Configure Slack first (main menu -> Slack Setup)."
        pause
        return
    fi

    if [ ! -d /var/ossec/integrations ]; then
        fail "/var/ossec/integrations not found. This does not look like a Wazuh manager/local install — aborting."
        pause
        return
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 is required to parse alert JSON but was not found."
        if confirm "Install python3 with dnf now?"; then
            if dnf install -y python3 >>"$LOG_FILE" 2>&1; then
                ok "python3 installed."
            else
                fail "Failed to install python3."
                pause
                return
            fi
        else
            fail "Cannot continue without python3."
            pause
            return
        fi
    fi

    if xml_block_present "$SLACK_INTEGRATION_MARKER"; then
        warn "Slack FIM/log alerting already configured by ViciSOC. Skipping (idempotent)."
        if confirm "Reinstall the integration script anyway (e.g. to pick up a fix)?"; then
            install_slack_integration_script
            ok "Integration script re-written at $SLACK_INTEGRATION_SCRIPT (ossec.conf unchanged)."
        fi
        pause
        return
    fi

    install_slack_integration_script
    ok "Installed Slack alert script: $SLACK_INTEGRATION_SCRIPT"

    # <hook_url> is required by ossec.conf's schema for an <integration>
    # block to be accepted, but this integration script deliberately
    # ignores whatever value is here and reads the real webhook live from
    # vicisoc.env instead — so this placeholder is never a real secret.
    local block
    block=$(cat <<EOF
<integration>
  <name>${SLACK_INTEGRATION_NAME}</name>
  <hook_url>https://hooks.slack.com/services/UNUSED-see-vicisoc.env</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
EOF
)
    inject_xml_block "$SLACK_INTEGRATION_MARKER" "$block" \
        && ok "Slack FIM/log alerting enabled (alerts level 7+)." \
        || fail "Integration not applied (rolled back)."
    pause
}

# ---------------------------------------------------------------------------
# Wazuh Integration submenu
# ---------------------------------------------------------------------------
wazuh_integration_menu() {
    while true; do
        clear
        echo "========= WAZUH INTEGRATION ========="
        echo
        echo "1  Log Monitoring"
        echo "2  File Integrity Monitoring"
        echo "3  Slack Alerts for FIM / Log Monitoring"
        echo "4  Active Response (Future Placeholder)"
        echo "0  Back to Main Menu"
        echo "======================================"
        read -r -p "Select: " SUBOP

        case "$SUBOP" in
            1) logs ;;
            2) fim ;;
            3) slack_fim_alerts ;;
            4) active_response_placeholder ;;
            0) return ;;
            *) echo "Invalid option."; sleep 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Verify installation
# ---------------------------------------------------------------------------
verify() {
    clear
    echo "========= VERIFY INSTALLATION ========="
    echo

    local all_ok=true

    if wazuh_installed; then
        ok "ossec.conf present: $OSSEC_CONF"
        if xmllint --noout "$OSSEC_CONF" 2>>"$LOG_FILE"; then
            ok "ossec.conf is valid XML"
        else
            fail "ossec.conf has XML errors"
            all_ok=false
        fi
        local svc
        svc="$(wazuh_service_name)"
        if systemctl is-active --quiet "$svc"; then
            ok "$svc service is active"
        else
            fail "$svc service is NOT active"
            all_ok=false
        fi
    else
        fail "Wazuh not installed"
        all_ok=false
    fi

    if xml_block_present "$LOG_MARKER" 2>/dev/null; then
        ok "Log Monitoring configured"
    else
        warn "Log Monitoring not configured"
    fi

    if xml_block_present "$FIM_MARKER" 2>/dev/null; then
        ok "File Integrity Monitoring configured"
    else
        warn "File Integrity Monitoring not configured"
    fi

    if xml_block_present "$AR_MARKER" 2>/dev/null; then
        ok "Active Response Placeholder present"
    else
        warn "Active Response Placeholder not configured (optional)"
    fi

    if xml_block_present "$SLACK_INTEGRATION_MARKER" 2>/dev/null; then
        if [ -f "$SLACK_INTEGRATION_SCRIPT" ]; then
            ok "Slack FIM/log alerting integration installed and wired"
        else
            fail "ossec.conf references the Slack integration but $SLACK_INTEGRATION_SCRIPT is missing"
            all_ok=false
        fi
    else
        warn "Slack FIM/log alerting not configured (optional)"
    fi

    local perm
    perm=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo "??")
    if [ "$perm" = "600" ]; then
        ok "$ENV_FILE permissions correct (600)"
    else
        warn "$ENV_FILE permissions are $perm (expected 600)"
    fi

    echo
    if $all_ok; then
        ok "Installation Successful — all core checks passed."
    else
        warn "Some checks failed. Review the output above and $LOG_FILE."
    fi
    pause
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
menu() {
    while true; do
        clear
        status
        echo "===================================="
        echo "1  System Check"
        echo "2  Slack Setup"
        echo "3  VirusTotal Setup"
        echo "4  Settings"
        echo "5  Wazuh Integration"
        echo "6  Verify Installation"
        echo "0  Exit"
        echo "===================================="
        read -r -p "Select: " OP

        case "$OP" in
            1) system_check ;;
            2) slack ;;
            3) virustotal ;;
            4) settings ;;
            5) wazuh_integration_menu ;;
            6) verify ;;
            0) echo "Goodbye."; exit 0 ;;
            *) echo "Invalid option."; sleep 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    root_check
    writable_check "$BASE"
    detect_os
    init
    acquire_lock
    check_dependencies
    menu
}

main "$@"
