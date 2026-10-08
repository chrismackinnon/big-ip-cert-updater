#!/bin/bash
# =============================================================================
#  certrotate.sh - BIG-IP SSL certificate / key rotation for client-ssl and
#                  server-ssl profiles. Designed to run from cron or iCall.
#
#  What it does, per job (one job = one jobs.d/*.conf file):
#    1. Fetch a new cert/key (+ optional chain) from a local drop dir, SCP or HTTPS
#    2. Skip if this exact certificate was already applied (SHA-256 fingerprint)
#    3. Validate: PEM parses, key matches cert, not expired / not expiring soon,
#       not "not-yet-valid", chain actually issues the leaf, expected name in SAN,
#       RSA >= 2048
#    4. Import as NEW, versioned objects   <prefix>_<YYYYmmddHHMMSS>.crt/.key
#       (never overwrites an object that is live in a profile)
#    5. Re-point the profile in ONE tmsh command (atomic cert+key+chain swap),
#       or create a new profile (and optionally attach it to a virtual server)
#    6. Verify the profile now references the new objects; optional live TLS
#       check against a VIP. Automatic rollback on any failure.
#    7. Prune old versions, save config, config-sync to the device group
#
#  Safe-by-default behaviour:
#    - Only runs on the ACTIVE unit (standby exits quietly) - same script can be
#      scheduled on both HA peers
#    - Will not auto-sync if the device group was already out of sync before the
#      run (avoids pushing someone else's half-finished changes)
#    - flock prevents overlapping runs
#    - -n (dry run) prints every tmsh change without making it
#
#  Usage:  certrotate.sh [-n] [-f] [-v] [-j <job>] [-c <global.conf>]
#            -n  dry run        -f  force re-apply even if fingerprint unchanged
#            -j  run one job    -c  alternate global config file
#            -v  log to stdout even when not on a terminal (remote/automation)
#            -t  test job configuration only (profile found? which entry?) - no files needed
#
#  Tested logic against TMOS 15.1 / 16.1 / 17.x tmsh syntax. Validate in a lab
#  (or with -n) before scheduling in production.
# =============================================================================

set -o pipefail
umask 077
PATH=/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin:${PATH}

VERSION="1.2.0"

# ----------------------------------------------------------------- defaults --
BASE_DIR="${CERTROTATE_BASE:-/shared/certrotate}"
GLOBAL_CONF="${BASE_DIR}/certrotate.conf"

JOBS_DIR=""            # derived from BASE_DIR after config load if unset
STAGING_DIR=""
ARCHIVE_DIR=""
FAILED_DIR=""
STATE_DIR=""
LOG_FILE="/var/log/certrotate.log"
LOCK_FILE="/var/run/certrotate.lock"
SYSLOG_TAG="certrotate"
SYSLOG_FACILITY="local0"   # local0 lands in /var/log/ltm on BIG-IP

REQUIRE_ACTIVE="yes"       # only act on the Active unit
SYNC_GROUP=""              # sync-failover device group to push to (blank = no sync)
SYNC_ONLY_IF_CLEAN="yes"   # do not sync if group was not "In Sync" before we started
SAVE_CONFIG="yes"
DRY_RUN="no"
FORCE="no"
ONLY_JOB=""
VERBOSE="no"
TEST_ONLY="no"

TMSH="${TMSH:-tmsh}"
OPENSSL="${OPENSSL:-openssl}"

TS="$(date +%Y%m%d%H%M%S)"
OVERALL_RC=0

# ------------------------------------------------------------------ logging --
log() {   # log <level> <message...>
    local lvl="$1"; shift
    local msg="$*"
    local line
    line="$(date '+%Y-%m-%d %H:%M:%S') [${lvl}] ${JOB:+[${JOB}] }${msg}"
    echo "${line}" >>"${LOG_FILE}" 2>/dev/null
    { [ -t 1 ] || [ "${VERBOSE}" = "yes" ]; } && echo "${line}"
    case "${lvl}" in
        ERROR) logger -p "${SYSLOG_FACILITY}.err"    -t "${SYSLOG_TAG}" -- "${JOB:+[${JOB}] }${msg}" 2>/dev/null ;;
        WARN)  logger -p "${SYSLOG_FACILITY}.warning" -t "${SYSLOG_TAG}" -- "${JOB:+[${JOB}] }${msg}" 2>/dev/null ;;
        NOTICE) logger -p "${SYSLOG_FACILITY}.notice" -t "${SYSLOG_TAG}" -- "${JOB:+[${JOB}] }${msg}" 2>/dev/null ;;
    esac
    return 0
}

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# --------------------------------------------------------------- tmsh glue --
# tmq: read-only tmsh (always executed). tmc: config change (skipped in dry run)
tmq() { "${TMSH}" -c "$*" 2>&1; }

tmc() {
    if [ "${DRY_RUN}" = "yes" ]; then
        log INFO "DRY-RUN tmsh: $*"
        return 0
    fi
    local out rc
    out="$("${TMSH}" -c "$*" 2>&1)"; rc=$?
    # tmsh sometimes returns 0 but prints an error
    if [ ${rc} -ne 0 ] || echo "${out}" | grep -qiE '^(01[0-9a-f]{6}:[0-9]+:|Syntax Error|Data Input Error)'; then
        log ERROR "tmsh failed (rc=${rc}): $*"
        [ -n "${out}" ] && log ERROR "tmsh said: ${out}"
        return 1
    fi
    log INFO "tmsh ok: $*"
    return 0
}

obj_exists() {  # obj_exists "<tmsh path e.g. sys file ssl-cert>" "<full name>"
    "${TMSH}" -c "list $1 $2" >/dev/null 2>&1
}

strip_part() {  # normalise /Common/foo.crt -> foo.crt for comparisons
    local v="$1"
    v="${v#/${PARTITION}/}"
    echo "${v}"
}

# Print names of the direct children of block <blk> from tmsh "list" output
#   e.g. cert-key-chain entries, or virtual server profiles
child_names() {
    awk -v blk="$1" '
    {
        line=$0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
        if (!inblk) { if (line == blk " {") { inblk=1; depth=1 } ; next }
        if (line == "}")          { depth--; if (depth == 0) inblk=0; next }
        if (line ~ / \{ \}$/)     { if (depth == 1) { n=line; sub(/ \{ \}$/, "", n); print n }; next }
        if (line ~ / \{$/)        { if (depth == 1) { n=line; sub(/ \{$/, "", n); print n }; depth++; next }
    }'
}

# Print attribute <attr> of child <child> inside block <blk>
child_attr() {
    awk -v blk="$1" -v child="$2" -v attr="$3" '
    {
        line=$0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
        if (!inblk) { if (line == blk " {") { inblk=1; depth=1 } ; next }
        if (line == "}") { if (depth == 2 && inchild) inchild=0; depth--; if (depth == 0) inblk=0; next }
        if (line ~ / \{ \}$/) next
        if (line ~ / \{$/) { if (depth == 1 && line == child " {") inchild=1; depth++; next }
        if (inchild && depth == 2) { split(line, f, " "); if (f[1] == attr) { print f[2]; exit } }
    }'
}

# --------------------------------------------------------- HA / mcpd state --
failover_state() {
    local st=""
    [ -r /var/prompt/ps1 ] && st="$(cat /var/prompt/ps1 2>/dev/null)"
    if [ -z "${st}" ]; then
        st="$(tmq "show cm failover-status" | awk '/^Status/ {print $2; exit}')"
    fi
    echo "${st}"
}

sync_status() {
    local st=""
    [ -r /var/prompt/cmiSyncStatus ] && st="$(cat /var/prompt/cmiSyncStatus 2>/dev/null)"
    if [ -z "${st}" ]; then
        st="$(tmq "show cm sync-status" | awk '/^Status/ {sub(/^Status[ \t]+/, ""); print; exit}')"
    fi
    echo "${st}"
}

mcpd_running() {
    tmq "show sys mcp-state field-fmt" | grep -q "phase running"
}

# ------------------------------------------------------------ cert helpers --
fp_sha256() { "${OPENSSL}" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':'; }

pem_count() { grep -c -- '-----BEGIN CERTIFICATE-----' "$1" 2>/dev/null; }

# split a PEM bundle: first cert -> $2, remainder -> $3
split_bundle() {
    awk -v leaf="$2" -v rest="$3" '
        /-----BEGIN CERTIFICATE-----/ { n++ }
        n == 1 { print > leaf }
        n >  1 { print > rest }
    ' "$1"
}

date_to_epoch() { date -d "$1" +%s 2>/dev/null; }

secure_rm() {
    local f
    for f in "$@"; do
        [ -f "${f}" ] || continue
        shred -u "${f}" 2>/dev/null || rm -f "${f}"
    done
}

# ======================================================================= JOB ==
reset_job_vars() {
    JOB=""
    SOURCE_TYPE="local"          # local | scp | https
    SOURCE_DIR=""                # local: drop directory
    SOURCE_SCP=""                # scp: user@host:/remote/dir
    SCP_KEY="/root/.ssh/id_rsa"
    SOURCE_URL=""                # https: base URL (files appended)
    CURL_OPTS=""                 # extra curl args, e.g. --cacert /shared/ca.pem
    CERT_FILE="cert.pem"         # leaf cert (or full-chain bundle)
    KEY_FILE="key.pem"
    CHAIN_FILE="chain.pem"       # optional; blank or missing = none / derive from bundle
    KEY_PASSFILE=""              # file holding passphrase if key is encrypted
    STABLE_SECONDS=60            # local: files must be unchanged this long
    READY_MARKER=""              # local: optional marker file that must exist

    PARTITION="Common"
    OBJ_PREFIX=""                # e.g. www.example.com  -> www.example.com_<ts>.crt
    PROFILE_TYPE="client-ssl"    # client-ssl | server-ssl
    PROFILE_NAME=""
    CREATE_IF_MISSING="no"       # create PROFILE_NAME if it does not exist
    PARENT_PROFILE=""            # defaults-from for new profiles
    CKC_ENTRY=""                 # client-ssl cert-key-chain entry to replace (auto if only one)
    SNI_SERVER_NAME=""           # new client-ssl: server-name (SNI)
    SNI_DEFAULT="false"          # new client-ssl: sni-default
    ATTACH_VIRTUAL=""            # new profile: attach to this virtual server
    ATTACH_MODE="add"            # add (only if VS has no profile of this type) | replace

    MIN_DAYS_VALID=7             # refuse certs expiring within N days
    EXPECT_NAME=""               # require this DNS name in SAN (wildcards honoured)
    REQUIRE_CHAIN="yes"          # refuse a CA-issued leaf with no chain
    MIN_RSA_BITS=2048
    VERIFY_HOST=""               # live TLS check after apply (client-ssl)
    VERIFY_PORT=443
    VERIFY_SNI=""
    RETAIN_VERSIONS=2            # versions of <prefix>_* objects to keep (incl. current)
    ARCHIVE_KEYS="no"            # keep a copy of the private key in archive dir?
}

validate_job_conf() {
    local ok=0
    [ -n "${OBJ_PREFIX}" ]   || { log ERROR "OBJ_PREFIX not set"; ok=1; }
    [ -n "${PROFILE_NAME}" ] || { log ERROR "PROFILE_NAME not set"; ok=1; }
    case "${PROFILE_TYPE}" in client-ssl|server-ssl) ;; *) log ERROR "PROFILE_TYPE must be client-ssl or server-ssl"; ok=1 ;; esac
    case "${SOURCE_TYPE}" in
        local) [ -n "${SOURCE_DIR}" ] || { log ERROR "SOURCE_DIR not set"; ok=1; } ;;
        scp)   [ -n "${SOURCE_SCP}" ] || { log ERROR "SOURCE_SCP not set"; ok=1; } ;;
        https) [ -n "${SOURCE_URL}" ] || { log ERROR "SOURCE_URL not set"; ok=1; } ;;
        *) log ERROR "SOURCE_TYPE must be local, scp or https"; ok=1 ;;
    esac
    if [ "${CREATE_IF_MISSING}" = "yes" ] && [ -z "${PARENT_PROFILE}" ]; then
        PARENT_PROFILE="/Common/${PROFILE_TYPE//-/}"   # /Common/clientssl or /Common/serverssl
    fi
    if ! echo "${OBJ_PREFIX}" | grep -qE '^[A-Za-z0-9._-]+$'; then
        log ERROR "OBJ_PREFIX may only contain A-Z a-z 0-9 . _ -"; ok=1
    fi
    case "${PROFILE_NAME}" in /*) ;; *) PROFILE_NAME="/${PARTITION}/${PROFILE_NAME}" ;; esac
    if [ -n "${ATTACH_VIRTUAL}" ]; then
        case "${ATTACH_VIRTUAL}" in /*) ;; *) ATTACH_VIRTUAL="/${PARTITION}/${ATTACH_VIRTUAL}" ;; esac
    fi
    return ${ok}
}

# ---------------------------------------------------------------- fetch --
# Populates ${STG}/cert.pem ${STG}/key.pem [${STG}/chain.pem]
# Returns 0 = files fetched, 3 = nothing to do, 1 = error
fetch_files() {
    rm -rf "${STG}"; mkdir -p "${STG}" && chmod 700 "${STG}" || return 1

    case "${SOURCE_TYPE}" in
    local)
        local c="${SOURCE_DIR}/${CERT_FILE}" k="${SOURCE_DIR}/${KEY_FILE}" now age f
        [ -f "${c}" ] && [ -f "${k}" ] || return 3
        if [ -n "${READY_MARKER}" ] && [ ! -f "${SOURCE_DIR}/${READY_MARKER}" ]; then
            log INFO "files present but ready marker '${READY_MARKER}' missing - waiting"; return 3
        fi
        now=$(date +%s)
        for f in "${c}" "${k}"; do
            age=$(( now - $(stat -c %Y "${f}") ))
            if [ "${age}" -lt "${STABLE_SECONDS}" ]; then
                log INFO "$(basename "${f}") modified ${age}s ago (<${STABLE_SECONDS}s) - waiting for upload to settle"
                return 3
            fi
        done
        cp -p "${c}" "${STG}/cert.pem" && cp -p "${k}" "${STG}/key.pem" || return 1
        if [ -n "${CHAIN_FILE}" ] && [ -f "${SOURCE_DIR}/${CHAIN_FILE}" ]; then
            cp -p "${SOURCE_DIR}/${CHAIN_FILE}" "${STG}/chain.pem" || return 1
        fi
        ;;
    scp)
        local sopts=(-q -B -o ConnectTimeout=15 -o StrictHostKeyChecking=yes)
        [ -n "${SCP_KEY}" ] && sopts+=(-i "${SCP_KEY}")
        scp "${sopts[@]}" "${SOURCE_SCP}/${CERT_FILE}" "${STG}/cert.pem" || { log ERROR "scp of cert failed"; return 1; }
        scp "${sopts[@]}" "${SOURCE_SCP}/${KEY_FILE}"  "${STG}/key.pem"  || { log ERROR "scp of key failed";  return 1; }
        if [ -n "${CHAIN_FILE}" ]; then
            scp "${sopts[@]}" "${SOURCE_SCP}/${CHAIN_FILE}" "${STG}/chain.pem" 2>/dev/null \
                || { rm -f "${STG}/chain.pem"; log INFO "no chain file at source (ok if cert is a bundle)"; }
        fi
        ;;
    https)
        # shellcheck disable=SC2086  # CURL_OPTS is intentionally word-split
        curl -fsS --max-time 60 ${CURL_OPTS} -o "${STG}/cert.pem" "${SOURCE_URL}/${CERT_FILE}" || { log ERROR "download of cert failed"; return 1; }
        # shellcheck disable=SC2086
        curl -fsS --max-time 60 ${CURL_OPTS} -o "${STG}/key.pem"  "${SOURCE_URL}/${KEY_FILE}"  || { log ERROR "download of key failed";  return 1; }
        if [ -n "${CHAIN_FILE}" ]; then
            # shellcheck disable=SC2086
            curl -fsS --max-time 60 ${CURL_OPTS} -o "${STG}/chain.pem" "${SOURCE_URL}/${CHAIN_FILE}" 2>/dev/null \
                || { rm -f "${STG}/chain.pem"; log INFO "no chain file at source (ok if cert is a bundle)"; }
        fi
        ;;
    esac
    chmod 600 "${STG}"/* 2>/dev/null
    return 0
}

# ------------------------------------------------------------- validation --
validate_material() {
    local cert="${STG}/cert.pem" key="${STG}/key.pem" chain="${STG}/chain.pem"
    local n

    # Full-chain bundle in cert file? split it.
    n=$(pem_count "${cert}")
    if [ "${n:-0}" -eq 0 ]; then log ERROR "cert file contains no PEM certificate"; return 1; fi
    if [ "${n}" -gt 1 ]; then
        split_bundle "${cert}" "${STG}/leaf.pem" "${STG}/bundle_chain.pem"
        mv "${STG}/leaf.pem" "${cert}"
        if [ ! -s "${chain}" ]; then mv "${STG}/bundle_chain.pem" "${chain}"; else rm -f "${STG}/bundle_chain.pem"; fi
        log INFO "cert file was a ${n}-cert bundle; split into leaf + chain"
    fi
    [ -s "${chain}" ] || rm -f "${chain}"

    "${OPENSSL}" x509 -in "${cert}" -noout 2>/dev/null || { log ERROR "certificate does not parse"; return 1; }

    # Encrypted key -> decrypt into staging (imported without a passphrase)
    if grep -q 'ENCRYPTED' "${key}"; then
        [ -n "${KEY_PASSFILE}" ] && [ -r "${KEY_PASSFILE}" ] || { log ERROR "key is encrypted but KEY_PASSFILE not set/readable"; return 1; }
        "${OPENSSL}" pkey -in "${key}" -passin "file:${KEY_PASSFILE}" -out "${STG}/key.dec" 2>/dev/null \
            || { log ERROR "could not decrypt key with KEY_PASSFILE"; return 1; }
        secure_rm "${key}"; mv "${STG}/key.dec" "${key}"; chmod 600 "${key}"
    fi
    "${OPENSSL}" pkey -in "${key}" -noout 2>/dev/null || { log ERROR "private key does not parse"; return 1; }

    # Key <-> cert match (works for RSA and EC)
    local cpub kpub
    cpub=$("${OPENSSL}" x509 -in "${cert}" -noout -pubkey | "${OPENSSL}" sha256 | awk '{print $NF}')
    kpub=$("${OPENSSL}" pkey -in "${key}" -pubout 2>/dev/null | "${OPENSSL}" sha256 | awk '{print $NF}')
    if [ -z "${cpub}" ] || [ "${cpub}" != "${kpub}" ]; then
        log ERROR "private key does NOT match certificate public key"; return 1
    fi

    # Validity window
    local nb na nbe nae now
    nb=$("${OPENSSL}" x509 -in "${cert}" -noout -startdate | cut -d= -f2)
    na=$("${OPENSSL}" x509 -in "${cert}" -noout -enddate   | cut -d= -f2)
    nbe=$(date_to_epoch "${nb}"); nae=$(date_to_epoch "${na}"); now=$(date +%s)
    if [ -n "${nbe}" ] && [ "${nbe}" -gt $(( now + 300 )) ]; then
        log ERROR "certificate not valid until ${nb} - refusing (check BIG-IP clock/NTP too)"; return 1
    fi
    if ! "${OPENSSL}" x509 -in "${cert}" -noout -checkend $(( MIN_DAYS_VALID * 86400 )) >/dev/null; then
        log ERROR "certificate expires ${na} - less than MIN_DAYS_VALID=${MIN_DAYS_VALID} days"; return 1
    fi
    NEW_NOTAFTER="${na}"
    [ -n "${nae}" ] && NEW_DAYS_LEFT=$(( (nae - now) / 86400 ))

    # Key strength
    local text bits
    text=$("${OPENSSL}" x509 -in "${cert}" -noout -text)
    if echo "${text}" | grep -q 'rsaEncryption'; then
        bits=$(echo "${text}" | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1)
        if [ -n "${bits}" ] && [ "${bits}" -lt "${MIN_RSA_BITS}" ]; then
            log ERROR "RSA key is ${bits} bits (< ${MIN_RSA_BITS})"; return 1
        fi
        NEW_KEYTYPE="RSA-${bits}"
    else
        NEW_KEYTYPE="EC"
    fi

    # Expected name
    if [ -n "${EXPECT_NAME}" ]; then
        local sans wild
        sans=$(echo "${text}" | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ')
        wild="*.${EXPECT_NAME#*.}"
        if ! echo ",${sans}," | grep -qF ",DNS:${EXPECT_NAME}," && ! echo ",${sans}," | grep -qF ",DNS:${wild},"; then
            log ERROR "EXPECT_NAME ${EXPECT_NAME} not found in SAN (${sans:-none})"; return 1
        fi
    fi

    # Chain
    local subj iss
    subj=$("${OPENSSL}" x509 -in "${cert}" -noout -subject | sed 's/^subject= *//')
    iss=$("${OPENSSL}" x509 -in "${cert}" -noout -issuer  | sed 's/^issuer= *//')
    if [ -f "${chain}" ]; then
        "${OPENSSL}" crl2pkcs7 -nocrl -certfile "${chain}" >/dev/null 2>&1 || { log ERROR "chain file does not parse"; return 1; }
        if ! "${OPENSSL}" verify -partial_chain -CAfile "${chain}" "${cert}" >/dev/null 2>&1; then
            log ERROR "chain does not validate the leaf certificate (wrong/missing intermediate?)"; return 1
        fi
    elif [ "${subj}" != "${iss}" ] && [ "${REQUIRE_CHAIN}" = "yes" ]; then
        log ERROR "no chain supplied for a CA-issued certificate (set REQUIRE_CHAIN=no to allow)"; return 1
    fi

    NEW_FP=$(fp_sha256 "${cert}")
    NEW_SUBJECT="${subj}"
    log INFO "validated: ${NEW_SUBJECT}; ${NEW_KEYTYPE}; expires ${NEW_NOTAFTER} (${NEW_DAYS_LEFT:-?}d); sha256 ${NEW_FP}"
    return 0
}

# ------------------------------------------------------------ import objs --
import_objects() {
    NEW_CERT="/${PARTITION}/${OBJ_PREFIX}_${TS}.crt"
    NEW_KEY="/${PARTITION}/${OBJ_PREFIX}_${TS}.key"
    NEW_CHAIN="none"
    [ -f "${STG}/chain.pem" ] && NEW_CHAIN="/${PARTITION}/${OBJ_PREFIX}_${TS}_chain.crt"

    tmc "install sys crypto key ${NEW_KEY} from-local-file ${STG}/key.pem"   || return 1
    IMPORTED+=("ssl-key ${NEW_KEY}")
    tmc "install sys crypto cert ${NEW_CERT} from-local-file ${STG}/cert.pem" || return 1
    IMPORTED+=("ssl-cert ${NEW_CERT}")
    if [ "${NEW_CHAIN}" != "none" ]; then
        tmc "install sys crypto cert ${NEW_CHAIN} from-local-file ${STG}/chain.pem" || return 1
        IMPORTED+=("ssl-cert ${NEW_CHAIN}")
    fi
    return 0
}

remove_imported() {
    local o
    for o in "${IMPORTED[@]}"; do
        tmc "delete sys file ${o}" || log WARN "could not remove ${o} (remove manually)"
    done
}

# --------------------------------------------------------- profile changes --
profile_exists() { obj_exists "ltm profile ${PROFILE_TYPE}" "${PROFILE_NAME}"; }

# Records OLD_CERT/OLD_KEY/OLD_CHAIN (+ CKC_ENTRY for client-ssl)
snapshot_profile() {
    local out
    if [ "${PROFILE_TYPE}" = "client-ssl" ]; then
        out="$(tmq "list ltm profile client-ssl ${PROFILE_NAME} cert-key-chain")"
        local entries count
        entries="$(echo "${out}" | child_names "cert-key-chain")"
        count=$(echo "${entries}" | grep -c .)
        if [ -z "${CKC_ENTRY}" ]; then
            if [ "${count}" -eq 1 ]; then
                CKC_ENTRY="${entries}"
            elif [ "${count}" -eq 0 ]; then
                log ERROR "profile has no cert-key-chain entries (inherits from parent?) - set one explicitly first"; return 1
            else
                log ERROR "profile has ${count} cert-key-chain entries ($(echo "${entries}" | tr '\n' ' ')) - set CKC_ENTRY"; return 1
            fi
        elif ! echo "${entries}" | grep -qxF "${CKC_ENTRY}"; then
            log ERROR "CKC_ENTRY '${CKC_ENTRY}' not found in profile (have: $(echo "${entries}" | tr '\n' ' '))"; return 1
        fi
        OLD_CERT="$(echo "${out}" | child_attr "cert-key-chain" "${CKC_ENTRY}" cert)"
        OLD_KEY="$(echo "${out}"  | child_attr "cert-key-chain" "${CKC_ENTRY}" key)"
        OLD_CHAIN="$(echo "${out}" | child_attr "cert-key-chain" "${CKC_ENTRY}" chain)"
    else
        out="$(tmq "list ltm profile server-ssl ${PROFILE_NAME} cert key chain")"
        OLD_CERT="$(echo "${out}"  | awk '$1=="cert"  {print $2; exit}')"
        OLD_KEY="$(echo "${out}"   | awk '$1=="key"   {print $2; exit}')"
        OLD_CHAIN="$(echo "${out}" | awk '$1=="chain" {print $2; exit}')"
    fi
    [ -z "${OLD_CHAIN}" ] && OLD_CHAIN="none"
    log INFO "current binding: cert=${OLD_CERT:-none} key=${OLD_KEY:-none} chain=${OLD_CHAIN}${CKC_ENTRY:+ (entry ${CKC_ENTRY})}"
    if [ -z "${OLD_CERT}" ] || [ -z "${OLD_KEY}" ]; then
        log ERROR "could not read current cert/key from profile - aborting (nothing changed)"; return 1
    fi
    return 0
}

bind_profile() {   # bind_profile <cert> <key> <chain>  - single atomic tmsh command
    if [ "${PROFILE_TYPE}" = "client-ssl" ]; then
        tmc "modify ltm profile client-ssl ${PROFILE_NAME} cert-key-chain modify { ${CKC_ENTRY} { cert $1 key $2 chain $3 } }"
    else
        tmc "modify ltm profile server-ssl ${PROFILE_NAME} cert $1 key $2 chain $3"
    fi
}

create_profile() {
    if [ "${PROFILE_TYPE}" = "client-ssl" ]; then
        local sni=""
        [ -n "${SNI_SERVER_NAME}" ] && sni=" server-name ${SNI_SERVER_NAME} sni-default ${SNI_DEFAULT}"
        CKC_ENTRY="${OBJ_PREFIX}"
        tmc "create ltm profile client-ssl ${PROFILE_NAME} defaults-from ${PARENT_PROFILE} cert-key-chain replace-all-with { ${CKC_ENTRY} { cert ${NEW_CERT} key ${NEW_KEY} chain ${NEW_CHAIN} } }${sni}"
    else
        tmc "create ltm profile server-ssl ${PROFILE_NAME} defaults-from ${PARENT_PROFILE} cert ${NEW_CERT} key ${NEW_KEY} chain ${NEW_CHAIN}"
    fi
}

# Returns profile names of PROFILE_TYPE currently on ATTACH_VIRTUAL
vs_profiles_of_type() {
    local p full
    tmq "list ltm virtual ${ATTACH_VIRTUAL} profiles" | child_names "profiles" | while read -r p; do
        [ -z "${p}" ] && continue
        case "${p}" in /*) full="${p}" ;; *) full="/${PARTITION}/${p}" ;; esac
        obj_exists "ltm profile ${PROFILE_TYPE}" "${full}" && echo "${full}"
    done
}

attach_profile() {
    local ctx="clientside"; [ "${PROFILE_TYPE}" = "server-ssl" ] && ctx="serverside"
    obj_exists "ltm virtual" "${ATTACH_VIRTUAL}" || { log ERROR "virtual ${ATTACH_VIRTUAL} not found"; return 1; }
    local existing; existing="$(vs_profiles_of_type)"
    if [ -z "${existing}" ]; then
        tmc "modify ltm virtual ${ATTACH_VIRTUAL} profiles add { ${PROFILE_NAME} { context ${ctx} } }" || return 1
        DETACHED=""
    elif [ "${ATTACH_MODE}" = "replace" ]; then
        if [ "$(echo "${existing}" | grep -c .)" -ne 1 ]; then
            log ERROR "virtual has multiple ${PROFILE_TYPE} profiles (SNI set) - refusing automatic replace"; return 1
        fi
        tmc "create cli transaction; modify ltm virtual ${ATTACH_VIRTUAL} profiles delete { ${existing} }; modify ltm virtual ${ATTACH_VIRTUAL} profiles add { ${PROFILE_NAME} { context ${ctx} } }; submit cli transaction" || return 1
        DETACHED="${existing}"
    else
        log WARN "virtual already has ${PROFILE_TYPE} profile(s): $(echo "${existing}" | tr '\n' ' ')- not attaching (ATTACH_MODE=add). Attach manually or use ATTACH_MODE=replace"
        return 0
    fi
    ATTACHED="yes"
    log NOTICE "attached ${PROFILE_NAME} to ${ATTACH_VIRTUAL}${DETACHED:+ (replaced ${DETACHED})}"
}

detach_profile() {
    local ctx="clientside"; [ "${PROFILE_TYPE}" = "server-ssl" ] && ctx="serverside"
    if [ -n "${DETACHED}" ]; then
        tmc "create cli transaction; modify ltm virtual ${ATTACH_VIRTUAL} profiles delete { ${PROFILE_NAME} }; modify ltm virtual ${ATTACH_VIRTUAL} profiles add { ${DETACHED} { context ${ctx} } }; submit cli transaction"
    else
        tmc "modify ltm virtual ${ATTACH_VIRTUAL} profiles delete { ${PROFILE_NAME} }"
    fi
}

verify_binding() {
    [ "${DRY_RUN}" = "yes" ] && return 0
    local cur
    if [ "${PROFILE_TYPE}" = "client-ssl" ]; then
        cur="$(tmq "list ltm profile client-ssl ${PROFILE_NAME} cert-key-chain" | child_attr "cert-key-chain" "${CKC_ENTRY}" cert)"
    else
        cur="$(tmq "list ltm profile server-ssl ${PROFILE_NAME} cert" | awk '$1=="cert" {print $2; exit}')"
    fi
    if [ "$(strip_part "${cur}")" != "$(strip_part "${NEW_CERT}")" ]; then
        log ERROR "post-change check: profile references '${cur}', expected '${NEW_CERT}'"; return 1
    fi
    log INFO "post-change check: profile now references ${NEW_CERT}"
    return 0
}

verify_live() {
    [ "${DRY_RUN}" = "yes" ] && return 0
    [ -n "${VERIFY_HOST}" ] || return 0
    [ "${PROFILE_TYPE}" = "client-ssl" ] || { log INFO "live verify only applies to client-ssl - skipped"; return 0; }
    local sni="${VERIFY_SNI:-${EXPECT_NAME}}" served i
    for i in 1 2 3; do
        sleep 2
        served=$(echo | timeout 15 "${OPENSSL}" s_client -connect "${VERIFY_HOST}:${VERIFY_PORT}" ${sni:+-servername "${sni}"} 2>/dev/null \
                 | "${OPENSSL}" x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':')
        [ "${served}" = "${NEW_FP}" ] && { log INFO "live check: ${VERIFY_HOST}:${VERIFY_PORT} is serving the new certificate"; return 0; }
    done
    log ERROR "live check: ${VERIFY_HOST}:${VERIFY_PORT} served '${served:-nothing}', expected ${NEW_FP}"
    return 1
}

prune_versions() {
    [ "${RETAIN_VERSIONS}" -ge 1 ] 2>/dev/null || return 0
    local kind re obj list n del
    for kind in "ssl-cert:_[0-9]{14}\\.crt" "ssl-cert:_[0-9]{14}_chain\\.crt" "ssl-key:_[0-9]{14}\\.key"; do
        re="^${OBJ_PREFIX//./\\.}${kind#*:}\$"
        list="$(tmq "list sys file ${kind%%:*} one-line" | awk '{print $4}' | sed "s#^/${PARTITION}/##" | grep -E "${re}" | sort)"
        n=$(echo "${list}" | grep -c .)
        [ "${n}" -le "${RETAIN_VERSIONS}" ] && continue
        del=$(( n - RETAIN_VERSIONS ))
        echo "${list}" | head -n "${del}" | while read -r obj; do
            # tmsh refuses to delete objects still referenced by any profile - that is our safety net
            if [ "${DRY_RUN}" = "yes" ]; then
                log INFO "DRY-RUN tmsh: delete sys file ${kind%%:*} /${PARTITION}/${obj}"
            elif "${TMSH}" -c "delete sys file ${kind%%:*} /${PARTITION}/${obj}" >/dev/null 2>&1; then
                log INFO "pruned old ${kind%%:*} /${PARTITION}/${obj}"
            else
                log INFO "kept /${PARTITION}/${obj} (still referenced)"
            fi
        done
    done
}

finish_source() {   # finish_source ok|failed
    [ "${DRY_RUN}" = "yes" ] && return 0
    local dest
    if [ "$1" = "ok" ]; then dest="${ARCHIVE_DIR}/${JOB}/${TS}"; else dest="${FAILED_DIR}/${JOB}/${TS}"; fi
    mkdir -p "${dest}" && chmod 700 "${dest}"
    cp -p "${STG}/cert.pem" "${dest}/" 2>/dev/null
    [ -f "${STG}/chain.pem" ] && cp -p "${STG}/chain.pem" "${dest}/"
    if [ "$1" = "failed" ] || [ "${ARCHIVE_KEYS}" = "yes" ]; then cp -p "${STG}/key.pem" "${dest}/" 2>/dev/null; fi

    if [ "${SOURCE_TYPE}" = "local" ]; then
        # remove from drop dir so it is not re-processed; key is securely wiped
        secure_rm "${SOURCE_DIR}/${KEY_FILE}"
        rm -f "${SOURCE_DIR}/${CERT_FILE}"
        [ -n "${CHAIN_FILE}" ]   && rm -f "${SOURCE_DIR}/${CHAIN_FILE}"
        [ -n "${READY_MARKER}" ] && rm -f "${SOURCE_DIR}/${READY_MARKER}"
    fi
}

cleanup_staging() { secure_rm "${STG}"/*; rm -rf "${STG}"; }

# ------------------------------------------------------------- run_job ----
run_job() {   # executed in a subshell; exit code: 0 ok/nothing, 1 failed
    local conf="$1"
    reset_job_vars
    JOB="$(basename "${conf}" .conf)"
    JOBCONF="${conf}"
    # shellcheck disable=SC1090
    . "${conf}" || { log ERROR "cannot read ${conf}"; exit 1; }
    # One-off override: take material from a given directory instead of the job's
    # normal source, e.g.  CERTROTATE_SOURCE_OVERRIDE=/var/tmp/test certrotate.sh -n -j www
    if [ -n "${CERTROTATE_SOURCE_OVERRIDE:-}" ]; then
        SOURCE_TYPE="local"; SOURCE_DIR="${CERTROTATE_SOURCE_OVERRIDE}"
        CERT_FILE="cert.pem"; KEY_FILE="key.pem"; CHAIN_FILE="chain.pem"
        STABLE_SECONDS=0; READY_MARKER=""
        log INFO "source overridden: ${SOURCE_DIR}"
    fi
    validate_job_conf || exit 1

    if [ "${TEST_ONLY}" = "yes" ]; then
        log INFO "TEST: job file parsed; source=${SOURCE_TYPE} ${SOURCE_DIR}${SOURCE_SCP}${SOURCE_URL}"
        if profile_exists; then
            snapshot_profile || exit 1
            log NOTICE "TEST OK: ${PROFILE_TYPE} ${PROFILE_NAME} found; certificate entry to be replaced: cert=${OLD_CERT} key=${OLD_KEY} chain=${OLD_CHAIN}${CKC_ENTRY:+ (entry ${CKC_ENTRY})}"
        elif [ "${CREATE_IF_MISSING}" = "yes" ]; then
            obj_exists "ltm profile ${PROFILE_TYPE}" "${PARENT_PROFILE}" || { log ERROR "TEST FAILED: parent profile ${PARENT_PROFILE} not found"; exit 1; }
            log NOTICE "TEST OK: ${PROFILE_NAME} does not exist yet and will be created from ${PARENT_PROFILE} on the first run"
        else
            log ERROR "TEST FAILED: ${PROFILE_TYPE} profile ${PROFILE_NAME} does not exist"; exit 1
        fi
        exit 0
    fi

    STG="${STAGING_DIR}/${JOB}"
    IMPORTED=()
    ATTACHED="no"; DETACHED=""; CREATED="no"
    trap 'cleanup_staging' EXIT

    fetch_files; local rc=$?
    [ ${rc} -eq 3 ] && exit 0
    [ ${rc} -ne 0 ] && { log ERROR "fetch failed"; exit 1; }

    # Idempotency: compare with last applied / last failed fingerprint
    # (openssl x509 reads only the first cert, so this is the leaf even for a bundle)
    local fp; fp="$(fp_sha256 "${STG}/cert.pem")"
    if [ "${FORCE}" != "yes" ] && [ -n "${fp}" ]; then
        if [ -f "${STATE_DIR}/${JOB}.applied" ] && grep -q "^fingerprint=${fp}$" "${STATE_DIR}/${JOB}.applied"; then
            local applied_cert; applied_cert="$(sed -n 's/^cert=//p' "${STATE_DIR}/${JOB}.applied")"
            if tmq "list ltm profile ${PROFILE_TYPE} ${PROFILE_NAME}" | grep -qF "$(strip_part "${applied_cert}")"; then
                log NOTICE "this certificate (${fp}) is already applied to ${PROFILE_NAME} - nothing to do; clearing inbox"
                [ "${SOURCE_TYPE}" = "local" ] && finish_source ok
                exit 0
            fi
            log NOTICE "this certificate was applied before but ${PROFILE_NAME} no longer uses it (rolled back?) - applying it again"
        elif [ -f "${STATE_DIR}/${JOB}.failed" ] && grep -q "^fingerprint=${fp}$" "${STATE_DIR}/${JOB}.failed"; then
            if [ "${JOBCONF}" -nt "${STATE_DIR}/${JOB}.failed" ]; then
                log NOTICE "this certificate failed before, but the job file has changed since - retrying"
            else
                log WARN "SKIPPED: this exact certificate already failed at $(sed -n 's/^time=//p' "${STATE_DIR}/${JOB}.failed") ($(sed -n 's/^reason=//p' "${STATE_DIR}/${JOB}.failed")). Fix the cause and upload again, or run with -f. Removing the duplicate upload from the inbox."
                if [ "${SOURCE_TYPE}" = "local" ] && [ "${DRY_RUN}" != "yes" ]; then
                    secure_rm "${SOURCE_DIR}/${KEY_FILE}"; rm -f "${SOURCE_DIR}/${CERT_FILE}"
                    [ -n "${CHAIN_FILE}" ] && rm -f "${SOURCE_DIR}/${CHAIN_FILE}"
                    [ -n "${READY_MARKER}" ] && rm -f "${SOURCE_DIR}/${READY_MARKER}"
                fi
                exit 1
            fi
        fi
    fi

    log NOTICE "new certificate material found (source=${SOURCE_TYPE}) for ${PROFILE_TYPE} ${PROFILE_NAME}"

    fail() {
        log ERROR "$* - job FAILED, configuration left as it was"
        [ "${DRY_RUN}" = "yes" ] && exit 1
        { echo "fingerprint=${fp}"; echo "time=${TS}"; echo "reason=$*"; } >"${STATE_DIR}/${JOB}.failed"
        finish_source failed
        exit 1
    }

    validate_material || fail "validation failed"

    local exists="no"
    if profile_exists; then
        exists="yes"
        snapshot_profile || fail "could not snapshot profile"
    elif [ "${CREATE_IF_MISSING}" = "yes" ]; then
        obj_exists "ltm profile ${PROFILE_TYPE}" "${PARENT_PROFILE}" || fail "parent profile ${PARENT_PROFILE} not found"
    else
        fail "profile ${PROFILE_NAME} does not exist (set CREATE_IF_MISSING=yes to create it)"
    fi

    local DRYP=""; [ "${DRY_RUN}" = "yes" ] && DRYP="DRY-RUN would have "
    import_objects || { remove_imported; fail "import of cert/key failed"; }

    if [ "${exists}" = "yes" ]; then
        bind_profile "${NEW_CERT}" "${NEW_KEY}" "${NEW_CHAIN}" || { remove_imported; fail "profile update rejected by tmsh"; }
        log NOTICE "${DRYP}profile ${PROFILE_NAME} switched: ${OLD_CERT} -> ${NEW_CERT}"
    else
        create_profile || { remove_imported; fail "profile create rejected by tmsh"; }
        CREATED="yes"
        log NOTICE "${DRYP}created ${PROFILE_TYPE} profile ${PROFILE_NAME} with ${NEW_CERT}"
        if [ -n "${ATTACH_VIRTUAL}" ]; then
            attach_profile || {
                tmc "delete ltm profile ${PROFILE_TYPE} ${PROFILE_NAME}"; remove_imported
                fail "attach to ${ATTACH_VIRTUAL} failed"; }
        fi
    fi

    if ! verify_binding || ! verify_live; then
        log WARN "verification failed - rolling back"
        if [ "${CREATED}" = "yes" ]; then
            [ "${ATTACHED}" = "yes" ] && detach_profile
            tmc "delete ltm profile ${PROFILE_TYPE} ${PROFILE_NAME}"
        else
            bind_profile "${OLD_CERT}" "${OLD_KEY}" "${OLD_CHAIN}" \
                && log NOTICE "rolled back ${PROFILE_NAME} to ${OLD_CERT}" \
                || log ERROR "ROLLBACK FAILED - restore ${PROFILE_NAME} manually to cert ${OLD_CERT} key ${OLD_KEY} chain ${OLD_CHAIN}"
        fi
        remove_imported
        fail "post-change verification failed"
    fi

    prune_versions

    if [ "${DRY_RUN}" != "yes" ]; then
        {
            echo "fingerprint=${NEW_FP}"; echo "time=${TS}"; echo "subject=${NEW_SUBJECT}"
            echo "not_after=${NEW_NOTAFTER}"; echo "cert=${NEW_CERT}"; echo "key=${NEW_KEY}"; echo "chain=${NEW_CHAIN}"
            echo "profile=${PROFILE_TYPE} ${PROFILE_NAME}"; echo "previous_cert=${OLD_CERT:-}"; echo "previous_key=${OLD_KEY:-}"
            echo "previous_chain=${OLD_CHAIN:-}"; echo "profile_type=${PROFILE_TYPE}"; echo "profile_name=${PROFILE_NAME}"
            echo "ckc_entry=${CKC_ENTRY:-}"; echo "created=${CREATED}"
        } >"${STATE_DIR}/${JOB}.applied"
        rm -f "${STATE_DIR}/${JOB}.failed"
    fi
    finish_source ok
    if [ "${DRY_RUN}" = "yes" ]; then
        log NOTICE "DRY-RUN OK: validation passed; ${PROFILE_NAME} WOULD use ${NEW_CERT} (expires ${NEW_NOTAFTER}). Nothing was changed."
    else
        log NOTICE "SUCCESS: ${PROFILE_NAME} now uses ${NEW_CERT} (expires ${NEW_NOTAFTER})"
    fi
    exit 0
}

# ===================================================================== MAIN ==
while getopts ":nfvtj:c:h" opt; do
    case "${opt}" in
        n) DRY_RUN="yes" ;;
        f) FORCE="yes" ;;
        v) VERBOSE="yes" ;;
        t) TEST_ONLY="yes" ;;
        j) ONLY_JOB="${OPTARG}" ;;
        c) GLOBAL_CONF="${OPTARG}" ;;
        h) usage ;;
        *) echo "unknown option -${OPTARG}" >&2; exit 2 ;;
    esac
done

CLI_DRY_RUN="${DRY_RUN}"
# shellcheck disable=SC1090
[ -f "${GLOBAL_CONF}" ] && . "${GLOBAL_CONF}"
[ "${CLI_DRY_RUN}" = "yes" ] && DRY_RUN="yes"

: "${JOBS_DIR:=${BASE_DIR}/jobs.d}"
: "${STAGING_DIR:=${BASE_DIR}/staging}"
: "${ARCHIVE_DIR:=${BASE_DIR}/archive}"
: "${FAILED_DIR:=${BASE_DIR}/failed}"
: "${STATE_DIR:=${BASE_DIR}/state}"
mkdir -p "${JOBS_DIR}" "${STAGING_DIR}" "${ARCHIVE_DIR}" "${FAILED_DIR}" "${STATE_DIR}" 2>/dev/null
chmod 700 "${BASE_DIR}" "${STAGING_DIR}" "${ARCHIVE_DIR}" "${FAILED_DIR}" "${STATE_DIR}" 2>/dev/null

# Single instance
exec 9>"${LOCK_FILE}" || { echo "cannot open lock ${LOCK_FILE}" >&2; exit 2; }
if ! flock -n 9; then log WARN "another certrotate run is in progress - exiting"; exit 0; fi

# Is there anything to do at all? (cheap check before touching mcpd)
shopt -s nullglob
JOB_FILES=("${JOBS_DIR}"/*.conf)
if [ -n "${ONLY_JOB}" ]; then JOB_FILES=("${JOBS_DIR}/${ONLY_JOB%.conf}.conf"); fi
[ ${#JOB_FILES[@]} -eq 0 ] && exit 0

mcpd_running || { log ERROR "mcpd is not in 'running' phase - not touching config"; exit 2; }

if [ "${REQUIRE_ACTIVE}" = "yes" ]; then
    FO="$(failover_state)"
    case "${FO}" in
        *[Aa]ctive*|*ACTIVE*) ;;
        *) { [ -t 1 ] || [ "${VERBOSE}" = "yes" ]; } && log INFO "unit is '${FO:-unknown}', not Active - nothing to do"; exit 0 ;;
    esac
fi

SYNC_BEFORE="$(sync_status)"

CHANGED=0
for conf in "${JOB_FILES[@]}"; do
    [ -f "${conf}" ] || { log ERROR "job file ${conf} not found"; OVERALL_RC=1; continue; }
    before="$(cat "${STATE_DIR}/$(basename "${conf}" .conf).applied" 2>/dev/null)"
    ( run_job "${conf}" ) || OVERALL_RC=1
    after="$(cat "${STATE_DIR}/$(basename "${conf}" .conf).applied" 2>/dev/null)"
    [ "${before}" != "${after}" ] && CHANGED=1
done
JOB=""

if [ ${CHANGED} -eq 1 ] && [ "${DRY_RUN}" != "yes" ]; then
    if [ "${SAVE_CONFIG}" = "yes" ]; then
        tmc "save sys config" || OVERALL_RC=1
    fi
    if [ -n "${SYNC_GROUP}" ]; then
        if [ "${SYNC_ONLY_IF_CLEAN}" = "yes" ] && ! echo "${SYNC_BEFORE}" | grep -qi "in sync"; then
            log WARN "device group was '${SYNC_BEFORE}' BEFORE this run - NOT auto-syncing to avoid pushing unrelated pending changes. Sync ${SYNC_GROUP} manually."
            OVERALL_RC=1
        else
            tmc "run cm config-sync to-group ${SYNC_GROUP}" && log NOTICE "config-sync to ${SYNC_GROUP} requested" || OVERALL_RC=1
        fi
    fi
fi

exit ${OVERALL_RC}
