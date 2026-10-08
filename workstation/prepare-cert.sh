#!/bin/bash
# =============================================================================
#  prepare-cert.sh - turn a DigiCert download + your private key into the three
#                    files certrotate.sh expects, check them, and (optionally)
#                    upload them to the Active BIG-IP.
#
#  Runs on a Linux or macOS workstation/server (not on the BIG-IP).
#
#  Accepts whatever DigiCert gives you, in any combination:
#    - the .zip download (e.g. "Apache" or "Individual .crt files")
#    - .crt / .pem / .cer files (PEM or DER), a .pem bundle, or a .p7b
#  It works out which certificate is yours (the one matching your key), puts
#  the intermediate(s) in the right order, and leaves the root out.
#
#  Usage:
#    ./prepare-cert.sh -k <private key> [-e <expected name>] [-o <out dir>]
#                      [-u <user@bigip> -j <job>] [-f] <download files...>
#
#    -k  your private key (the one created with make-csr.sh)        REQUIRED
#    -e  name that must be on the certificate (e.g. www.example.com)
#    -o  output directory (default ./ready-<YYYYMMDD-HHMMSS>)
#    -u  upload to this BIG-IP (ssh user@address) ...
#    -j  ... into the inbox of this certrotate job
#    -f  upload even if that unit is not Active
#
#  Example:
#    ./prepare-cert.sh -k www.example.com.key -e www.example.com \
#        -u admin@10.1.1.245 -j www_example_com  ~/Downloads/www_example_com.zip
#
#  Output: <out dir>/cert.pem  chain.pem  key.pem   (key.pem is mode 600)
# =============================================================================
set -u
umask 077

KEY=""; EXPECT=""; OUT=""; UPLOAD=""; JOB=""; FORCE="no"
REMOTE_BASE="/shared/certrotate"

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
ok()   { echo "  [ OK ] $*"; }
warn() { echo "  [WARN] $*"; }

while getopts ":k:e:o:u:j:fh" opt; do
    case "$opt" in
        k) KEY="$OPTARG" ;;
        e) EXPECT="$OPTARG" ;;
        o) OUT="$OPTARG" ;;
        u) UPLOAD="$OPTARG" ;;
        j) JOB="$OPTARG" ;;
        f) FORCE="yes" ;;
        h) usage 0 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 2 ;;
    esac
done
shift $((OPTIND - 1))

[ -n "$KEY" ] || { echo "ERROR: -k <private key> is required" >&2; usage 2; }
[ -f "$KEY" ] || die "private key file '$KEY' not found"
[ $# -ge 1 ]  || { echo "ERROR: give at least one DigiCert file (zip, crt, pem, p7b)" >&2; usage 2; }
if [ -n "$UPLOAD" ] && [ -z "$JOB" ]; then die "-u needs -j <job name>"; fi
if [ -n "$JOB" ]; then case "$JOB" in *[!A-Za-z0-9_.-]*) die "invalid job name '$JOB'" ;; esac; fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/prepcert.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/in" "$WORK/certs"

echo "== Reading files"
# ---------------------------------------------------------------- collect --
for f in "$@"; do
    [ -f "$f" ] || die "file '$f' not found"
    case "$(echo "$f" | tr 'A-Z' 'a-z')" in
        *.zip)
            command -v unzip >/dev/null || die "unzip is not installed"
            d="$WORK/in/$(basename "$f").d"; mkdir -p "$d"
            unzip -q -o "$f" -d "$d" || die "could not unzip $f"
            find "$d" -type f ! -name '.*' ! -path '*/__MACOSX/*' -print | while read -r x; do echo "$x"; done >> "$WORK/list"
            echo "  unzipped $(basename "$f")"
            ;;
        *) echo "$f" >> "$WORK/list" ;;
    esac
done

# ------------------------------------------------- extract every certificate --
n=0
add_cert() {   # add_cert <pem file with exactly one cert>
    local fp
    fp=$(openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    [ -n "$fp" ] || return 0
    if ! grep -qx "$fp" "$WORK/fps" 2>/dev/null; then
        echo "$fp" >> "$WORK/fps"
        n=$((n + 1))
        openssl x509 -in "$1" -out "$WORK/certs/$(printf '%03d' $n).pem" 2>/dev/null
    fi
}
split_pem() {  # split_pem <file>  -> calls add_cert for each cert
    awk -v dir="$WORK/split" '
        /-----BEGIN CERTIFICATE-----/ { i++; f = sprintf("%s/%03d.pem", dir, i) }
        f { print > f }
        /-----END CERTIFICATE-----/ { close(f); f = "" }' "$1"
    for c in "$WORK"/split/*.pem; do [ -f "$c" ] && add_cert "$c"; done
    rm -f "$WORK"/split/*.pem
}
mkdir -p "$WORK/split"

while read -r f; do
    [ -n "$f" ] || continue
    if grep -q 'PRIVATE KEY' "$f" 2>/dev/null; then
        warn "$(basename "$f") contains a private key - ignored (use -k for the key)"; continue
    fi
    before=$n
    if grep -q -- '-----BEGIN PKCS7-----' "$f" 2>/dev/null; then
        openssl pkcs7 -in "$f" -print_certs -out "$WORK/p7.pem" 2>/dev/null && split_pem "$WORK/p7.pem"
    elif grep -q -- '-----BEGIN CERTIFICATE-----' "$f" 2>/dev/null; then
        split_pem "$f"
    elif openssl pkcs7 -inform DER -in "$f" -print_certs -out "$WORK/p7.pem" 2>/dev/null; then
        split_pem "$WORK/p7.pem"
    elif openssl x509 -inform DER -in "$f" -out "$WORK/der.pem" 2>/dev/null; then
        add_cert "$WORK/der.pem"
    fi
    added=$((n - before))
    [ $added -gt 0 ] && echo "  $(basename "$f"): $added certificate(s)"
done < "$WORK/list"

[ $n -gt 0 ] || die "no certificates found in the files given"

# ------------------------------------------------------------------- key --
echo "== Checking private key"
if grep -q 'ENCRYPTED' "$KEY"; then
    echo "  The key is passphrase-protected; enter the passphrase to continue."
fi
openssl pkey -in "$KEY" -out "$WORK/key.pem" || die "cannot read private key $KEY"
KEYPUB=$(openssl pkey -in "$WORK/key.pem" -pubout 2>/dev/null | openssl sha256 | awk '{print $NF}')
ok "private key readable"

# ---------------------------------------------------------- find the leaf --
LEAF=""
for c in "$WORK"/certs/*.pem; do
    p=$(openssl x509 -in "$c" -noout -pubkey 2>/dev/null | openssl sha256 | awk '{print $NF}')
    if [ "$p" = "$KEYPUB" ]; then LEAF="$c"; break; fi
done
if [ -z "$LEAF" ]; then
    echo "  Certificates found:"
    for c in "$WORK"/certs/*.pem; do echo "    - $(openssl x509 -in "$c" -noout -subject)"; done
    die "none of these certificates match the private key. Wrong key, or the order was issued from a different CSR."
fi
if openssl x509 -in "$LEAF" -noout -text | grep -A1 'Basic Constraints' | grep -q 'CA:TRUE'; then
    die "the key matches a CA certificate ($(openssl x509 -in "$LEAF" -noout -subject | sed 's/^subject= *//')), not a server certificate. Use the key you created for this order."
fi
ok "your certificate: $(openssl x509 -in "$LEAF" -noout -subject | sed 's/^subject= *//')"

# --------------------------------------------------------- build the chain --
echo "== Building chain"
: > "$WORK/chain.pem"
cur="$LEAF"; ROOT=""; depth=0
while [ $depth -lt 6 ]; do
    iss=$(openssl x509 -in "$cur" -noout -issuer_hash)
    sub=$(openssl x509 -in "$cur" -noout -subject_hash)
    [ "$iss" = "$sub" ] && { ROOT="$cur"; break; }      # self-signed: reached a root
    next=""
    for c in "$WORK"/certs/*.pem; do
        [ "$c" = "$cur" ] && continue
        if [ "$(openssl x509 -in "$c" -noout -subject_hash)" = "$iss" ]; then next="$c"; break; fi
    done
    [ -n "$next" ] || break
    if [ "$(openssl x509 -in "$next" -noout -subject_hash)" = "$(openssl x509 -in "$next" -noout -issuer_hash)" ]; then
        ROOT="$next"; break                               # issuer is the root - don't include it
    fi
    cat "$next" >> "$WORK/chain.pem"
    ok "intermediate: $(openssl x509 -in "$next" -noout -subject | sed 's/^subject= *//')"
    cur="$next"; depth=$((depth + 1))
done

if [ ! -s "$WORK/chain.pem" ]; then
    if [ "$(openssl x509 -in "$LEAF" -noout -subject_hash)" = "$(openssl x509 -in "$LEAF" -noout -issuer_hash)" ]; then
        warn "certificate is self-signed - no chain (fine for a lab, not for DigiCert)"
    else
        die "the intermediate certificate is missing. Download the DigiCert files again including the intermediate (e.g. the 'Apache' zip) and pass them all to this script."
    fi
elif [ -z "$ROOT" ]; then
    last_iss=$(openssl x509 -in "$cur" -noout -issuer | sed 's/^issuer= *//')
    ok "chain ends at an intermediate issued by: $last_iss (root not included - correct)"
else
    ok "root found in download and left out of the chain (correct): $(openssl x509 -in "$ROOT" -noout -subject | sed 's/^subject= *//')"
fi

# -------------------------------------------------------------- validate --
echo "== Validating"
if [ -n "$ROOT" ]; then
    if [ -s "$WORK/chain.pem" ]; then
        set -- -CAfile "$ROOT" -untrusted "$WORK/chain.pem"
    else
        set -- -CAfile "$ROOT"
    fi
    if openssl verify "$@" "$LEAF" >/dev/null 2>&1; then
        ok "signature chain verifies up to the root"
    else
        die "the chain does not verify - files may be from different orders"
    fi
fi

openssl x509 -in "$LEAF" -noout -checkend 0 >/dev/null || die "certificate has EXPIRED"
openssl x509 -in "$LEAF" -noout -checkend 604800 >/dev/null || warn "certificate expires within 7 days"
NOTBEFORE=$(openssl x509 -in "$LEAF" -noout -startdate | cut -d= -f2)
NOTAFTER=$(openssl x509 -in "$LEAF" -noout -enddate | cut -d= -f2)
ok "valid from $NOTBEFORE to $NOTAFTER"

TEXT=$(openssl x509 -in "$LEAF" -noout -text)
SANS=$(echo "$TEXT" | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//')
ok "names on certificate: ${SANS:-none}"
if echo "$TEXT" | grep -q 'rsaEncryption'; then
    BITS=$(echo "$TEXT" | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1)
    ok "key type: RSA ${BITS}"
else
    ok "key type: EC"
fi

if [ -n "$EXPECT" ]; then
    wild="*.${EXPECT#*.}"
    clean=$(echo "$SANS" | tr -d ' ')
    if echo ",$clean," | grep -qF ",DNS:$EXPECT," || echo ",$clean," | grep -qF ",DNS:$wild,"; then
        ok "expected name '$EXPECT' is on the certificate"
    else
        die "expected name '$EXPECT' is NOT on the certificate"
    fi
fi

# ----------------------------------------------------------------- output --
[ -n "$OUT" ] || OUT="./ready-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT" || die "cannot create $OUT"
cp "$LEAF" "$OUT/cert.pem"
cp "$WORK/key.pem" "$OUT/key.pem"
if [ -s "$WORK/chain.pem" ]; then cp "$WORK/chain.pem" "$OUT/chain.pem"; else rm -f "$OUT/chain.pem"; fi
chmod 600 "$OUT"/*.pem
FP=$(openssl x509 -in "$LEAF" -noout -fingerprint -sha256 | cut -d= -f2)

echo
echo "== Ready"
echo "  $OUT/cert.pem    your certificate"
[ -f "$OUT/chain.pem" ] && echo "  $OUT/chain.pem   intermediate chain"
echo "  $OUT/key.pem     private key (mode 600 - keep secret)"
echo "  SHA-256 fingerprint: $FP"

# ----------------------------------------------------------------- upload --
if [ -z "$UPLOAD" ]; then
    echo
    echo "Next: copy these files to the ACTIVE BIG-IP, into ${REMOTE_BASE}/inbox/<job>/ - e.g."
    echo "  ssh <user>@<active-bigip> 'mkdir -p ${REMOTE_BASE}/inbox/<job>.incoming'"
    echo "  scp $OUT/*.pem <user>@<active-bigip>:${REMOTE_BASE}/inbox/<job>.incoming/"
    echo "  ssh <user>@<active-bigip> 'mkdir -p ${REMOTE_BASE}/inbox/<job> && mv ${REMOTE_BASE}/inbox/<job>.incoming/*.pem ${REMOTE_BASE}/inbox/<job>/ && rmdir ${REMOTE_BASE}/inbox/<job>.incoming'"
    echo "or re-run this script with  -u <user>@<active-bigip> -j <job>"
    echo
    echo "NOTE: $OUT/key.pem is an UNENCRYPTED copy of your private key. Delete it after copying."
    exit 0
fi

echo
echo "== Uploading to $UPLOAD (job $JOB)"
SSHOPTS="-o ConnectTimeout=15"
# OpenSSH 9+ scp uses SFTP by default; BIG-IP accounts may not allow it. Use legacy scp if supported.
SCPLEGACY=""; scp -O 2>&1 | grep -q "illegal option\|unknown option" || SCPLEGACY="-O"
STATE=$(ssh $SSHOPTS "$UPLOAD" 'echo "FO=$(cat /var/prompt/ps1 2>/dev/null)"; test -f '"$REMOTE_BASE/jobs.d/$JOB.conf"' && echo JOB_OK; true') \
    || die "cannot ssh to $UPLOAD (try: ssh $UPLOAD)"
echo "$STATE" | grep -q '^FO=' || die "unexpected response from $UPLOAD - is the login shell bash? Got: $(echo "$STATE" | head -3)"
echo "$STATE" | grep -q JOB_OK || die "job '$JOB' does not exist on $UPLOAD ($REMOTE_BASE/jobs.d/$JOB.conf missing)"
FO=$(echo "$STATE" | sed -n 's/^FO=//p' | head -1)
case "$FO" in
    *Active*|*ACTIVE*) ok "$UPLOAD is Active" ;;
    *) [ "$FORCE" = "yes" ] || die "$UPLOAD reports '${FO:-unknown}', not Active. Upload to the Active unit (or use -f)." ;;
esac
INC="$REMOTE_BASE/inbox/$JOB.incoming"; DST="$REMOTE_BASE/inbox/$JOB"
ssh $SSHOPTS "$UPLOAD" "umask 077; rm -rf '$INC'; mkdir -p '$INC' '$DST'" || die "could not create $INC"
scp -q $SCPLEGACY $SSHOPTS "$OUT"/*.pem "$UPLOAD:$INC/" || die "scp failed"
# move into place in one step so the scheduled run never sees half the files
ssh $SSHOPTS "$UPLOAD" "chmod 600 '$INC'/*.pem && mv -f '$INC'/*.pem '$DST'/ && rmdir '$INC'" || die "could not move files into $DST"
ok "uploaded to $UPLOAD:$DST/"
# the uploaded key is now on the BIG-IP; don't leave an extra unencrypted copy here
rm -P "$OUT/key.pem" 2>/dev/null || shred -u "$OUT/key.pem" 2>/dev/null || rm -f "$OUT/key.pem"
ok "removed the local copy $OUT/key.pem (your original key file is untouched)"
echo
echo "Next, on $UPLOAD (as a bash user):"
echo "  $REMOTE_BASE/certrotate.sh -n -j $JOB     # dry run - shows what would change"
echo "  $REMOTE_BASE/certrotate.sh -j $JOB        # apply   (or wait for the schedule)"
