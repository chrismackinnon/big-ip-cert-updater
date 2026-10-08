#!/bin/bash
# =============================================================================
#  make-csr.sh - create a private key + CSR to submit to DigiCert
#
#  Runs on a Linux or macOS workstation/server (not on the BIG-IP).
#
#  Usage:
#    ./make-csr.sh -n www.example.com [-a www2.example.com -a example.com]
#                  [-o "Example Corp" -l "Seattle" -s "Washington" -c US]
#                  [-t rsa|ec] [-b 2048|3072|4096] [-d <output dir>]
#
#    -n  primary name (Common Name, also put in the SAN list)       REQUIRED
#    -a  additional SAN name (repeat for each)
#    -o/-l/-s/-c  Organization / Locality / State / Country (optional - DigiCert
#                 OV/EV orders take these from your account, but harmless to include)
#    -t  key type: rsa (default) or ec (P-256)
#    -b  RSA key size, default 2048
#    -d  output directory, default ./<name>-<YYYYMMDD>
#
#  Produces in the output directory:
#    <name>.key   private key      - KEEP SECRET. Never email it or upload it to DigiCert.
#    <name>.csr   signing request  - paste this into the DigiCert order
# =============================================================================
set -u
set -f      # no filename globbing - "*.example.com" must stay literal
umask 077

NAME=""; SANS=""; ORG=""; LOC=""; ST=""; C=""; KTYPE="rsa"; BITS=2048; OUT=""

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":n:a:o:l:s:c:t:b:d:h" opt; do
    case "$opt" in
        n) NAME="$OPTARG" ;;
        a) SANS="$SANS $OPTARG" ;;
        o) ORG="$OPTARG" ;;
        l) LOC="$OPTARG" ;;
        s) ST="$OPTARG" ;;
        c) C="$OPTARG" ;;
        t) KTYPE="$OPTARG" ;;
        b) BITS="$OPTARG" ;;
        d) OUT="$OPTARG" ;;
        h) usage 0 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 2 ;;
    esac
done

[ -n "$NAME" ] || { echo "ERROR: -n <name> is required" >&2; usage 2; }
case "$NAME" in *[!A-Za-z0-9.*-]*) echo "ERROR: invalid name '$NAME'" >&2; exit 2 ;; esac
case "$KTYPE" in rsa|ec) ;; *) echo "ERROR: -t must be rsa or ec" >&2; exit 2 ;; esac
case "$BITS" in 2048|3072|4096) ;; *) echo "ERROR: -b must be 2048, 3072 or 4096" >&2; exit 2 ;; esac

FILEBASE=$(echo "$NAME" | sed 's/^\*\./wildcard./')
[ -n "$OUT" ] || OUT="./${FILEBASE}-$(date +%Y%m%d)"
mkdir -p "$OUT" || exit 1
KEY="$OUT/$FILEBASE.key"; CSR="$OUT/$FILEBASE.csr"; CNF="$OUT/.csr.cnf"
if [ -e "$KEY" ]; then echo "ERROR: $KEY already exists - refusing to overwrite a private key" >&2; exit 1; fi

# Build SAN list (primary name first, de-duplicated)
SANLIST="DNS:$NAME"
for s in $SANS; do
    case ",$SANLIST," in *",DNS:$s,"*) ;; *) SANLIST="$SANLIST,DNS:$s" ;; esac
done

{
    echo "[req]"
    echo "prompt = no"
    echo "distinguished_name = dn"
    echo "req_extensions = ext"
    echo "[dn]"
    [ -n "$C" ]   && echo "C = $C"
    [ -n "$ST" ]  && echo "ST = $ST"
    [ -n "$LOC" ] && echo "L = $LOC"
    [ -n "$ORG" ] && echo "O = $ORG"
    echo "CN = $NAME"
    echo "[ext]"
    echo "subjectAltName = $SANLIST"
} > "$CNF"

if [ "$KTYPE" = "rsa" ]; then
    openssl genrsa -out "$KEY" "$BITS" 2>/dev/null || { echo "ERROR: key generation failed" >&2; exit 1; }
else
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY" 2>/dev/null || { echo "ERROR: key generation failed" >&2; exit 1; }
fi
chmod 600 "$KEY"
openssl req -new -key "$KEY" -config "$CNF" -out "$CSR" || { echo "ERROR: CSR generation failed" >&2; exit 1; }
rm -f "$CNF"

echo
echo "Created:"
echo "  Private key : $KEY   (keep secret - do NOT send to DigiCert)"
echo "  CSR         : $CSR"
echo
openssl req -in "$CSR" -noout -subject
openssl req -in "$CSR" -noout -text | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ */  SANs: /'
echo
echo "Next: paste the contents of $CSR into the DigiCert order (CertCentral)."
echo "      Keep $KEY - you need it again when the certificate is issued."
echo
cat "$CSR"
