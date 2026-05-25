#!/bin/bash
# ============================================================
# scan.sh — Glowny skrypt skanowania sieci z NSE
# Wersja dostosowana do RouterOS /container
# ============================================================

TARGET="${1:-192.168.88.0/24}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="/scanner/reports"

HOSTS_OUT="${REPORT_DIR}/hosts_${TIMESTAMP}.gnmap"
GNMAP_OUT="${REPORT_DIR}/scan_${TIMESTAMP}.gnmap"
TXT_OUT="${REPORT_DIR}/scan_${TIMESTAMP}.txt"
NSE_OUT="${REPORT_DIR}/nse_${TIMESTAMP}.txt"
MIKROTIK_OUT="${REPORT_DIR}/mikrotik_${TIMESTAMP}.txt"
SUMMARY="${REPORT_DIR}/summary_${TIMESTAMP}.txt"

mkdir -p "${REPORT_DIR}"

echo "=============================================="
echo "  MikroTik Network Vulnerability Scanner"
echo "  Target : ${TARGET}"
echo "  Time   : $(date)"
echo "=============================================="

echo ""
echo "[1/4] Host discovery..."

nmap -sn \
     -PE -PS22,53,80,443,8291 \
     --min-rate 300 \
     -oG "${HOSTS_OUT}" \
     "${TARGET}" 2>/dev/null

LIVE_HOSTS=$(grep "Status: Up" "${HOSTS_OUT}" | awk '{print $2}' | tr '\n' ' ')

if [ -z "$LIVE_HOSTS" ]; then
    echo "[WARN] Host discovery did not detect active hosts."
    echo "[WARN] Continuing with -Pn mode for target: ${TARGET}"
    LIVE_HOSTS="${TARGET}"
fi

echo "[+] Hosts selected for scanning: ${LIVE_HOSTS}"

echo ""
echo "[2/4] TCP port scanning..."

nmap -Pn -sT \
     -p T:21,22,23,25,53,80,443,445,1194,1723,2000,8080,8291,8443,8728,8729 \
     --open \
     --min-rate 100 \
     --host-timeout 90s \
     -oG "${GNMAP_OUT}" \
     -oN "${TXT_OUT}" \
     ${LIVE_HOSTS} 2>/dev/null || true

echo ""
echo "[3/4] Running NSE vulnerability scripts..."

nmap -Pn -sT -sV \
     --script="banner,vuln and safe,ftp-anon,ssh2-enum-algos,ssh-hostkey,ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,ssl-poodle,smb-vuln-ms17-010,smb-security-mode,http-title,http-server-header,http-auth-finder,http-default-accounts,mikrotik-routeros-brute,/scanner/nse-scripts/mikrotik-detect.nse" \
     --script-args="unsafe=0,mikrotik-routeros-brute.timeout=3s" \
     --script-timeout=20s \
     -p T:21,22,23,25,53,80,443,445,8080,8291,8443,8728,8729 \
     --min-rate 50 \
     --host-timeout 120s \
     -oN "${NSE_OUT}" \
     ${LIVE_HOSTS} 2>/dev/null || true

echo ""
echo "[4/4] MikroTik-specific checks..."

{
    echo "=== MikroTik Specific Security Checks ==="
    echo "Timestamp: $(date)"
    echo ""

    for HOST in ${LIVE_HOSTS}; do
        echo "--- Host: ${HOST} ---"

        if nmap -Pn -sT -p 8291 --open -oG - "${HOST}" 2>/dev/null | grep -q "8291/open"; then
            echo "[WARN] Port 8291 (Winbox) is open - restrict access to trusted IP addresses."
        fi

        if nmap -Pn -sT -p 8728 --open -oG - "${HOST}" 2>/dev/null | grep -q "8728/open"; then
            echo "[WARN] Port 8728 (RouterOS API) is open - disable it or filter access if not needed."
        fi

        if nmap -Pn -sT -p 8729 --open -oG - "${HOST}" 2>/dev/null | grep -q "8729/open"; then
            echo "[INFO] Port 8729 (RouterOS API SSL) is open."
        fi

        if nmap -Pn -sT -p 23 --open -oG - "${HOST}" 2>/dev/null | grep -q "23/open"; then
            echo "[CRITICAL] Port 23 (Telnet) is open - disable immediately. Traffic is not encrypted."
        fi

        if nmap -Pn -sT -p 21 --open -oG - "${HOST}" 2>/dev/null | grep -q "21/open"; then
            echo "[HIGH] Port 21 (FTP) is open - file transfer is not encrypted."
        fi

        if nmap -Pn -sT -p 80 --open -oG - "${HOST}" 2>/dev/null | grep -q "80/open"; then
            echo "[WARN] Port 80 (HTTP) is open - consider enforcing HTTPS."
        fi

        echo ""
    done
} > "${MIKROTIK_OUT}"

cat "${MIKROTIK_OUT}"
cat "${MIKROTIK_OUT}" >> "${NSE_OUT}"

echo ""
echo "[+] Generating final report..."

if [ -x "/scanner/scripts/report.sh" ]; then
    /scanner/scripts/report.sh \
        "${GNMAP_OUT}" \
        "${NSE_OUT}" \
        "${SUMMARY}" 2>/dev/null || true
else
    echo "[ERROR] report.sh not found or not executable." > "${SUMMARY}"
fi

echo ""
echo "=============================================="
echo "  Scan completed!"
echo "  Reports saved in: ${REPORT_DIR}"
echo "  - Port scan GNMAP : scan_${TIMESTAMP}.gnmap"
echo "  - NSE results TXT : nse_${TIMESTAMP}.txt"
echo "  - Summary         : summary_${TIMESTAMP}.txt"
echo "=============================================="

MAIL_BODY="${REPORT_DIR}/mail_body_${TIMESTAMP}.txt"
MAIL_FLAG="${REPORT_DIR}/SEND_MAIL_${TIMESTAMP}.flag"

CRITICAL_COUNT=$(grep -c "CRITICAL" "${SUMMARY}" 2>/dev/null || true)
HIGH_COUNT=$(grep -c "HIGH" "${SUMMARY}" 2>/dev/null || true)
WARN_COUNT=$(grep -c "WARN" "${SUMMARY}" 2>/dev/null || true)

CRITICAL_COUNT=${CRITICAL_COUNT:-0}
HIGH_COUNT=${HIGH_COUNT:-0}
WARN_COUNT=${WARN_COUNT:-0}

if [ "${CRITICAL_COUNT}" -gt 0 ]; then
    SUBJECT="[CRITICAL] Network scanner - ${CRITICAL_COUNT} critical findings | $(date +%Y-%m-%d)"
elif [ "${HIGH_COUNT}" -gt 0 ]; then
    SUBJECT="[HIGH] Network scanner - ${HIGH_COUNT} high severity findings | $(date +%Y-%m-%d)"
else
    SUBJECT="[OK] Network scanner - no critical findings | $(date +%Y-%m-%d)"
fi

{
    echo "SUBJECT=${SUBJECT}"
    echo "---BODY---"
    echo "MikroTik network security report"
    echo "Scan date: $(date)"
    echo "Scanned target: ${TARGET}"
    echo ""
    echo "SUMMARY:"
    echo "  CRITICAL : ${CRITICAL_COUNT}"
    echo "  HIGH     : ${HIGH_COUNT}"
    echo "  WARN     : ${WARN_COUNT}"
    echo ""
    echo "========================================"
    echo "DETAILED REPORT:"
    echo "========================================"
    cat "${SUMMARY}"
} > "${MAIL_BODY}"

touch "${MAIL_FLAG}"

echo ""
echo "[5/5] Mail body ready: ${MAIL_BODY}"
echo "[5/5] Mail flag ready: ${MAIL_FLAG}"
