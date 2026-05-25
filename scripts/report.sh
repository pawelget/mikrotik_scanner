#!/bin/bash
# ============================================================
# report.sh — generuje raport koncowy po polsku
# Argumenty:
#   $1 - plik GNMAP ze skanu portow
#   $2 - plik TXT z wynikami NSE/MikroTik checks
#   $3 - plik wyjsciowy summary
# ============================================================

PORTSCAN="$1"
NSE_OUT="$2"
OUTPUT="$3"

TARGET=$(grep -m1 "Nmap scan report for" "${NSE_OUT}" 2>/dev/null | awk '{print $5}')
if [ -z "$TARGET" ]; then
    TARGET="nieustalony"
fi

HOSTS_WITH_PORTS=$(grep -c "Ports:" "${PORTSCAN}" 2>/dev/null || true)
OPEN_PORTS=$(grep -o "/open/" "${PORTSCAN}" 2>/dev/null | wc -l || true)
FILTERED_PORTS=$(grep -Ei "filtered|open\|filtered" "${NSE_OUT}" 2>/dev/null | wc -l || true)

CRITICAL=$(grep -c "\[CRITICAL\]" "${NSE_OUT}" 2>/dev/null || true)
HIGH=$(grep -c "\[HIGH\]" "${NSE_OUT}" 2>/dev/null || true)
WARN=$(grep -c "\[WARN\]" "${NSE_OUT}" 2>/dev/null || true)
NSE_VULNS=$(grep -c "VULNERABLE\|CVE-" "${NSE_OUT}" 2>/dev/null || true)

HOSTS_WITH_PORTS=${HOSTS_WITH_PORTS:-0}
OPEN_PORTS=${OPEN_PORTS:-0}
FILTERED_PORTS=${FILTERED_PORTS:-0}
CRITICAL=${CRITICAL:-0}
HIGH=${HIGH:-0}
WARN=${WARN:-0}
NSE_VULNS=${NSE_VULNS:-0}

{
    echo "============================================================"
    echo "  RAPORT BEZPIECZENSTWA SIECI — MikroTik Scanner"
    echo "  Wygenerowano: $(date)"
    echo "============================================================"
    echo ""
    echo "PODSUMOWANIE:"
    echo "  Skanowany cel                 : ${TARGET}"
    echo "  Hosty z wykrytymi portami     : ${HOSTS_WITH_PORTS}"
    echo "  Otwarte porty                 : ${OPEN_PORTS}"
    echo "  Porty filtrowane              : ${FILTERED_PORTS}"
    echo "  Wykryte podatnosci NSE/CVE    : ${NSE_VULNS}"
    echo ""
    echo "POZIOMY ZAGROZEN:"
    echo "  [CRITICAL] : ${CRITICAL}"
    echo "  [HIGH]     : ${HIGH}"
    echo "  [WARN]     : ${WARN}"
    echo ""

    if [ "${OPEN_PORTS}" -eq 0 ]; then
        echo "WYNIK OGOLNY:"
        echo "  Nie wykryto otwartych portow w badanym zakresie."
        if [ "${FILTERED_PORTS}" -gt 0 ]; then
            echo "  Wykryto jednak porty w stanie filtered/open|filtered."
            echo "  Oznacza to, ze host lub firewall filtruje ruch i nie potwierdza jednoznacznie stanu portow."
        fi
        echo ""
    else
        echo "WYNIK OGOLNY:"
        echo "  Wykryto otwarte porty. Nalezy zweryfikowac, czy wszystkie uslugi sa potrzebne."
        echo ""
    fi

    if [ "${CRITICAL}" -gt 0 ] || [ "${HIGH}" -gt 0 ]; then
        echo "------------------------------------------------------------"
        echo "KRYTYCZNE I WAZNE OSTRZEZENIA:"
        echo "------------------------------------------------------------"
        grep "\[CRITICAL\]\|\[HIGH\]" "${NSE_OUT}" 2>/dev/null || true
        echo ""
    fi

    echo "------------------------------------------------------------"
    echo "WYNIKI SKRYPTOW NSE / USLUG:"
    echo "------------------------------------------------------------"
    grep -E "VULNERABLE|CVE-|vulnerable|open|filtered|ssl|ssh|ftp|http|Winbox|RouterOS|Telnet|FTP|HTTP" \
        "${NSE_OUT}" 2>/dev/null | head -100 || true
    echo ""

    echo "------------------------------------------------------------"
    echo "OTWARTE PORTY:"
    echo "------------------------------------------------------------"
    if [ "${OPEN_PORTS}" -eq 0 ]; then
        echo "  Brak otwartych portow w badanym zakresie."
    else
        awk '/Ports:/{
            host=$2
            line=$0
            sub(/.*Ports: /,"",line)
            n=split(line, ports, ", ")
            for(i=1;i<=n;i++){
                split(ports[i], p, "/")
                if(p[2]=="open")
                    printf "  %-18s  %s/%s  %s\n", host, p[1], p[3], p[5]
            }
        }' "${PORTSCAN}" 2>/dev/null || true
    fi
    echo ""

    echo "============================================================"
    echo "ZALECENIA:"
    echo "============================================================"

    if [ "${OPEN_PORTS}" -eq 0 ]; then
        echo "  1. Nie wykryto otwartych portow zarzadzania w badanym zakresie."
        echo "  2. Porty filtrowane moga oznaczac dzialajacy firewall — to dobry znak."
        echo "  3. Warto okresowo powtarzac skan po zmianach konfiguracji sieci."
        echo "  4. Upewnij sie, ze dostep do routera od strony WAN jest zablokowany."
        echo "  5. Aktualizuj RouterOS oraz urzadzenia sieciowe."
    else
        echo "  1. Wylacz Telnet i uzywaj SSH zamiast niego."
        echo "  2. Ogranicz dostep do Winbox tylko do zaufanych adresow IP."
        echo "  3. Wylacz RouterOS API, jesli nie jest potrzebne."
        echo "  4. Aktualizuj RouterOS do najnowszej stabilnej wersji."
        echo "  5. Wylacz HTTP lub przekieruj panel na HTTPS."
        echo "  6. Uzywaj silnych hasel administracyjnych."
        echo "  7. Blokuj porty zarzadzania od strony niezaufanych sieci."
    fi

} > "${OUTPUT}"

cat "${OUTPUT}"
