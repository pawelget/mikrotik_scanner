# BSO MikroTik Network Scanner

Automatyczny skaner sieci lokalnej uruchamiany jako kontener RouterOS.

## Wymagania

- RouterOS v7
- pakiet container
- wlaczone `/system/device-mode/update container=yes`
- dysk `sata1`
- skonfigurowany `/tool e-mail`
- dostep SSH do MikroTika

## Instalacja jedna komenda

```routeros
/tool/fetch url="https://raw.githubusercontent.com/pawelget/mikrotik_scanner/main/routeros/install.rsc" dst-path=install.rsc; /import install.rsc
```

## Ręczne uruchomienie skanu

```routeros
/system/script/run bso-run-scan
```

## Budowanie `.tar` na Windows + WSL Ubuntu

W WSL:

```bash
cd "/mnt/c/Users/USER/Desktop/bso-mikrotik-scanner"

chmod +x scripts/scan.sh scripts/report.sh

podman build --no-cache --platform linux/amd64 -t bso-scanner-mtik .

podman save --format docker-archive -o bso-scanner-podman.tar bso-scanner-mtik
