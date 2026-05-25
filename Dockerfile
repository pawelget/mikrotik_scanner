# ============================================================
# nmap/NSE scanner for MikroTik RouterOS v7 ARM
# Base: Alpine Linux + nmap + nmap-scripts
# ============================================================
FROM alpine:3.19

LABEL maintainer="network-scanner"
LABEL description="Nmap NSE vulnerability scanner for MikroTik RouterOS v7"
LABEL arch="amd64"

RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    bash \
    tzdata \
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

ENV TZ=Europe/Warsaw

WORKDIR /scanner
RUN mkdir -p /scanner/reports /scanner/scripts /scanner/nse-scripts

COPY scripts/scan.sh    /scanner/scripts/scan.sh
COPY scripts/report.sh  /scanner/scripts/report.sh
COPY nse-scripts/       /scanner/nse-scripts/

RUN chmod +x /scanner/scripts/scan.sh \
             /scanner/scripts/report.sh

VOLUME ["/scanner/reports"]

ENTRYPOINT ["/scanner/scripts/scan.sh"]
CMD ["192.168.88.0/24"]
