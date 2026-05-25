-- ============================================================
-- mikrotik-detect.nse
-- Wykrywa urządzenia MikroTik RouterOS i zbiera informacje
-- o wersji oraz potencjalnych podatnościach
-- ============================================================

local nmap    = require "nmap"
local shortport = require "shortport"
local stdnse  = require "stdnse"
local http    = require "http"
local string  = require "string"

description = [[
Wykrywa urządzenia MikroTik RouterOS przez HTTP/HTTPS (Webfig),
Winbox (8291) i RouterOS API (8728/8729).
Zbiera informacje o wersji i sprawdza znane podatności.
]]

author  = "network-scanner"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

-- Działa na portach HTTP, Winbox i API
portrule = shortport.port_or_service(
    {80, 443, 8080, 8291, 8443, 8728, 8729},
    {"http", "https", "winbox"},
    "tcp"
)

-- Znane podatne wersje RouterOS
local VULNERABLE_VERSIONS = {
    -- CVE-2018-14847 (Winbox credentials leak)
    {pattern = "^6%.[3-3][0-9]%.",   cve = "CVE-2018-14847",
     desc    = "Winbox critical — wyciek danych uwierzytelniających"},
    -- CVE-2019-3943 (path traversal)
    {pattern = "^6%.4[0-3]%.",       cve = "CVE-2019-3943",
     desc    = "Path traversal via Winbox/HTTP"},
    -- Stare wersje v6 ogólnie
    {pattern = "^6%.[0-2][0-9]%.",   cve = "LEGACY",
     desc    = "Stara wersja RouterOS — wiele znanych podatności, aktualizuj!"},
}

local function check_version_vulns(version)
    local vulns = {}
    for _, v in ipairs(VULNERABLE_VERSIONS) do
        if string.match(version, v.pattern) then
            table.insert(vulns, string.format("[%s] %s", v.cve, v.desc))
        end
    end
    return vulns
end

local function check_http_mikrotik(host, port)
    local results = {}

    -- Sprawdź Webfig
    local paths = {"/", "/webfig/", "/index.html"}
    for _, path in ipairs(paths) do
        local resp = http.get(host, port, path, {timeout = 5000})
        if resp and resp.status then
            local body = resp.body or ""

            -- Wykryj MikroTik po charakterystycznych znacznikach
            if string.match(body, "MikroTik") or
               string.match(body, "RouterOS")  or
               string.match(body, "webfig")    then

                table.insert(results, "✓ Wykryto interfejs MikroTik Webfig")

                -- Wersja w tytule lub body
                local version = string.match(body, "RouterOS%s+([%d%.]+)")
                if version then
                    table.insert(results, "Wersja RouterOS: " .. version)
                    local vulns = check_version_vulns(version)
                    for _, v in ipairs(vulns) do
                        table.insert(results, "[!] PODATNOŚĆ: " .. v)
                    end
                end

                -- Sprawdź nagłówki bezpieczeństwa
                local headers = resp.header or {}
                if not headers["x-frame-options"] then
                    table.insert(results, "[WARN] Brak nagłówka X-Frame-Options")
                end
                if not headers["strict-transport-security"] and port.number == 443 then
                    table.insert(results, "[WARN] Brak HSTS na HTTPS")
                end

                -- Sprawdź domyślną stronę logowania
                if string.match(body, 'name="username"') or
                   string.match(body, 'id="username"') then
                    table.insert(results, "[INFO] Strona logowania dostępna publicznie")
                end

                break
            end
        end
    end

    return results
end

action = function(host, port)
    local output = stdnse.output_table()
    local results = {}

    -- Sprawdzenie HTTP/HTTPS
    if port.number == 80 or port.number == 443 or
       port.number == 8080 or port.number == 8443 then
        local http_results = check_http_mikrotik(host, port)
        for _, r in ipairs(http_results) do
            table.insert(results, r)
        end
    end

    -- Winbox port
    if port.number == 8291 then
        table.insert(results, "[WARN] Port Winbox (8291) otwarty")
        table.insert(results, "       Upewnij się że dostęp jest ograniczony firewallem")
        table.insert(results, "       Podatne na CVE-2018-14847 jeśli RouterOS < 6.40.9")
    end

    -- RouterOS API
    if port.number == 8728 then
        table.insert(results, "[WARN] RouterOS API (8728) otwarty — nieszyfrowany!")
        table.insert(results, "       Rozważ użycie API-SSL (8729) lub wyłączenie API")
    end

    if port.number == 8729 then
        table.insert(results, "[INFO] RouterOS API SSL (8729) otwarty")
    end

    if #results == 0 then
        return nil
    end

    return table.concat(results, "\n")
end
