# ============================================================
# BSO MikroTik Scanner - installer for RouterOS
# ============================================================

:global bsoMailTo
:global bsoSmtpPassword
:global bsoTarget

:local diskName "sata1"
:local reportDir "sata1/reports"
:local tmpDir "sata1/tmp"
:local rootDir "sata1/bso-scanner"

:local containerName "bso-scanner-podman"
:local tarName "bso-scanner-podman.tar"
:local tarUrl "https://raw.githubusercontent.com/pawelget/mikrotik_scanner/main/releases/bso-scanner-podman.tar"

:local smtpAddress "smtp.gmail.com"
:local smtpPort 587
:local smtpTls "starttls"

# Nadawca jest predefiniowany w instalatorze.
# Haslo NIE jest trzymane w repozytorium.
:local smtpFrom "bsomikrotik@gmail.com"
:local smtpUser "bsomikrotik@gmail.com"

:if ([:typeof $bsoMailTo] = "nothing") do={
    :error "BSO: missing bsoMailTo"
}

:if ([:typeof $bsoSmtpPassword] = "nothing") do={
    :error "BSO: missing bsoSmtpPassword"
}

:log info "BSO: installation started"

# ============================================================
# Basic checks
# ============================================================

:if ([:len [/file/find where name=$diskName]] = 0) do={
    :error "BSO: disk sata1 not found. Add and format disk first."
}

# ============================================================
# E-mail configuration
# ============================================================

/tool/e-mail/set address=$smtpAddress port=$smtpPort tls=$smtpTls from=$smtpFrom user=$smtpUser password=$bsoSmtpPassword

# Czyszczenie zmiennej globalnej z haslem po zapisaniu konfiguracji e-mail.
:set bsoSmtpPassword "CLEARED"

:log info "BSO: e-mail configured"

# ============================================================
# Container storage config
# ============================================================

/container/config/set registry-url=https://registry-1.docker.io tmpdir=$tmpDir

# ============================================================
# Network config for container
# ============================================================

:if ([:len [/interface/find where name="veth-bso"]] = 0) do={
    /interface/veth/add name=veth-bso address=172.17.0.2/24 gateway=172.17.0.1
}

:if ([:len [/interface/bridge/find where name="br-containers"]] = 0) do={
    /interface/bridge/add name=br-containers
}

:if ([:len [/interface/bridge/port/find where interface="veth-bso"]] = 0) do={
    /interface/bridge/port/add bridge=br-containers interface=veth-bso
}

:if ([:len [/ip/address/find where address="172.17.0.1/24"]] = 0) do={
    /ip/address/add address=172.17.0.1/24 interface=br-containers
}

/ip/dns/set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8

/ip/firewall/nat/remove [find where comment="BSO container NAT"]
/ip/firewall/nat/add chain=srcnat src-address=172.17.0.0/24 action=masquerade comment="BSO container NAT"

:log info "BSO: container network configured"

# ============================================================
# Mount list for reports
# ============================================================

/container/mounts/remove [find where list="bso-reports"]
/container/mounts/add list=bso-reports src=$reportDir dst=/scanner/reports

:log info "BSO: report mount configured"

# ============================================================
# Remove old container and old files
# ============================================================

/container/stop [find where name=$containerName]
/container/remove [find where name=$containerName]

:if ([:len [/file/find where name=$rootDir]] > 0) do={
    /file/remove [find where name=$rootDir]
}

:if ([:len [/file/find where name=$tarName]] > 0) do={
    /file/remove [find where name=$tarName]
}

# ============================================================
# Download and import container image
# ============================================================

:log info "BSO: downloading container image"

/tool/fetch url=$tarUrl dst-path=$tarName check-certificate=no

:log info "BSO: importing container"

/container/add file=$tarName interface=veth-bso mountlists=bso-reports root-dir=$rootDir cmd="auto" logging=yes

# Po imporcie plik tar nie jest potrzebny.
:if ([:len [/file/find where name=$tarName]] > 0) do={
    /file/remove [find where name=$tarName]
}

:log info "BSO: container imported"

# ============================================================
# Remove old scripts and schedulers
# ============================================================

/system/script/remove [find where name="bso-run-scan"]
/system/script/remove [find where name="bso-send-report"]
/system/scheduler/remove [find where name="bso-daily-scan"]

# ============================================================
# Script: bso-send-report
# ============================================================

/system/script/add name=bso-send-report source={
    :global bsoMailTo

    :local reportDir "sata1/reports"

    :if ([:typeof $bsoMailTo] = "nothing") do={
        :log error "BSO: missing bsoMailTo"
        :error "BSO: missing bsoMailTo"
    }

    :log info "BSO: checking for report flags"

    :foreach flagId in=[/file/find where name~"sata1/reports/SEND_MAIL_"] do={

        :local flagName [/file/get $flagId name]
        :local timestamp [:pick $flagName 24 39]
        :local summaryFile ($reportDir . "/summary_" . $timestamp . ".txt")

        :local summaryId [/file/find where name=$summaryFile]

        :if ([:len $summaryId] > 0) do={

            :local subject ("BSO raport skanowania sieci " . $timestamp)
            :local body ("Automatyczny raport bezpieczenstwa sieci BSO. Znacznik czasu: " . $timestamp)

            /tool/e-mail/send to=$bsoMailTo subject=$subject body=$body file=$summaryFile

            /file/remove [find where name~$timestamp]

            :log info ("BSO: report sent to " . $bsoMailTo . " and files removed: " . $timestamp)

        } else={
            :log error ("BSO: summary not found for " . $timestamp)
        }
    }
}

# ============================================================
# Script: bso-run-scan
# ============================================================

/system/script/add name=bso-run-scan source={
    :global bsoTarget

    :local target ""
    :local maxWait 30
    :local waitStep 30
    :local reportSent false

    :if ([:typeof $bsoTarget] = "nothing") do={

        :local addressId [/ip/address/find where interface="ether1"]

        :if ([:len $addressId] > 0) do={
            :local addressValue [/ip/address/get [:pick $addressId 0] address]
            :local slashPos [:find $addressValue "/"]
            :set target [:pick $addressValue 0 $slashPos]
        } else={
            :set target "10.0.2.15"
        }

    } else={
        :set target $bsoTarget
    }

    :log info ("BSO: starting full scan flow for target " . $target)

    :local containerId [/container/find where name="bso-scanner-podman"]

    :if ([:len $containerId] = 0) do={
        :log error "BSO: scanner container not found"
        :error "BSO: scanner container not found"
    }

    /container/set $containerId cmd=$target
    /container/start $containerId

    :log info "BSO: scanner container started"
    :log info "BSO: waiting for SEND_MAIL flag"

    :for i from=1 to=$maxWait do={

        :if ($reportSent = false) do={

            :delay ($waitStep . "s")

            :local flags [/file/find where name~"sata1/reports/SEND_MAIL_"]

            :if ([:len $flags] > 0) do={
                :log info "BSO: mail flag detected, running send-report script"
                /system/script/run bso-send-report
                :log info "BSO: full scan flow finished"
                :set reportSent true
            } else={
                :log info ("BSO: report not ready yet, attempt " . $i . "/" . $maxWait)
            }
        }
    }

    :if ($reportSent = false) do={
        :log warning "BSO: timeout waiting for SEND_MAIL flag"
    }
}


:log info "BSO: scheduler created but disabled"
:log info "BSO: installation completed"
:log info "BSO: run manually with /system/script/run bso-run-scan"
