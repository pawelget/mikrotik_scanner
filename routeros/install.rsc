:log info "BSO: installation started"

:local diskName "sata1"
:local reportDir "sata1/reports"
:local containerName "bso-scanner-podman"
:local tarName "bso-scanner-podman.tar"
:local tarUrl "https://github.com/pawelget/mikrotik_scanner/releases/bso-scanner-podman.tar"

# Container config
/container/config/set registry-url=https://registry-1.docker.io tmpdir=($diskName . "/tmp")

# VETH
:if ([:len [/interface/veth/find where name="veth-bso"]] = 0) do={
    /interface/veth/add name=veth-bso address=172.17.0.2/24 gateway=172.17.0.1
}

# Bridge
:if ([:len [/interface/bridge/find where name="br-containers"]] = 0) do={
    /interface/bridge/add name=br-containers
}

:if ([:len [/interface/bridge/port/find where interface="veth-bso"]] = 0) do={
    /interface/bridge/port/add bridge=br-containers interface=veth-bso
}

# IP dla bridge kontenerow
:if ([:len [/ip/address/find where address="172.17.0.1/24"]] = 0) do={
    /ip/address/add address=172.17.0.1/24 interface=br-containers
}

# NAT dla kontenerow
:if ([:len [/ip/firewall/nat/find where src-address="172.17.0.0/24"]] = 0) do={
    /ip/firewall/nat/add chain=srcnat src-address=172.17.0.0/24 action=masquerade comment="BSO container NAT"
}

# DNS
/ip/dns/set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8

# Mount raportow
:if ([:len [/container/mounts/find where list="bso-reports"]] = 0) do={
    /container/mounts/add list=bso-reports src=$reportDir dst=/scanner/reports
}

# Usuniecie starego kontenera i katalogu
:if ([:len [/container/find where name=$containerName]] > 0) do={
    /container/remove [find where name=$containerName]
}

:if ([:len [/file/find where name=($diskName . "/bso-scanner")]] > 0) do={
    /file/remove [find where name=($diskName . "/bso-scanner")]
}

# Pobranie obrazu kontenera
:if ([:len [/file/find where name=$tarName]] > 0) do={
    /file/remove [find where name=$tarName]
}

/tool/fetch url=$tarUrl dst-path=$tarName

# Import kontenera
/container/add file=$tarName interface=veth-bso mountlists=bso-reports root-dir=($diskName . "/bso-scanner") cmd="auto" logging=yes

# Usuniecie starego skryptu bso-send-report
:if ([:len [/system/script/find where name="bso-send-report"]] > 0) do={
    /system/script/remove [find where name="bso-send-report"]
}

# Dodanie bso-send-report
/system/script/add name=bso-send-report source={
    :local reportDir "sata1/reports"
    :local mailTo "ADRES_EMAIL_DO_RAPORTU"

    :foreach flagId in=[/file/find where name~"sata1/reports/SEND_MAIL_"] do={
        :local flagName [/file/get $flagId name]
        :local timestamp [:pick $flagName 24 39]
        :local summaryFile ($reportDir . "/summary_" . $timestamp . ".txt")

        :local summaryId [/file/find where name=$summaryFile]

        :if ([:len $summaryId] > 0) do={
            /tool/e-mail/send to=$mailTo subject=("BSO raport skanowania sieci " . $timestamp) body=("Automatyczny raport bezpieczenstwa sieci BSO. Znacznik czasu: " . $timestamp) file=$summaryFile

            /file/remove [find where name~$timestamp]
            :log info ("BSO: report sent and files removed: " . $timestamp)
        } else={
            :log error ("BSO: summary not found for " . $timestamp)
        }
    }
}

# Usuniecie starego skryptu bso-run-scan
:if ([:len [/system/script/find where name="bso-run-scan"]] > 0) do={
    /system/script/remove [find where name="bso-run-scan"]
}

# Dodanie bso-run-scan
/system/script/add name=bso-run-scan source={
    :local scanInterface "ether1"
    :local target ""
    :local maxWait 40
    :local waitStep 30
    :local reportSent false

    :log info "BSO: starting automatic LAN scan"

    :foreach a in=[/ip/address/find where interface=$scanInterface disabled=no] do={
        :local addr [/ip/address/get $a address]

        :if (($target = "") && ($addr !~ "172.17.")) do={
            :set target $addr
        }
    }

    :if ($target = "") do={
        :log error ("BSO: no IP address found on interface " . $scanInterface)
        :error "No target network detected"
    }

    :log info ("BSO: detected scan target: " . $target)

    :local containerId [/container/find where name="bso-scanner-podman"]

    :if ([:len $containerId] = 0) do={
        :log error "BSO: scanner container not found"
        :error "Scanner container not found"
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
                :log info "BSO: mail flag detected, sending report"
                /system/script/run bso-send-report
                :set reportSent true
                :log info "BSO: full scan flow finished"
            } else={
                :log info ("BSO: report not ready yet, attempt " . $i . "/" . $maxWait)
            }
        }
    }

    :if ($reportSent = false) do={
        :log warning "BSO: timeout waiting for SEND_MAIL flag"
    }
}

:log info "BSO: installation finished"