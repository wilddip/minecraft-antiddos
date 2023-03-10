#!/bin/bash

#export IPTABLES_CMD=
default_ipt_cmd="/sbin/iptables"

if [ "$EUID" -ne 0 ]; then
    # Can be run as normal user, will just use "sudo"
    export su=sudo
fi

function usage() {
    echo ""
    echo " $0 - ANTI-DDOS ПРАВИЛА"
    echo ""
    echo "Usage:"
    echo "------"
    echo " Script    : $0"
    echo " Parameters: [-vf]"
    echo ""
    echo "  -v : verbose"
    echo "  -f : Flush rules before creating new rules"
    echo ""
}

##  --- Parse command line arguments ---
while getopts ":i:p:vf" option; do
    case $option in
        v)
            VERBOSE=yes
            ;;
        f)
            FLUSH=yes
            ;;
        ?|*)
            echo ""
            echo "[ERROR] Unknown parameter \"$OPTARG\""
            usage
            exit 2
    esac
done
shift $[ OPTIND - 1 ]

# Extra checking for iptables
if [ -z "$IPTABLES_CMD" ]; then
    echo "WARNING: Shell env variable IPTABLES_CMD is undefined"
    export IPTABLES_CMD=${default_ipt_cmd}
    echo "WARNING: Fallback to default IPTABLES_CMD=${default_ipt_cmd}"
fi

#
# A shell iptables function wrapper
#
iptables() {
    $su $IPTABLES_CMD "$@"
    local result=$?
    if [ ${result} -gt 0 ]; then
        echo "WARNING -- Error (${result}) when executing the iptables command:"
        echo " \"iptables $@\""
    else
        if [ -n "${VERBOSE}" ]; then
            echo "iptables $@"
        fi
    fi
}

# Cleanup before applying our rules
if [ -n "$FLUSH" ]; then
    iptables -t raw -F
    iptables -t raw -X
    iptables -F
    iptables -X
fi

# SYNPROXY works on untracked conntracks
#  it will create the appropiate conntrack proxied TCP conn
# NOTICE: table "raw"

## ОТРУБИЛ 2 ПРАВИЛА НИЖЕ ИБО МЫ ТЕРЯЛИ ЛЮДЕЙ
## ЕСЛИ БУДЕТ ПИЗДЕЦ
## https://github.com/github/synsanity

## Drop rest of state INVALID
## This will e.g. catch SYN-ACK packet attacks

#iptables -A INPUT -i $DEV -p tcp -m tcp --dport $PORT \
#    -m state --state INVALID -j DROP

## Разрешить существующим соединениям шмыгать туды-сюды
iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

## Блокирование INVALID-пакетов
iptables -A INPUT -i eth0 -m conntrack --ctstate INVALID -j DROP

## Блокирование новых пакетов, которые не имеют флага SYN
iptables -A INPUT -i eth0 -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

## Блокирование нестандартных значений MSS
iptables -A INPUT -i eth0 -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

## Блокирование пакетов с неверными TCP флагами
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP


## Защита от сканирования портов
# ОТРУБИЛ ДО УТОЧНЕНИЯ

iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP


## Ограничение на коннкеты с одного адреса
iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 20 --connlimit-mask 32 --connlimit-saddr -j DROP
iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j REJECT --reject-with icmp-port-unreachable

## udp пошел в жопу
iptables -A INPUT -p udp -j DROP

## защита от ддоса по ICMP NOT WORKING
#iptables -A PREROUTING -p icmp -j DROP




# More strict conntrack handling to get unknown ACKs (from 3WHS) to be
#  marked as INVALID state (else a conntrack is just created)
#
#$su /sbin/sysctl -w net/netfilter/nf_conntrack_tcp_loose=0

# Enable timestamping, because SYN cookies uses TCP options field
#$su /sbin/sysctl -w net/ipv4/tcp_timestamps=1

# Adjusting maximum number of connection tracking entries possible
#
# Conntrack element size 288 bytes found in /proc/slabinfo
#  "nf_conntrack" <objsize> = 288
#
# 288 * 2000000 / 10^6 = 576.0 MB
$su /sbin/sysctl -w net/netfilter/nf_conntrack_max=2000000

# IMPORTANT: Also adjust hash bucket size for conntracks
#   net/netfilter/nf_conntrack_buckets writeable
#   via /sys/module/nf_conntrack/parameters/hashsize
#
# Hash entry 8 bytes pointer (uses struct hlist_nulls_head)
#  8 * 2000000 / 10^6 = 16 MB
$su sh -c 'echo 2000000 > /sys/module/nf_conntrack/parameters/hashsize'
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/ip_forward
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/mc_forwarding; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done
echo "a2VybmVsLnByaW50ayA9IDQgNCAxIDcgCmtlcm5lbC5wYW5pYyA9IDEwIAprZXJuZWwuc3lzcnEgPSAwIAprZXJuZWwuc2htbWF4ID0gNDI5NDk2NzI5NiAKa2VybmVsLnNobWFsbCA9IDQxOTQzMDQgCmtlcm5lbC5jb3JlX3VzZXNfcGlkID0gMSAKa2VybmVsLm1zZ21uYiA9IDY1NTM2IAprZXJuZWwubXNnbWF4ID0gNjU1MzYgCnZtLnN3YXBwaW5lc3MgPSAyMCAKdm0uZGlydHlfcmF0aW8gPSA4MCAKdm0uZGlydHlfYmFja2dyb3VuZF9yYXRpbyA9IDUgCmZzLmZpbGUtbWF4ID0gMjA5NzE1MiAKbmV0LmNvcmUubmV0ZGV2X21heF9iYWNrbG9nID0gMjYyMTQ0IApuZXQuY29yZS5ybWVtX2RlZmF1bHQgPSAzMTQ1NzI4MCAKbmV0LmNvcmUucm1lbV9tYXggPSA2NzEwODg2NCAKbmV0LmNvcmUud21lbV9kZWZhdWx0ID0gMzE0NTcyODAgCm5ldC5jb3JlLndtZW1fbWF4ID0gNjcxMDg4NjQgCm5ldC5jb3JlLnNvbWF4Y29ubiA9IDY1NTM1IApuZXQuY29yZS5vcHRtZW1fbWF4ID0gMjUxNjU4MjQgCm5ldC5pcHY0Lm5laWdoLmRlZmF1bHQuZ2NfdGhyZXNoMSA9IDQwOTYgCm5ldC5pcHY0Lm5laWdoLmRlZmF1bHQuZ2NfdGhyZXNoMiA9IDgxOTIgCm5ldC5pcHY0Lm5laWdoLmRlZmF1bHQuZ2NfdGhyZXNoMyA9IDE2Mzg0IApuZXQuaXB2NC5uZWlnaC5kZWZhdWx0LmdjX2ludGVydmFsID0gNSAKbmV0LmlwdjQubmVpZ2guZGVmYXVsdC5nY19zdGFsZV90aW1lID0gMTIwIApuZXQubmV0ZmlsdGVyLm5mX2Nvbm50cmFja19tYXggPSAxMDAwMDAwMCAKbmV0Lm5ldGZpbHRlci5uZl9jb25udHJhY2tfdGNwX2xvb3NlID0gMCAKbmV0Lm5ldGZpbHRlci5uZl9jb25udHJhY2tfdGNwX3RpbWVvdXRfZXN0YWJsaXNoZWQgPSAxODAwIApuZXQubmV0ZmlsdGVyLm5mX2Nvbm50cmFja190Y3BfdGltZW91dF9jbG9zZSA9IDEwIApuZXQubmV0ZmlsdGVyLm5mX2Nvbm50cmFja190Y3BfdGltZW91dF9jbG9zZV93YWl0ID0gMTAgCm5ldC5uZXRmaWx0ZXIubmZfY29ubnRyYWNrX3RjcF90aW1lb3V0X2Zpbl93YWl0ID0gMjAgCm5ldC5uZXRmaWx0ZXIubmZfY29ubnRyYWNrX3RjcF90aW1lb3V0X2xhc3RfYWNrID0gMjAgCm5ldC5uZXRmaWx0ZXIubmZfY29ubnRyYWNrX3RjcF90aW1lb3V0X3N5bl9yZWN2ID0gMjAgCm5ldC5uZXRmaWx0ZXIubmZfY29ubnRyYWNrX3RjcF90aW1lb3V0X3N5bl9zZW50ID0gMjAgCm5ldC5uZXRmaWx0ZXIubmZfY29ubnRyYWNrX3RjcF90aW1lb3V0X3RpbWVfd2FpdCA9IDEwIApuZXQuaXB2NC50Y3Bfc2xvd19zdGFydF9hZnRlcl9pZGxlID0gMCAKbmV0LmlwdjQuaXBfbG9jYWxfcG9ydF9yYW5nZSA9IDEwMjQgNjUwMDAgCm5ldC5pcHY0LmlwX25vX3BtdHVfZGlzYyA9IDEgCm5ldC5pcHY0LnJvdXRlLmZsdXNoID0gMSAKbmV0LmlwdjQucm91dGUubWF4X3NpemUgPSA4MDQ4NTc2IApuZXQuaXB2NC5pY21wX2VjaG9faWdub3JlX2Jyb2FkY2FzdHMgPSAxIApuZXQuaXB2NC5pY21wX2lnbm9yZV9ib2d1c19lcnJvcl9yZXNwb25zZXMgPSAxIApuZXQuaXB2NC50Y3BfY29uZ2VzdGlvbl9jb250cm9sID0gaHRjcCAKbmV0LmlwdjQudGNwX21lbSA9IDY1NTM2IDEzMTA3MiAyNjIxNDQgCm5ldC5pcHY0LnVkcF9tZW0gPSA2NTUzNiAxMzEwNzIgMjYyMTQ0IApuZXQuaXB2NC50Y3Bfcm1lbSA9IDQwOTYgODczODAgMzM1NTQ0MzIgCm5ldC5pcHY0LnVkcF9ybWVtX21pbiA9IDE2Mzg0IApuZXQuaXB2NC50Y3Bfd21lbSA9IDQwOTYgODczODAgMzM1NTQ0MzIgCm5ldC5pcHY0LnVkcF93bWVtX21pbiA9IDE2Mzg0IApuZXQuaXB2NC50Y3BfbWF4X3R3X2J1Y2tldHMgPSAxNDQwMDAwIApuZXQuaXB2NC50Y3BfdHdfcmVjeWNsZSA9IDAgCm5ldC5pcHY0LnRjcF90d19yZXVzZSA9IDEgCm5ldC5pcHY0LnRjcF9tYXhfb3JwaGFucyA9IDQwMDAwMCAKbmV0LmlwdjQudGNwX3dpbmRvd19zY2FsaW5nID0gMSAKbmV0LmlwdjQudGNwX3JmYzEzMzcgPSAxIApuZXQuaXB2NC50Y3Bfc3luY29va2llcyA9IDEgCm5ldC5pcHY0LnRjcF9zeW5hY2tfcmV0cmllcyA9IDEgCm5ldC5pcHY0LnRjcF9zeW5fcmV0cmllcyA9IDIgCm5ldC5pcHY0LnRjcF9tYXhfc3luX2JhY2tsb2cgPSAxNjM4NCAKbmV0LmlwdjQudGNwX3RpbWVzdGFtcHMgPSAxIApuZXQuaXB2NC50Y3Bfc2FjayA9IDEgCm5ldC5pcHY0LnRjcF9mYWNrID0gMSAKbmV0LmlwdjQudGNwX2VjbiA9IDIgCm5ldC5pcHY0LnRjcF9maW5fdGltZW91dCA9IDEwIApuZXQuaXB2NC50Y3Bfa2VlcGFsaXZlX3RpbWUgPSA2MDAgCm5ldC5pcHY0LnRjcF9rZWVwYWxpdmVfaW50dmwgPSA2MCAKbmV0LmlwdjQudGNwX2tlZXBhbGl2ZV9wcm9iZXMgPSAxMCAKbmV0LmlwdjQudGNwX25vX21ldHJpY3Nfc2F2ZSA9IDEgCm5ldC5pcHY0LmlwX2ZvcndhcmQgPSAwIApuZXQuaXB2NC5jb25mLmFsbC5hY2NlcHRfcmVkaXJlY3RzID0gMCAKbmV0LmlwdjQuY29uZi5hbGwuc2VuZF9yZWRpcmVjdHMgPSAwIApuZXQuaXB2NC5jb25mLmFsbC5hY2NlcHRfc291cmNlX3JvdXRlID0gMCAKbmV0LmlwdjQuY29uZi5hbGwucnBfZmlsdGVyID0gMQ==" | base64 -d > /etc/sysctl.conf
sysctl -p
clear

# Hint: Monitor nf_conntrack usage searched, found, new, etc.:
#  lnstat -c -1 -f nf_conntrack
