#!/bin/sh
# Re-download the real-world test corpus into testdata-real/ (gitignored).
# Sources: tcpreplay sample captures (S3) and the Wireshark project's
# wiki + test corpus. tests/real_world.rs sweeps whatever is present and
# skips silently when the directory is empty.
set -eu
cd "$(dirname "$0")/../testdata-real" 2>/dev/null || { mkdir -p "$(dirname "$0")/../testdata-real" && cd "$(dirname "$0")/../testdata-real"; }

S3="https://s3.amazonaws.com/tcpreplay-pcap-files"
WIKI="https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures"
TEST="https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures"

get() { [ -f "$2" ] || curl -sL --max-time 300 -o "$2" "$1" || true; }

get "$S3/smallFlows.pcap"                smallFlows.pcap
get "$S3/bigFlows.pcap"                  bigFlows.pcap
get "$WIKI/teardrop.cap"                 teardrop.cap
get "$WIKI/dhcp.pcap"                    dhcp.pcap
get "$WIKI/dns.cap"                      dns.cap
get "$WIKI/v6.pcap"                      v6.pcap
get "$WIKI/arp-storm.pcap"               arp-storm.pcap
get "$WIKI/nb6-startup.pcap"             nb6-startup.pcap
get "$WIKI/SkypeIRC.cap"                 SkypeIRC.cap
get "$WIKI/ipv4frags.pcap"               ipv4frags.pcap
get "$WIKI/mpls-basic.cap"               mpls-basic.cap
get "$WIKI/Network_Join_Nokia_Mobile.pcap" Network_Join_Nokia_Mobile.pcap
get "$WIKI/telnet-cooked.pcap"           telnet-cooked.pcap
get "$WIKI/smb-on-windows-10.pcapng"     smb-on-windows-10.pcapng
get "$WIKI/sctp-www.cap"                 sctp-www.cap
get "$TEST/dhcp.pcapng"                  wstest-dhcp.pcapng
get "$TEST/dhcp-nanosecond.pcap"         wstest-dhcp-nanosecond.pcap
get "$TEST/sip.pcapng"                   wstest-sip.pcapng
get "$TEST/http.pcap"                    wstest-http.pcap
get "$TEST/dns_port.pcap"                wstest-dns_port.pcap
get "$TEST/tls12-dsb.pcapng"             wstest-tls12-dsb.pcapng
get "$TEST/segmented_fpm.pcap"           wstest-segmented_fpm.pcap

get "$WIKI/cdp_v2.pcap"                  cdp_v2.pcap
get "$WIKI/wpa-Induction.pcap"           wpa-Induction.pcap
TCPD="https://github.com/the-tcpdump-group/tcpdump/raw/master/tests"
get "$TCPD/espudp1.pcap"                 tcpd-espudp1.pcap
get "$TCPD/vrrp.pcap"                    tcpd-vrrp.pcap
get "$TCPD/ospf-gmpls.pcap"              tcpd-ospf-gmpls.pcap
get "$TCPD/mpls-ldp-hello.pcap"          tcpd-mpls-ldp-hello.pcap
get "$TCPD/forces1.pcap"                 tcpd-forces1.pcap
get "$TCPD/babel.pcap"                   tcpd-babel.pcap
get "$TCPD/lmp.pcap"                     tcpd-lmp.pcap
get "$TCPD/nflog.pcap"                   tcpd-nflog.pcap

# Drop 404 HTML bodies.
for f in *; do
  case "$(file -b "$f")" in
    *HTML*|*ASCII\ text*|*JSON*|*empty*) echo "discarding non-capture: $f"; rm -f "$f" ;;
  esac
done
ls -la
