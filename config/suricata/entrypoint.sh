#!/bin/sh
# Suricata entrypoint — switches between passive IDS (default) and inline
# IPS mode based on SURICATA_IPS_MODE. IPS mode is opt-in: set
# SURICATA_IPS_MODE=true in .env only after you understand the trade-off
# below.
set -e

IPS_MODE="${SURICATA_IPS_MODE:-false}"
IFACE="${SURICATA_INTERFACE:-eth0}"

if [ "$IPS_MODE" = "true" ]; then
    echo "[entrypoint] IPS mode enabled — redirecting traffic through NFQUEUE 0"
    echo "[entrypoint] --queue-bypass is set: if Suricata stops, traffic fails OPEN (passes"
    echo "[entrypoint] through unfiltered) rather than blocking all network traffic."

    # Route forwarded, inbound, and outbound traffic on this host through
    # Suricata's queue. --queue-bypass means a crashed/overloaded Suricata
    # does not become a total network outage — it just stops filtering.
    iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
    iptables -I INPUT   -j NFQUEUE --queue-num 0 --queue-bypass
    iptables -I OUTPUT  -j NFQUEUE --queue-num 0 --queue-bypass

    exec suricata -q 0 -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid
else
    echo "[entrypoint] IDS mode (passive, alert-only) on interface $IFACE"
    exec suricata -i "$IFACE" -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid
fi
