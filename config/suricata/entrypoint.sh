#!/bin/sh
# Suricata entrypoint — switches between passive IDS (default) and inline
# IPS mode based on SURICATA_IPS_MODE. IPS mode is opt-in: set
# SURICATA_IPS_MODE=true in .env only after you understand the trade-off
# below.
set -e

IPS_MODE="${SURICATA_IPS_MODE:-false}"
IFACE="${SURICATA_INTERFACE:-eth0}"

# suricata.yaml is mounted read-only and Suricata does not expand ${VARS}
# itself - the ${SURICATA_HOME_NET} placeholder in it is only ever resolved
# by docker-compose in command:/environment: fields, never inside a mounted
# file, so it reached Suricata as a literal, unparseable string. Render it
# into a writable copy here instead.
CONFIG_SRC="/etc/suricata/suricata.yaml"
CONFIG_RENDERED="/tmp/suricata-rendered.yaml"
SURICATA_HOME_NET="${SURICATA_HOME_NET:-[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]}" \
    envsubst '${SURICATA_HOME_NET}' < "$CONFIG_SRC" > "$CONFIG_RENDERED"

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

    exec suricata -q 0 -c "$CONFIG_RENDERED" --pidfile /var/run/suricata.pid
else
    echo "[entrypoint] IDS mode (passive, alert-only) on interface $IFACE"
    exec suricata -i "$IFACE" -c "$CONFIG_RENDERED" --pidfile /var/run/suricata.pid
fi
