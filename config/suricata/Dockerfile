FROM jasonish/suricata:7.0

# iptables is needed to redirect traffic through Suricata's NFQUEUE when
# running in inline IPS mode (see entrypoint.sh). Not needed for plain IDS
# mode, but harmless to have installed either way.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
