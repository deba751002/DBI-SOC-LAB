FROM jasonish/suricata:7.0

# jasonish/suricata is AlmaLinux-based (not Debian/Ubuntu) - dnf, not apt-get.
# iptables is needed to redirect traffic through Suricata's NFQUEUE when
# running in inline IPS mode (see entrypoint.sh). Not needed for plain IDS
# mode, but harmless to have installed either way. gettext provides envsubst,
# used to render ${SURICATA_HOME_NET} into suricata.yaml at container start.
RUN dnf install -y iptables gettext && \
    dnf clean all

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
