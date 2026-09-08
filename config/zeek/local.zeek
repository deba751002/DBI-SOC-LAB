# ================================================================
#  Zeek Local Configuration — SOC Lab
#  Network Security Monitoring (Security Onion core engine)
# ================================================================
@load base/frameworks/intel
@load base/frameworks/notice
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/smb
@load base/protocols/krb
# Scan detection (MITRE T1046) was removed from core Zeek entirely - Zeek's
# own shipped local.zeek template now points to the ncsa/bro-simple-scan zkg
# package instead ("zkg install ncsa/bro-simple-scan"), not installed here by
# default. @load detection/scan / policy/misc/scan no longer exist.
@load misc/capture-loss
@load misc/stats
# policy/frameworks/network/ doesn't exist in this Zeek version - there is no
# detect-protocols script at that path (verified against the current script
# tree); dropped rather than guessing at a replacement.

# JSON output for Vector pipeline
@load tuning/json-logs

# MITRE ATT&CK enrichment scripts
@load policy/integration/collective-intel

module SOC;

# Log all connections to OpenSearch via Vector
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1hrs;

# Track C2 beacon intervals (MITRE T1071)
redef HTTP::max_pending_requests = 100;

event zeek_init() {
    print "SOC Lab Zeek NSM started";
}
