#!/usr/bin/env bash
# =============================================================================
# Advanced SOC Lab v2.0 — Security Scan
# Two independent one-shot scans, run via their official Docker images so
# nothing extra needs installing on the host:
#   --docker-bench  Docker Bench Security (CIS Docker Benchmark) against the
#                    running daemon/containers. Complements Lynis, which
#                    audits the host OS, not Docker-specific config.
#   --nuclei        Fast, template-based scan against this lab's own exposed
#                    web services. Complements OpenVAS, which does slow/deep
#                    scans on a weekly-or-slower cadence - Nuclei is meant to
#                    run daily.
# With no flags, both run. Pass one flag to run only that scan.
# =============================================================================
set -euo pipefail

C_RESET='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[0;36m'

RUN_DOCKER_BENCH=true
RUN_NUCLEI=true
if [[ "${1:-}" == "--docker-bench" ]]; then RUN_NUCLEI=false; fi
if [[ "${1:-}" == "--nuclei" ]]; then RUN_DOCKER_BENCH=false; fi

if ! command -v docker &>/dev/null; then
  echo "docker not found on PATH — run this on the machine that hosts the SOC Lab stack." >&2
  exit 1
fi

if $RUN_DOCKER_BENCH; then
  echo -e "${C_CYAN}${C_BOLD}"
  echo "+======================================================+"
  echo "|   DBI SOC — Docker Bench Security                   |"
  echo "|   CIS Docker Benchmark against this host's daemon   |"
  echo "+======================================================+"
  echo -e "${C_RESET}"

  docker run --rm --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST="${DOCKER_CONTENT_TRUST:-0}" \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security

  echo ""
  echo "Full report also written to docker-bench-security's own log output above."
  echo "Re-run after any docker-compose.yml change that touches privileges, mounts, or ports."
fi

if $RUN_NUCLEI; then
  echo -e "${C_CYAN}${C_BOLD}"
  echo "+======================================================+"
  echo "|   DBI SOC — Nuclei                                  |"
  echo "|   Fast template-based scan of this lab's own web UIs|"
  echo "+======================================================+"
  echo -e "${C_RESET}"

  # Only this lab's own exposed services — never point Nuclei at anything
  # outside this network without explicit authorization.
  cat > /tmp/soc-lab-nuclei-targets.txt <<EOF
http://localhost:5601
http://localhost:8443
http://localhost:8080
http://localhost:3000
http://localhost:8180
http://localhost:9000
EOF

  docker run --rm -v /tmp/soc-lab-nuclei-targets.txt:/targets.txt:ro \
    projectdiscovery/nuclei:latest \
    -l /targets.txt -severity low,medium,high,critical -silent

  rm -f /tmp/soc-lab-nuclei-targets.txt
  echo ""
  echo "Nuclei templates auto-update on each run. Schedule this daily (cron) once"
  echo "the stack is actually running - unlike OpenVAS, this is meant to be frequent."
fi
