# Harbor — Private Container Registry

Secures the supply-chain gap none of this lab's other tools cover: images are
currently pulled straight from Docker Hub or built locally with no central,
access-controlled, pre-scanned place to store them. Harbor is that registry —
and it bundles Trivy natively, so every image pushed here is scanned
automatically.

## Why this isn't in the main `docker-compose.yml`

Harbor ships its own official offline installer that **generates its own
`docker-compose.yml`** (8+ interconnected services: core, portal, registry,
jobservice, redis, trivy-adapter, its own Postgres, nginx-proxy) from a single
`harbor.yml` config file. Hand-writing that generated compose file here would
drift from whatever Harbor version you actually install, and defeats the
point of using the official installer at all. `harbor.yml.example` in this
folder is the *input* config — Harbor's `install.sh` produces the real
compose file from it.

## Install

```bash
# On the Docker host, outside this repo
wget https://github.com/goharbor/harbor/releases/download/v2.11.1/harbor-offline-installer-v2.11.1.tgz
tar xzvf harbor-offline-installer-v2.11.1.tgz
cd harbor
cp /path/to/this/repo/config/harbor/harbor.yml.example harbor.yml
# Edit harbor.yml: hostname, harbor_admin_password, database.password
./install.sh --with-trivy
```

## Firewall / port impact

Exposes `http.port` from `harbor.yml` (8030 in the example) for the web
console and `docker login`/`docker push`/`docker pull`. Scope this to the
lab network only — it holds every image this stack's own build pipeline
produces.

## Using it with this lab's images

```bash
docker login harbor.soc.lab:8030
docker tag soc-lab/ai-agents:latest harbor.soc.lab:8030/soc-lab/ai-agents:latest
docker push harbor.soc.lab:8030/soc-lab/ai-agents:latest
# Harbor scans it automatically on push - view results in the web console
```

Then point `docker-compose.yml`'s `crewai-soc` (and any other custom-built
service) at the Harbor-hosted tag instead of building locally, once this is
running.
