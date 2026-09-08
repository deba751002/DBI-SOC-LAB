FROM python:3.11-slim

LABEL maintainer="SOC-Lab"
LABEL description="CrewAI SOC agents: Threat Analyst, Incident Responder, Threat Hunter, Detection Engineer"

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Package install
RUN pip install --no-cache-dir -e . 2>/dev/null || true

ENV CREWAI_API_PORT=8500

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:${CREWAI_API_PORT}/health || exit 1

EXPOSE 8500

# Default: run the API server
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${CREWAI_API_PORT} --reload"]
