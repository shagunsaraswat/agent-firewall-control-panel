#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.yml"
ENV_FILE="${SCRIPT_DIR}/docker/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/docker/.env.example"

info() { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
ok()   { printf "${GREEN}[OK]${NC}   %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$1" >&2; exit 1; }

# Check prerequisites
command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
docker compose version >/dev/null 2>&1 || fail "Docker Compose V2 is not installed"

# Setup env
if [[ ! -f "${ENV_FILE}" ]]; then
    info "Creating docker/.env from docker/.env.example"
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    ok "Environment file created at docker/.env"
fi

# Start stack
info "Starting Agent FirewallKit development stack..."
docker compose -f "${COMPOSE_FILE}" up --build -d

# Wait for health (four data services: postgres, clickhouse, nats, redis).
# Match healthy only — plain "healthy" matches the substring inside "unhealthy".
info "Waiting for services to become healthy..."
TIMEOUT=120
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT ]]; do
    HEALTHY=$(docker compose -f "${COMPOSE_FILE}" ps --format json 2>/dev/null \
        | grep -E '"Health"\s*:\s*"healthy"' | wc -l | tr -d ' ' || true)
    TOTAL=$(docker compose -f "${COMPOSE_FILE}" ps --format json 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${HEALTHY:-0}" -ge 4 ]]; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    printf "\r  Waiting... (%ds/%ds, %s/%s healthy)" "$ELAPSED" "$TIMEOUT" "${HEALTHY:-0}" "${TOTAL:-0}"
done
echo

if [[ $ELAPSED -ge $TIMEOUT ]]; then
    warn "Some services may not be healthy yet. Check with: docker compose -f docker/docker-compose.yml ps"
else
    ok "All data services healthy"
fi

# Print connection info
echo
printf "${GREEN}═══════════════════════════════════════════════════${NC}\n"
printf "${GREEN}  Agent FirewallKit Development Stack Running${NC}\n"
printf "${GREEN}═══════════════════════════════════════════════════${NC}\n"
echo
printf "  %-20s %s\n" "HTTP API:" "http://localhost:8080"
printf "  %-20s %s\n" "gRPC:" "localhost:50051"
printf "  %-20s %s\n" "Metrics:" "http://localhost:9090/metrics"
printf "  %-20s %s\n" "PostgreSQL:" "localhost:5432"
printf "  %-20s %s\n" "ClickHouse:" "http://localhost:8123"
printf "  %-20s %s\n" "NATS:" "localhost:4222"
printf "  %-20s %s\n" "NATS Monitor:" "http://localhost:8222"
printf "  %-20s %s\n" "Redis:" "localhost:6379"
echo
printf "  Stop:    docker compose -f docker/docker-compose.yml down\n"
printf "  Logs:    docker compose -f docker/docker-compose.yml logs -f\n"
printf "  Status:  docker compose -f docker/docker-compose.yml ps\n"
echo
