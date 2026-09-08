#!/usr/bin/env bash
# Postgres + TimescaleDB de desenvolvimento, em container. Nao precisa de sudo.
#
#   ./scripts/banco_dev.sh up      sobe e aplica migrations/001_init.sql
#   ./scripts/banco_dev.sh psql    abre um psql no banco
#   ./scripts/banco_dev.sh reset   derruba, sobe de novo e reaplica o schema
#   ./scripts/banco_dev.sh down    derruba
#
# DSN:  postgresql://postgres:teste@127.0.0.1:55432/netanomaly
set -euo pipefail

NOME=netanomaly-dev
PORTA=55432
IMAGEM=timescale/timescaledb:latest-pg17
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PGPASSWORD=teste
PSQL=(psql -h 127.0.0.1 -p "$PORTA" -U postgres -d netanomaly)

subir() {
    docker rm -f "$NOME" >/dev/null 2>&1 || true
    docker run -d --name "$NOME" \
        -e POSTGRES_PASSWORD=teste -e POSTGRES_DB=netanomaly \
        -p "$PORTA":5432 "$IMAGEM" >/dev/null
    # Espera pela PORTA EXTERNA, nao por pg_isready dentro do container: o
    # entrypoint sobe um servidor temporario para inicializar e depois o
    # derruba, entao pg_isready responde antes de o banco estar de pe.
    echo -n "aguardando o banco"
    for _ in $(seq 1 60); do
        if "${PSQL[@]}" -tAc "select 1" >/dev/null 2>&1; then echo " ok"; return; fi
        echo -n "."; sleep 1
    done
    echo; echo "[!] o banco nao subiu; veja: docker logs $NOME" >&2; exit 1
}

case "${1:-up}" in
    up|reset)
        subir
        "${PSQL[@]}" -q -v ON_ERROR_STOP=1 --single-transaction -f "$RAIZ/migrations/001_init.sql"
        echo "[+] schema aplicado em postgresql://postgres:teste@127.0.0.1:$PORTA/netanomaly"
        echo "    export NETANOMALY_DSN=postgresql://postgres:teste@127.0.0.1:$PORTA/netanomaly"
        ;;
    psql)  exec "${PSQL[@]}" ;;
    down)  docker rm -f "$NOME" >/dev/null 2>&1 && echo "[+] derrubado" ;;
    *)     echo "uso: $0 {up|reset|psql|down}" >&2; exit 2 ;;
esac
