#!/usr/bin/env bash
# Demonstracao: sobe um atacante e uma vitima em containers temporarios, roda
# uma varredura nmap, e verifica se o pipeline ALERTA.
#
#   ./scripts/demo_ataque.sh          nmap SYN scan (padrao)
#   ./scripts/demo_ataque.sh --limpar so derruba os recursos da demo
#
# POR QUE UM DETECTOR PROPRIO PARA A DEMO
# ---------------------------------------
# O detector de producao captura em CAPTURA_IFACE (no seu caso eth0, que esta
# DOWN). Dois containers conversam pela BRIDGE do Docker, nao pela eth0 -- entao
# o detector de producao nao veria este ataque. A demo sobe um detector
# descartavel capturando na bridge dedicada, usando o MESMO modelo promovido, o
# MESMO banco e o MESMO codigo de sink. Os alertas sao reais, gravados em
# na.alerts com sensor='demo-ataque'. Nada da sua config de producao e tocado.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REDE=netanomaly-demo
SENSOR=demo-ataque
IMG=netanomaly:dev

# --- le o .env do projeto ---------------------------------------------------
set -a; . "$RAIZ/.env" 2>/dev/null || true; set +a
SENHA="${SENHA_BANCO:?defina SENHA_BANCO no .env}"
PORTA="${PORTA_BANCO:-5432}"
POOL="$(cd "$RAIZ/${POOL_HOST:-./dados}" && pwd)"
DSN="postgresql://netanomaly:${SENHA}@127.0.0.1:${PORTA}/netanomaly"
PSQL=(docker compose -f "$RAIZ/docker-compose.yml" exec -T banco psql -U netanomaly -d netanomaly -tAc)

derrubar() {
    docker rm -f demo-detector demo-atacante demo-vitima >/dev/null 2>&1
    docker network rm "$REDE" >/dev/null 2>&1
}
trap derrubar EXIT

if [[ "${1:-}" == "--limpar" ]]; then derrubar; trap - EXIT; echo "[+] limpo"; exit 0; fi

# --- pre-checagens ----------------------------------------------------------
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "[!] imagem $IMG nao existe: docker compose build" >&2; exit 1; }
PROM=$("${PSQL[@]}" "SELECT count(*) FROM na.models WHERE status='promoted' AND visao='flow'" 2>/dev/null || echo 0)
[[ "$PROM" == "1" ]] || { echo "[!] nao ha modelo 'flow' promovido -- promova um antes (lifecycle.py promote)" >&2; exit 1; }

echo "== 1. rede e vitima =="
derrubar
docker network create "$REDE" >/dev/null
BR="br-$(docker network inspect "$REDE" --format '{{.Id}}' | cut -c1-12)"
echo "   rede $REDE -> interface $BR"
# vitima: alguns servicos abertos, so para a varredura ter o que encontrar.
docker run -d --rm --name demo-vitima --network "$REDE" alpine \
    sh -c 'for p in 22 80 443 3306; do (while true; do echo srv | nc -lp $p; done &); done; sleep 3600' >/dev/null
sleep 1

echo "== 2. detector descartavel na bridge da demo =="
# --user: as file-capabilities do tcpdump so valem para processo nao-root.
# Como root, o tcpdump tenta largar privilegio e precisa de SETUID/SETGID (que
# nao concedemos) -- e morre. Mesma razao pela qual o compose roda com user.
docker run -d --rm --name demo-detector --network host \
    --user "${UID_APP:-1000}:${GID_APP:-1000}" \
    --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
    -e NETANOMALY_DSN="$DSN" -e NETANOMALY_POOL=/var/lib/netanomaly \
    -v "$POOL":/var/lib/netanomaly \
    --entrypoint /usr/local/bin/entrypoint-detector \
    "$IMG" python3 netanomaly_live.py \
        --iface="$BR" \
        --model=/var/lib/netanomaly/models/current_flow.joblib \
        --view=flow --window=5 --sink --sensor="$SENSOR" >/dev/null
echo -n "   aguardando o detector capturar"
for i in $(seq 1 30); do
    docker logs demo-detector 2>&1 | grep -q "capturando" && { echo " ok"; break; }
    echo -n "."; sleep 1
done
docker logs demo-detector 2>&1 | grep -qE "\[!\]|Traceback" && { echo; echo "[!] detector falhou:"; docker logs demo-detector 2>&1 | tail -8; exit 1; }

ANTES=$("${PSQL[@]}" "SELECT count(*) FROM na.alerts WHERE sensor='$SENSOR'" 2>/dev/null || echo 0)

echo "== 3. ATAQUE: varredura nmap SYN =="
# -sS usa a capacidade NET_RAW que o Docker da por padrao. As duas passadas,
# com folga entre elas, garantem que varias janelas de analise (5s) fechem --
# a janela so fecha quando chega pacote APOS o limite dela.
docker run --rm --name demo-atacante --network "$REDE" alpine sh -c '
    apk add -q nmap 2>/dev/null
    ( for i in $(seq 1 30); do nc -zw1 demo-vitima 22 >/dev/null 2>&1; sleep 1; done ) &
    echo "   [nmap] varredura 1/2 (portas 1-1000)"; nmap -sS -T4 -p1-1000 demo-vitima >/dev/null 2>&1
    sleep 7
    echo "   [nmap] varredura 2/2 (portas 1-1000)"; nmap -sS -T4 -p1-1000 demo-vitima >/dev/null 2>&1
    sleep 7
    wait
' 2>&1 | grep nmap

echo "== 4. o detector alertou? =="
sleep 3
docker logs demo-detector 2>&1 | grep -E "ALERTA|anomalia" | tail -6 | sed 's/^/   /'
echo
DEPOIS=$("${PSQL[@]}" "SELECT count(*) FROM na.alerts WHERE sensor='$SENSOR'")
echo "   alertas gravados no banco: $((DEPOIS - ANTES)) novos (sensor=$SENSOR)"
"${PSQL[@]}" "
  SELECT '   '||host(src_ip)||' -> '||host(dst_ip)||':'||coalesce(dst_port::text,'?')
       ||'  score='||round(score::numeric,3)||'  pct='||round(percentile::numeric,4)
       ||'  ['||coalesce(surrogate_rule,'')||']'
  FROM na.alerts WHERE sensor='$SENSOR'
  ORDER BY percentile DESC LIMIT 8" 2>/dev/null

echo
if [[ "$DEPOIS" -gt "$ANTES" ]]; then
    echo "== RESULTADO: ataque DETECTADO e alertado =="
else
    echo "== RESULTADO: nenhum alerta. O modelo pode nao reconhecer este padrao,"
    echo "   ou as janelas nao fecharam. Veja: docker logs demo-detector =="
fi
echo "(recursos da demo serao derrubados ao sair)"
