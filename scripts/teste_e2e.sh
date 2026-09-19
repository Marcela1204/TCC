#!/usr/bin/env bash
# Teste de ponta a ponta do pipeline, com os pcaps do CIC-IDS-2017.
#
#   ./scripts/teste_e2e.sh            roda tudo
#   ./scripts/teste_e2e.sh --limpar   apaga as fatias e derruba o banco
#
# O que ele faz, na ordem:
#   1. fatia bootstrap (terca), golden (janela do FTP-Patator) e "atual" (quarta)
#   2. sobe Postgres+TimescaleDB e aplica o schema
#   3. extract  -> pool de treino a partir do bootstrap
#   4. golden   -> rotula a fatia de ataque pelo cronograma oficial do CIC
#   5. candidate-> treina e mede contra o golden set
#   6. promote  -> com --force, porque o portao REPROVA de verdade (ver nota)
#   7. live     -> reproduz o trafego "atual" com o sink ligado
#   8. verifica o que foi parar no banco e no disco
#
# NOTA SOBRE O PASSO 6: o portao reprova porque o Isolation Forest por fluxo
# tem recall 0.00 no FTP-Patator -- um ataque homogeneo e volumoso e, por
# construcao, normal para um metodo baseado em isolamento. A reprovacao esta
# CERTA. O --force existe aqui so para o teste do sink poder seguir.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRAB="${NETANOMALY_TESTE:-${TMPDIR:-/tmp}/netanomaly-teste}"
PY="$RAIZ/.venv/bin/python3"
DS="$RAIZ/datasets/CIC-IDS-2017"
TERCA="$DS/Tuesday-WorkingHours.pcap"
QUARTA="$DS/Wednesday-workingHours.pcap"

export NETANOMALY_DSN="postgresql://postgres:teste@127.0.0.1:55432/netanomaly"
export NETANOMALY_POOL="$TRAB/pool"
export PGPASSWORD=teste
PSQL=(psql -h 127.0.0.1 -p 55432 -U postgres -d netanomaly)

titulo() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

if [[ "${1:-}" == "--limpar" ]]; then
    "$RAIZ/scripts/banco_dev.sh" down || true
    rm -rf "$TRAB"; echo "[+] limpo"; exit 0
fi

# ---------------------------------------------------------------- verificacoes
for f in "$TERCA" "$QUARTA"; do
    [[ -f "$f" ]] || { echo "[!] falta $f" >&2; exit 1; }
done
[[ -x "$PY" ]] || { echo "[!] falta o venv em $PY" >&2; exit 1; }
command -v editcap >/dev/null || { echo "[!] instale wireshark-common (editcap)" >&2; exit 1; }
mkdir -p "$TRAB/pcaps" "$NETANOMALY_POOL"

# ------------------------------------------------------------------ 1. fatias
titulo "1. fatiando os pcaps"
# Bootstrap: primeiros pacotes da terca. Sao ~40 min de trafego, quase todo
# benigno -- o FTP-Patator so comeca as 12:20 UTC.
if [[ ! -f "$TRAB/pcaps/bootstrap.pcap" ]]; then
    tcpdump -r "$TERCA" -w "$TRAB/pcaps/bootstrap.pcap" -c 1200000 2>/dev/null
fi
# Golden: a janela do FTP-Patator. editcap le -A/-B em hora LOCAL, dai o TZ=UTC.
# 09:20-10:20 local do CIC = 12:20-13:20 UTC; 30 min ja dao fluxos de sobra.
if [[ ! -f "$TRAB/pcaps/golden.pcap" ]]; then
    TZ=UTC editcap -A "2017-07-04 12:20:00" -B "2017-07-04 12:50:00" \
        "$TERCA" "$TRAB/pcaps/golden.pcap"
fi
# "Trafego atual": quarta, fazendo o papel da captura ao vivo.
if [[ ! -f "$TRAB/pcaps/atual.pcap" ]]; then
    tcpdump -r "$QUARTA" -w "$TRAB/pcaps/atual.pcap" -c 400000 2>/dev/null
fi
du -h "$TRAB"/pcaps/*.pcap

# ------------------------------------------------------------------- 2. banco
titulo "2. banco"
"$RAIZ/scripts/banco_dev.sh" up | tail -1

# ----------------------------------------------------------------- 3. extract
titulo "3. extract: bootstrap -> pool de treino"
"$PY" "$RAIZ/lifecycle.py" extract --pcap "$TRAB/pcaps/bootstrap.pcap" \
    --sensor cic-lan --view flow

# ------------------------------------------------------------------ 4. golden
titulo "4. golden: rotulando pelo cronograma oficial do CIC"
"$PY" "$RAIZ/lifecycle.py" golden --pcap "$TRAB/pcaps/golden.pcap" \
    --view flow --cicids --scenario brute_force --capture-id ftp-patator \
    --ferramenta "FTP-Patator"
# Sem captura para os demais cenarios, eles nao podem barrar o portao.
"${PSQL[@]}" -q -c "UPDATE na.golden_scenarios SET obrigatorio=false
                    WHERE scenario NOT IN ('brute_force','benigno');"
"$PY" "$RAIZ/lifecycle.py" golden-list

# --------------------------------------------------------------- 5. candidate
titulo "5. pool e candidato"
"$PY" "$RAIZ/lifecycle.py" pool --view flow
# contamination 0.01, nao o padrao 0.03: gate_max_fpr esta em 0.02, e num pool
# limpo o falso positivo tende ao valor de contamination.
"$PY" "$RAIZ/lifecycle.py" candidate --view flow --contamination 0.01

# ---------------------------------------------------------------- 6. promote
titulo "6. promocao (sobrepondo o portao -- ver nota no topo)"
MID=$("${PSQL[@]}" -tAc "SELECT model_id FROM na.models
                         WHERE status='candidate' ORDER BY trained_at DESC LIMIT 1")
"$PY" "$RAIZ/lifecycle.py" promote --model "$MID" --by "${USER:-teste}" --force \
    --reason "teste e2e; portao reprovou por recall 0 em brute_force" | tail -3

# ------------------------------------------------------------- 7. live + sink
titulo "7. trafego 'atual' com o sink ligado"
"$PY" "$RAIZ/netanomaly_live.py" --pcap "$TRAB/pcaps/atual.pcap" \
    --model "$NETANOMALY_POOL/models/current_flow.joblib" \
    --sink --sensor cic-lan --window 10 2>&1 | grep -E "^\[(sink|pool|\+)" | tail -8

# --------------------------------------------------------------- 8. verificar
titulo "8. o que ficou no banco"
"${PSQL[@]}" -c "
SELECT extractor, count(*) AS janelas, sum(n_rows) AS fluxos
  FROM na.feature_windows GROUP BY extractor ORDER BY 1;
SELECT count(*) AS alertas,
       min(percentile)::numeric(6,4) AS pct_min,
       max(percentile)::numeric(6,4) AS pct_max FROM na.alerts;
SELECT count(*) AS acima_do_corte FROM na.v_alertas_correntes;"

titulo "9. o dataset novo ja entrou no pool de retreino"
"$PY" "$RAIZ/lifecycle.py" pool --view flow

echo
echo "Banco de pe em $NETANOMALY_DSN"
echo "  ./scripts/banco_dev.sh psql     para explorar"
echo "  ./scripts/teste_e2e.sh --limpar para derrubar e apagar as fatias"
