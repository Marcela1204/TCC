#!/usr/bin/env bash
# Prepara um deploy do zero: treina os modelos e sobe os containers.
#
#   ./scripts/preparar.sh --treino CAP.pcap [opcoes]
#
# Faz, na ordem, TUDO por dentro de containers (nao precisa de venv no host):
#   1. sobe o banco e aplica as migracoes
#   2. ESTAGIO 1: treina um Isolation Forest no seu pcap e o ADOTA como inicial
#   3. (opcional) registra uma captura de ataque no golden set
#   4. ESTAGIO 2: treina o SVM (bootstrap pelo golden) e o promove
#   5. sobe o restante dos containers (detector, grafana...) ja com modelo
#
# Os pcaps ja devem estar em PCAP_HOST (montado como /pcaps). Passe o caminho
# RELATIVO a esse diretorio -- so o nome do arquivo, ou um subcaminho. Aceita
# tambem com o prefixo /pcaps/ ou ./pcaps/, que e removido.
#
# Opcoes:
#   --treino  PCAP   captura de trafego NORMAL, dentro de /pcaps (obrigatorio)
#   --ataque  PCAP   captura com ataque, dentro de /pcaps (opcional, recomendado)
#   --cenario NOME   cenario do golden p/ --ataque (padrao: recon)
#   --cicids         rotula --ataque pelo cronograma oficial do CIC-IDS-2017
#   --sensor  NOME   nome do sensor (padrao: do .env ou sensor-01)
#   --contamination  fracao de anomalia no treino do estagio 1 (padrao 0.01)
#   --pular-subir    faz o treino mas NAO sobe os containers no fim
#
# Requer .env preparado (cp .env.example .env) e a imagem construida.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

TREINO="" ATAQUE="" CENARIO="recon" CICIDS="" CONT="0.01" PULAR_SUBIR=""
SENSOR_CLI=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --treino) TREINO="$2"; shift 2;;
        --ataque) ATAQUE="$2"; shift 2;;
        --cenario) CENARIO="$2"; shift 2;;
        --cicids) CICIDS=1; shift;;
        --sensor) SENSOR_CLI="$2"; shift 2;;
        --contamination) CONT="$2"; shift 2;;
        --pular-subir) PULAR_SUBIR=1; shift;;
        *) echo "[!] opcao desconhecida: $1" >&2; exit 2;;
    esac
done

[[ -f .env ]]      || { echo "[!] falta .env (cp .env.example .env e ajuste)" >&2; exit 1; }
[[ -n "$TREINO" ]] || { echo "[!] --treino e obrigatorio" >&2; exit 1; }
docker image inspect netanomaly:dev >/dev/null 2>&1 || { echo "[!] imagem nao construida: docker compose build" >&2; exit 1; }

set -a; . ./.env; set +a
SENSOR="${SENSOR_CLI:-${NOME_SENSOR:-sensor-01}}"
PCAP_DIR="${PCAP_HOST:-./pcaps}"
DC="docker compose"
RUN="$DC run --rm --entrypoint python3 treinador"

titulo() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# Normaliza um caminho para ser relativo a /pcaps: tira prefixo /pcaps/,
# ./pcaps/ ou $PCAP_DIR/, e confirma que o arquivo existe no host (em PCAP_DIR).
# Ecoa o caminho DENTRO do container (/pcaps/...).
resolver_pcap() {
    local rel="$1"
    rel="${rel#/pcaps/}"; rel="${rel#./pcaps/}"; rel="${rel#pcaps/}"
    rel="${rel#"$PCAP_DIR"/}"
    if [[ ! -f "$PCAP_DIR/$rel" ]]; then
        echo "[!] pcap nao encontrado em $PCAP_DIR/$rel" >&2
        echo "    (passe o caminho RELATIVO a $PCAP_DIR, ex.: --treino dia.pcap)" >&2
        echo "    disponiveis:" >&2
        ls -1 "$PCAP_DIR"/*.pcap 2>/dev/null | sed "s|^$PCAP_DIR/|      |" >&2             || echo "      (nenhum .pcap em $PCAP_DIR)" >&2
        return 1
    fi
    echo "/pcaps/$rel"
}

# `|| exit`: resolver_pcap sinaliza erro com return no subshell; o chamador
# encerra o script aqui (mais seguro que depender de set -e em fim de lista &&).
TREINO_C="$(resolver_pcap "$TREINO")" || exit 1
ATAQUE_C=""
[[ -n "$ATAQUE" ]] && { ATAQUE_C="$(resolver_pcap "$ATAQUE")" || exit 1; }

titulo "1. banco + migracoes"
$DC up -d banco
echo -n "   aguardando o banco"
pronto=""
for _ in $(seq 1 60); do
    if $DC exec -T banco pg_isready -U netanomaly -d netanomaly >/dev/null 2>&1; then
        pronto=1; echo " ok"; break
    fi
    echo -n "."; sleep 1
done
[[ -n "$pronto" ]] || { echo; echo "[!] o banco nao ficou pronto em 60s. Veja: docker compose logs banco" >&2; exit 1; }
$RUN /usr/local/bin/migrar /app/migrations

if [[ -n "$ATAQUE" ]]; then
    titulo "2. golden set: registrar a captura de ataque"
    if [[ -n "$CICIDS" ]]; then
        $RUN lifecycle.py golden --pcap "$ATAQUE_C" --cicids --scenario "$CENARIO"
    else
        $RUN lifecycle.py golden --pcap "$ATAQUE_C" --scenario "$CENARIO" --label 1
    fi
else
    echo
    echo "[i] sem --ataque: golden set fica so com o que ja houver. O estagio 2"
    echo "    ainda treina, mas sem ataque rotulado o portao nao mede detecao."
fi

titulo "3. estagio 1: treinar Isolation Forest e adotar (mede no golden)"
# treina no pcap e salva no POOL (rw). /pcaps e somente leitura, nao serve p/ salvar.
$RUN netanomaly.py "$TREINO_C" --nfstream --contamination "$CONT" \
    --save-model /var/lib/netanomaly/bootstrap
$RUN lifecycle.py adopt --model /var/lib/netanomaly/bootstrap_flow.joblib \
    --pcap "$TREINO_C" --sensor "$SENSOR" --by preparar

titulo "4. estagio 2: treinar o SVM e promover"
if $RUN netclassify.py train --view flow 2>/tmp/nc_train.log; then
    MID=$($DC exec -T banco psql -U netanomaly -d netanomaly -tAc \
        "SELECT model_id FROM na.models WHERE stage=2 AND status='candidate' ORDER BY trained_at DESC LIMIT 1")
    $RUN netclassify.py promote --model "$MID" --by preparar
else
    echo "[!] estagio 2 nao treinou (sem rotulo suficiente?). Detalhe:" >&2
    tail -3 /tmp/nc_train.log >&2
    echo "[i] o sistema sobe mesmo assim; o estagio 1 funciona sozinho." >&2
fi

if [[ -n "$PULAR_SUBIR" ]]; then
    titulo "pronto (--pular-subir: NAO subi os containers)"
    echo "   para subir:  docker compose up -d"
    exit 0
fi

titulo "5. subir os containers"
$DC up -d
echo
echo "[+] pronto. Estagio 1 adotado, estagio 2 promovido (se houve rotulo)."
echo "    O treinador ja roda o predict do estagio 2 a cada ciclo."
echo "    Grafana: dashboards 'visao geral' e 'estagio 2'."
echo "    Confira:  docker compose ps"
