#!/usr/bin/env bash
# Espera o modelo promovido antes de comecar a capturar.
#
# Numa instancia nova nao existe modelo: ninguem treinou nem promoveu nada
# ainda. Sem esta espera o detector morre com FileNotFoundError e, por causa
# do `restart: unless-stopped`, entra em laco de reinicio cuspindo traceback.
#
# Ele NAO treina sozinho de proposito. Treinar o detector no trafego que por
# acaso estiver passando e exatamente o caminho do envenenamento: se houver
# ataque em curso, o ataque entra no baseline como normal. O modelo tem de
# nascer de uma promocao deliberada, que passa pelo portao.
set -uo pipefail

# Descobre qual artefato esperar a partir do --model= do proprio comando.
MODELO=""
for arg in "$@"; do
    case "$arg" in
        --model=*) MODELO="${arg#--model=}" ;;
    esac
done
if [ -z "$MODELO" ]; then
    echo "[detector] sem --model no comando; seguindo sem esperar" >&2
    exec "$@"
fi

INTERVALO="${DETECTOR_ESPERA:-15}"
tentativa=0

while true; do
    pronto=$(python3 - "$MODELO" <<'PY'
import os, sys
caminho = sys.argv[1]
if not os.path.exists(caminho):
    print("sem-arquivo"); raise SystemExit
try:
    import psycopg
    dsn = os.environ["NETANOMALY_DSN"]
    real = os.path.realpath(caminho)
    with psycopg.connect(dsn, connect_timeout=5) as c:
        r = c.execute("SELECT status FROM na.models WHERE artifact_path = %s",
                      (real,)).fetchone()
except Exception as e:
    print(f"banco-indisponivel:{e.__class__.__name__}"); raise SystemExit
if r is None:
    print("nao-registrado")
elif r[0] != "promoted":
    print(f"status-{r[0]}")
else:
    print("ok")
PY
)
    case "$pronto" in
        ok)
            echo "[detector] modelo pronto: $MODELO"
            exec "$@"
            ;;
        sem-arquivo)
            motivo="o artefato ainda nao existe"
            ;;
        nao-registrado)
            # sink.py exige o registro: e o que faz cada alerta apontar para o
            # modelo que o produziu. Artefato solto nao tem essa identidade.
            motivo="o artefato existe mas nao esta registrado em na.models"
            ;;
        banco-indisponivel:*)
            motivo="banco indisponivel (${pronto#banco-indisponivel:})"
            ;;
        *)
            motivo="modelo existe mas esta em '${pronto#status-}', nao 'promoted'"
            ;;
    esac

    if [ "$tentativa" -eq 0 ]; then
        cat >&2 <<AJUDA
[detector] aguardando modelo promovido -- $motivo
[detector]
[detector]   arquivo esperado: $MODELO
[detector]
[detector] Numa instancia nova isto e esperado. Faca o bootstrap:
[detector]
[detector]   docker compose run --rm --entrypoint python3 treinador \\
[detector]       lifecycle.py extract --pcap /pcaps/dia.pcap --sensor SEU_SENSOR --view flow
[detector]   docker compose run --rm --entrypoint python3 treinador \\
[detector]       lifecycle.py golden --pcap /pcaps/ataque.pcap --cicids --scenario brute_force
[detector]   docker compose run --rm --entrypoint python3 treinador \\
[detector]       lifecycle.py candidate --view flow --contamination 0.01
[detector]   docker compose run --rm --entrypoint python3 treinador \\
[detector]       lifecycle.py promote --model <uuid> --by seu-nome
[detector]
[detector] Assim que houver promocao, comeco a capturar sozinho.
[detector] Reconferindo a cada ${INTERVALO}s (silenciosamente).
AJUDA
    fi
    tentativa=$((tentativa + 1))
    # Um lembrete por hora, para nao encher o log nem sumir de vista.
    if [ $((tentativa % (3600 / INTERVALO) )) -eq 0 ]; then
        echo "[detector] ainda aguardando modelo promovido -- $motivo" >&2
    fi
    sleep "$INTERVALO"
done
