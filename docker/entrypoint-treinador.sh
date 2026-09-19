#!/usr/bin/env bash
# Relogio DIARIO do ciclo de vida: treina candidato e mede. NUNCA promove.
#
# A promocao e deliberadamente manual e fica fora deste laco -- e o portao
# que a barra, e um portao que se auto-aprova nao e portao. Para promover:
#
#   docker compose run --rm treinador lifecycle.py promote --model <uuid> --by nome
set -uo pipefail

INTERVALO="${TREINADOR_INTERVALO:-86400}"
VISOES="${TREINADOR_VISOES:-flow}"
CONT="${TREINADOR_CONTAMINATION:-0.01}"

echo "[treinador] intervalo=${INTERVALO}s visoes='${VISOES}' contamination=${CONT}"

# O bind mount tem de ser ESCRIVEL pelo uid do container. Quando POOL_HOST
# nao existe no host, o Compose cria o diretorio como root:root -- e ai o
# container (uid nao-root) falha depois, num traceback de pandas que nao diz
# nada sobre permissao. Falhar aqui, com o comando do conserto, custa menos.
if ! touch "$NETANOMALY_POOL/.escrivel" 2>/dev/null; then
    echo "[treinador] ERRO: $NETANOMALY_POOL nao e escrivel por uid $(id -u)." >&2
    echo "[treinador] O Compose provavelmente criou POOL_HOST como root." >&2
    echo "[treinador] No host:" >&2
    echo "[treinador]   docker run --rm -v \"\$PWD/dados:/d\" alpine \\" >&2
    echo "[treinador]       chown -R \$(id -u):\$(id -g) /d" >&2
    echo "[treinador] e confira UID_APP/GID_APP no .env." >&2
    exit 1
fi
rm -f "$NETANOMALY_POOL/.escrivel"

# Espera o banco. O healthcheck do compose cobre o caso normal, mas o
# treinador tambem pode subir sozinho.
until python3 -c "
import os,sys,psycopg
try: psycopg.connect(os.environ['NETANOMALY_DSN']).close()
except Exception as e: sys.exit(1)
" 2>/dev/null; do
    echo "[treinador] aguardando o banco..."
    sleep 3
done

# As migracoes NAO sao idempotentes (001_init.sql tem 13 CREATE TABLE sem
# IF NOT EXISTS). Quem garante "aplica uma vez cada" e o migrar.py, via a
# tabela na.schema_migrations.
#
# Falha aqui ABORTA o container de proposito: treinador rodando contra schema
# errado grava dado que depois ninguem sabe interpretar. Melhor nao subir.
echo "[treinador] migracoes"
if ! python3 /usr/local/bin/migrar /app/migrations; then
    echo "[treinador] MIGRACAO FALHOU -- nao treino contra schema incerto" >&2
    exit 1
fi

while true; do
    for v in $VISOES; do
        echo "[treinador] --- $(date -u +%FT%TZ) candidato view=$v ---"
        # Pedido manual do analista tem prioridade: consome a fila primeiro.
        python3 /app/lifecycle.py requests --view "$v" --contamination "$CONT" \
            || echo "[treinador] requests falhou (segue)"
        python3 /app/lifecycle.py candidate --view "$v" --contamination "$CONT" \
            || echo "[treinador] candidate falhou (segue) -- pool vazio ou em quarentena?"

        # ESTAGIO 2: anota os alertas novos com a predicao do SVM promovido.
        # Se nao houver SVM estagio 2 promovido, predict sai avisando e o laco
        # segue -- por isso o `|| echo`. NAO treina nem promove estagio 2 aqui:
        # o treino depende de rotulo (golden/vereditos) e a promocao e manual,
        # mesmo principio do estagio 1.
        python3 /app/netclassify.py predict --view "$v" \
            || echo "[treinador] netclassify predict: sem SVM estagio 2 promovido ainda (ok)"
    done
    echo "[treinador] dormindo ${INTERVALO}s"
    sleep "$INTERVALO"
done
