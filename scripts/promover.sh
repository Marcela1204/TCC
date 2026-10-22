#!/usr/bin/env bash
# Promove um modelo pelo fluxo guiado: LISTA -> ESCOLHE -> (ve o portao) ->
# PROMOVE. Substitui o "abrir o banco na mao". Nao decide por voce: so encadeia
# os tres comandos do lifecycle e pede confirmacao antes da promocao.
#
#   ./scripts/promover.sh [--stage 1|2] [--by NOME] [--model UUID]
#                         [--limite N] [--force --reason "..."]
#
#   --stage N     filtra a listagem por estagio (padrao: ambos)
#   --by NOME     quem esta promovendo (padrao: $USER, ou pergunta)
#   --model UUID  pula a listagem/pergunta e vai direto neste modelo
#   --limite N    quantos modelos listar (padrao: 10)
#   --force       promove mesmo com o portao REPROVADO (exige --reason)
#   --reason TXT  justificativa registrada para o --force
#
# O proprio `promote` re-checa o portao: candidato reprovado e barrado a menos
# que --force --reason. Requer .env e a imagem construida (docker compose build).
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

STAGE="" BY="${USER:-}" MID="" LIMITE="10" FORCE="" REASON=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stage)  STAGE="$2"; shift 2;;
        --by)     BY="$2"; shift 2;;
        --model)  MID="$2"; shift 2;;
        --limite) LIMITE="$2"; shift 2;;
        --force)  FORCE=1; shift;;
        --reason) REASON="$2"; shift 2;;
        *) echo "[!] opcao desconhecida: $1" >&2; exit 2;;
    esac
done

[[ -f .env ]] || { echo "[!] falta .env (cp .env.example .env e ajuste)" >&2; exit 1; }
docker image inspect netanomaly:dev >/dev/null 2>&1 \
    || { echo "[!] imagem nao construida: docker compose build" >&2; exit 1; }
[[ -n "$FORCE" && -z "$REASON" ]] \
    && { echo "[!] --force exige --reason \"...\"" >&2; exit 1; }

# auto-detecta o compose (plugin novo ou docker-compose v1), igual ao preparar.sh
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else echo "[!] nem 'docker compose' nem 'docker-compose' encontrado" >&2; exit 1; fi
RUN="$DC run --rm --entrypoint python3 treinador"

echo "[i] subindo o banco..."
$DC up -d banco >/dev/null 2>&1 || true

# 1. LISTAR (pula se o modelo ja veio por --model)
if [[ -z "$MID" ]]; then
    echo
    $RUN lifecycle.py models ${STAGE:+--stage "$STAGE"} --limite "$LIMITE"
    echo
    # sem tty nao da para perguntar o id: exija --model
    [[ -t 0 ]] || { echo "[!] sem terminal interativo: passe --model UUID" >&2; exit 1; }
    read -r -p "model_id para promover (vazio = cancelar): " MID
    [[ -n "$MID" ]] || { echo "[i] cancelado."; exit 0; }
fi

# quem promove
if [[ -z "$BY" ]]; then
    [[ -t 0 ]] || { echo "[!] informe --by NOME" >&2; exit 1; }
    read -r -p "seu nome (--by): " BY
    [[ -n "$BY" ]] || { echo "[!] --by e obrigatorio" >&2; exit 1; }
fi

# 2. VER O PORTAO do escolhido
echo
echo "== portao de $MID =="
$RUN lifecycle.py gate --model "$MID" || {
    echo "[!] nao consegui ler o portao desse modelo (id errado?)." >&2; exit 1; }

# 3. CONFIRMAR e PROMOVER
echo
if [[ -t 0 ]]; then
    read -r -p "promover este modelo${FORCE:+ COM --force} por '$BY'? [s/N] " ok
    [[ "$ok" =~ ^[sSyY]$ ]] || { echo "[i] cancelado."; exit 0; }
fi

echo
extra=()
[[ -n "$FORCE" ]] && extra=(--force --reason "$REASON")
$RUN lifecycle.py promote --model "$MID" --by "$BY" "${extra[@]}"
