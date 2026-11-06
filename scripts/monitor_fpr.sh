#!/usr/bin/env bash
# Monitor de fpr: uma vez por dia, por ~5 dias, envia ao ntfy o fpr (benigno)
# do candidato mais recente do estagio 1 e o veredito do portao. Ao fim dos
# 5 dias manda um aviso e REMOVE o proprio cron (auto-encerra).
#
# Instalacao (no servidor do IDS):
#   crontab -l 2>/dev/null | { cat; echo "0 16 * * * /root/TCC/scripts/monitor_fpr.sh"; } | crontab -
# Remover antes do fim:
#   crontab -l | grep -v monitor_fpr.sh | crontab -   (e rm /root/TCC/.monitor_fpr.estado)
#
# ntfy: variavel NTFY_URL (padrao abaixo). Dias: variavel MONITOR_DIAS.
# cron roda com PATH minimo -- por isso o PATH explicito e o docker-compose por caminho.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -uo pipefail

NTFY="${NTFY_URL:-http://192.168.60.14/geral}"
DIAS="${MONITOR_DIAS:-5}"
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ESTADO="$RAIZ/.monitor_fpr.estado"   # guarda a data final
LOG="$RAIZ/.monitor_fpr.log"
cd "$RAIZ"

DC="docker compose"; $DC version >/dev/null 2>&1 || DC="docker-compose"

# primeira execucao define o fim (hoje + DIAS)
[[ -f "$ESTADO" ]] || date -d "+${DIAS} days" +%Y-%m-%d > "$ESTADO"
FIM="$(cat "$ESTADO" 2>/dev/null)"
HOJE="$(date +%Y-%m-%d)"

# fpr benigno + veredito do portao do candidato estagio 1 mais recente
SQL="SELECT to_char(m.trained_at,'YYYY-MM-DD'),
            substr(m.model_id::text,1,8),
            round(e.taxa_falso_positivo::numeric,4),
            coalesce((SELECT CASE WHEN aprovado THEN 'APROVADO' ELSE 'REPROVADO' END
                      FROM na.v_gate_verdict WHERE candidate_model_id = m.model_id),'-')
     FROM na.models m
     JOIN na.model_evaluations e
       ON e.model_id = m.model_id AND e.scope='scenario' AND e.scenario='benigno'
     WHERE m.stage=1 AND m.kind='isolation_forest' AND m.status='candidate'
     ORDER BY m.trained_at DESC LIMIT 1"
LINHA="$($DC exec -T banco psql -U netanomaly -d netanomaly -tAF'|' -c "$SQL" 2>>"$LOG" | head -1)"

if [[ -z "$LINHA" ]]; then
    MSG="Sem candidato estagio 1 recente para medir o fpr."
    TITULO="IDS estagio 1 - SEM DADO"
    TAG="warning"
else
    IFS='|' read -r dia id fpr veredito <<< "$LINHA"
    MSG="Status: ${veredito}  |  fpr benigno=${fpr} (teto 0.02)  |  candidato ${id} de ${dia}"
    TITULO="IDS estagio 1 - ${veredito}"
    case "$veredito" in
        APROVADO)  TAG="white_check_mark";;
        REPROVADO) TAG="x";;
        *)         TAG="information_source";;
    esac
fi

if curl -s -m 15 -H "Title: ${TITULO}" -H "Tags: ${TAG}" -d "$MSG" "$NTFY" >/dev/null; then
    echo "$(date -Is) enviado: $MSG" >>"$LOG"
else
    echo "$(date -Is) FALHA ao enviar ao ntfy: $MSG" >>"$LOG"
fi

# chegou/passou do fim: avisa e auto-encerra (remove o cron e o estado)
if [[ "$HOJE" > "$FIM" || "$HOJE" == "$FIM" ]]; then
    curl -s -m 15 -H "Title: IDS fpr" -d "Monitoramento de ${DIAS} dias encerrado." "$NTFY" >/dev/null || true
    crontab -l 2>/dev/null | grep -v 'monitor_fpr.sh' | crontab - 2>/dev/null || true
    rm -f "$ESTADO"
    echo "$(date -Is) monitor encerrado (fim=$FIM)" >>"$LOG"
fi
