-- ============================================================================
-- 006: view consolidada do RESULTADO FINAL do stack (estagio 1 -> estagio 2)
-- ============================================================================
-- Junta, por alerta, as tres camadas de decisao do sistema:
--
--   estagio 1  na.alerts              o detector nao supervisionado (IF/OCSVM)
--                                     marcou a janela como anomala. Traz score,
--                                     percentil e a regra do surrogate (o "por
--                                     que"). E a PENEIRA: recall alto, rap.
--   estagio 2  na.stage2_assignments  o classificador supervisionado (SVM)
--                                     rotulou o alerta em 'ataque'/'benigno'
--                                     com uma margem. E o REFINO: corta o falso
--                                     positivo que o estagio 1 deixa passar.
--   veredito   na.verdicts            rotulo humano/auto corrente, quando existe.
--                                     E a palavra final -- vira rotulo de treino.
--
-- A classificacao final consolidada segue essa precedencia: veredito manda;
-- na ausencia dele vale a predicao do estagio 2; se o estagio 2 ainda nao
-- rodou sobre o alerta, ele fica 'pendente' (so passou pelo estagio 1).
-- ============================================================================

CREATE OR REPLACE VIEW na.v_resultado_final AS
SELECT
    a.alert_id,
    a.ts,
    a.sensor,
    a.visao,
    a.src_ip,
    a.dst_ip,
    a.dst_port,
    a.proto,
    a.score                          AS e1_score,
    a.percentile                     AS e1_percentil,
    a.surrogate_rule                 AS e1_regra,
    a.label_cic,
    s.predicted                      AS e2_predito,
    s.decision_value                 AS e2_decisao,
    s.margin                         AS e2_margem,
    s.state                          AS e2_estado,
    cv.veredito,
    cv.classe                        AS veredito_classe,
    cv.analista,
    -- classificacao final: veredito > predicao do estagio 2 > so estagio 1.
    COALESCE(cv.veredito, s.predicted, 'pendente')   AS classificacao,
    CASE
        WHEN cv.veredito IS NOT NULL THEN 'veredito'
        WHEN s.predicted IS NOT NULL THEN 'estagio2'
        ELSE 'estagio1'
    END                              AS decidido_por
FROM na.alerts a
LEFT JOIN LATERAL (
    -- a classificacao mais recente do estagio 2 para este alerta
    SELECT z.predicted, z.decision_value, z.margin, z.state
    FROM na.stage2_assignments z
    WHERE z.alert_id = a.alert_id
    ORDER BY z.created_at DESC
    LIMIT 1
) s ON true
LEFT JOIN na.v_current_verdicts cv ON cv.alert_id = a.alert_id;
