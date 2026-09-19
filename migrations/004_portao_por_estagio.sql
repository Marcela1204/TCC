-- ============================================================================
-- 004: portao com piso POR ESTAGIO
-- ============================================================================
-- Ate aqui os pisos de recall viviam em na.golden_scenarios e eram aplicados a
-- QUALQUER candidato. Mas o estagio 1 (Isolation Forest) e estruturalmente
-- cego a ataque de volume homogeneo (brute force, beacon denso) -- recall 0,00
-- medido. Exigir esses cenarios no portao do estagio 1 o torna IMPOSSIVEL de
-- passar. Esses ataques sao competencia do estagio 2 (SVM), que os recupera.
--
-- Aqui o piso passa a ser por (estagio, cenario). O estagio 1 e cobrado so do
-- que o IF faz (recon + falso positivo); brute_force/beacon/exfil/lateral vao
-- para o portao do estagio 2.
-- ============================================================================

CREATE TABLE IF NOT EXISTS na.gate_pisos (
    stage         smallint NOT NULL CHECK (stage IN (1, 2)),
    scenario      text     NOT NULL REFERENCES na.golden_scenarios(scenario),
    recall_minimo double precision CHECK (recall_minimo BETWEEN 0 AND 1),
    obrigatorio   boolean  NOT NULL DEFAULT true,
    PRIMARY KEY (stage, scenario)
);

COMMENT ON TABLE na.gate_pisos IS
    'Piso de recall por (estagio, cenario). Substitui o uso de '
    'golden_scenarios.recall_minimo no portao. Cenario ausente para um estagio '
    '= nao gateia aquele estagio. benigno entra com recall_minimo NULL so para '
    'carregar a checagem de falso positivo (gate_max_fpr).';

-- Estagio 1: so recon (o IF pega varredura) + benigno (falso positivo).
-- Estagio 2: recupera os ataques densos, entao e cobrado de todos.
INSERT INTO na.gate_pisos (stage, scenario, recall_minimo, obrigatorio) VALUES
  (1, 'benigno',     NULL, true),
  (1, 'recon',       0.90, false),   -- nao-obrigatorio ate haver captura real
  (2, 'benigno',     NULL, true),
  (2, 'recon',       0.90, true),
  (2, 'brute_force', 0.85, true),
  (2, 'beacon_1h',   0.75, true),
  (2, 'beacon_6h',   0.60, true),
  (2, 'exfil',       0.80, true),
  (2, 'lateral',     0.80, true)
ON CONFLICT (stage, scenario) DO NOTHING;

-- v_gate_check: piso vem de gate_pisos casando (estagio, cenario). Cenario
-- avaliado mas sem linha em gate_pisos para o estagio do candidato nao entra
-- (nao gateia) -- e assim que brute_force deixa de bloquear o estagio 1.
CREATE OR REPLACE VIEW na.v_gate_check AS
SELECT
    c.model_id                    AS candidate_model_id,
    p.model_id                    AS incumbent_model_id,
    c.stage, c.visao,
    ec.scenario,
    gp.obrigatorio,
    ec.recall                     AS recall_candidato,
    ep.recall                     AS recall_producao,
    ec.recall - ep.recall         AS delta,
    gp.recall_minimo,
    ec.taxa_falso_positivo,
    (   (ep.recall IS NOT NULL
         AND ec.recall - ep.recall < -na.param_num('gate_max_scenario_drop'))
     OR (gp.recall_minimo IS NOT NULL AND ec.recall < gp.recall_minimo)
     OR (ec.taxa_falso_positivo IS NOT NULL
         AND ec.taxa_falso_positivo > na.param_num('gate_max_fpr'))
    )                             AS reprova
FROM na.models c
JOIN na.model_evaluations ec  ON ec.model_id = c.model_id
                             AND ec.scope    = 'scenario'
JOIN na.gate_pisos gp         ON gp.scenario = ec.scenario
                             AND gp.stage    = c.stage
LEFT JOIN na.models p         ON p.status = 'promoted'
                             AND p.stage  = c.stage
                             AND p.visao IS NOT DISTINCT FROM c.visao
                             AND p.kind  <> 'decision_tree_surrogate'
LEFT JOIN na.model_evaluations ep ON ep.model_id = p.model_id
                                 AND ep.scope    = 'scenario'
                                 AND ep.scenario = ec.scenario
WHERE c.status IN ('candidate', 'shadow');

-- v_gate_verdict: "todo cenario obrigatorio avaliado" agora e por estagio.
CREATE OR REPLACE VIEW na.v_gate_verdict AS
SELECT
    g.candidate_model_id,
    g.incumbent_model_id,
    g.stage, g.visao,
    count(*)                          AS cenarios_avaliados,
    count(*) FILTER (WHERE g.reprova) AS cenarios_reprovados,
    min(g.delta)                      AS pior_delta,
    (   NOT bool_or(g.reprova)
        AND NOT EXISTS (
            SELECT 1 FROM na.gate_pisos gp
            WHERE gp.stage = g.stage
              AND gp.obrigatorio
              AND gp.scenario NOT IN (
                  SELECT g2.scenario FROM na.v_gate_check g2
                  WHERE g2.candidate_model_id = g.candidate_model_id))
    )                                 AS aprovado
FROM na.v_gate_check g
GROUP BY g.candidate_model_id, g.incumbent_model_id, g.stage, g.visao;
