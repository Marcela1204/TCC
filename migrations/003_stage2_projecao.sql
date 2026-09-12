-- ============================================================================
-- 003: coordenadas 2D para visualizar a separacao do estagio 2
-- ============================================================================
-- O SVM do estagio 2 vive em 17 dimensoes (as FEATURE_COLS). Para o dashboard
-- desenhar o "grafico de clusterizacao" precisa de 2D. A projecao e um PCA(2)
-- ajustado no TREINO e congelado no artefato -- assim todos os pontos usam a
-- mesma transformacao e sao comparaveis entre janelas. O `predict` preenche
-- estas colunas; ficam nulas ate ele rodar.
-- ============================================================================

ALTER TABLE na.stage2_assignments
    ADD COLUMN IF NOT EXISTS coord_x double precision,
    ADD COLUMN IF NOT EXISTS coord_y double precision;

COMMENT ON COLUMN na.stage2_assignments.coord_x IS
    'Projecao PCA 2D (componente 1) das features do alerta, para o scatter do '
    'dashboard. Congelada no artefato do estagio 2.';

-- View pronta para o painel de dispersao: um ponto por alerta classificado,
-- com a classe predita e a margem (distancia ao hiperplano). Margem baixa =
-- perto da fronteira; e o que o analista revisa primeiro.
CREATE OR REPLACE VIEW na.v_stage2_scatter AS
SELECT
    s.assignment_id,
    s.coord_x,
    s.coord_y,
    s.predicted,
    s.decision_value,
    s.margin,
    s.state,
    host(a.src_ip)  AS origem,
    host(a.dst_ip)  AS destino,
    a.dst_port,
    a.ts
FROM na.stage2_assignments s
JOIN na.alerts a ON a.alert_id = s.alert_id AND a.ts = s.alert_ts
WHERE s.coord_x IS NOT NULL;
