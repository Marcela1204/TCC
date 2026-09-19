-- ============================================================================
-- netanomaly -- migracao 001: schema inicial
-- ============================================================================
-- Postgres 14+ com TimescaleDB (opcional -- ver secao 5).
--
-- Convencoes deste schema:
--
--   * Colunas de dado usam os mesmos nomes do netanomaly.py (src, dst, score,
--     n_packets...). So trocam para portugues quando o nome em ingles colide
--     com palavra-chave SQL: `view` -> `visao`, `precision` -> `precisao`.
--     Os VALORES continuam em ingles ('flow' / 'host') para casar com o
--     argumento --view do netanomaly_live.py.
--
--   * DIRECAO DO SCORE: em netanomaly.py o score e `-iso.score_samples(X)`,
--     entao MAIOR = MAIS ANOMALO. Todo percentil aqui segue a mesma direcao:
--     percentile = 0.99 significa "entre o 1% mais anomalo da janela".
--     Inverter isso silenciosamente e o erro mais caro possivel neste schema.
--
--   * Fluxos NAO moram no Postgres. Uma janela de 10 GB da milhoes de fluxos;
--     isso fica em parquet no disco e o banco guarda so o INDICE desses
--     arquivos (na.feature_windows). Vira linha aqui apenas o que passa do
--     piso de gravacao e portanto e candidato a alerta.
--
--   * O CORTE DO ANALISTA E APLICADO NA CONSULTA, NAO NA INGESTAO. Sao dois
--     limiares distintos: `ingest_floor_percentile` (fixo, generoso) decide o
--     que e gravado; `analyst_cut_percentile` (mexivel) decide o que aparece.
--     Por isso baixar o corte tem efeito RETROATIVO -- nao exige reprocessar.
-- ============================================================================

-- Sem BEGIN/COMMIT: quem gerencia a transacao e docker/migrar.py, para que
-- a migracao e o registro dela em na.schema_migrations commitem juntos.
-- Aplicando por psql, use --single-transaction.

-- ----------------------------------------------------------------------------
-- 0. Extensoes e schema
-- ----------------------------------------------------------------------------

-- TimescaleDB e opcional: sem ela, na.alerts continua uma tabela comum e todo
-- o resto do schema funciona igual (so nao ha particionamento nem retencao
-- automatica). Por isso a criacao vai dentro de um bloco tolerante a falha.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS timescaledb;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TimescaleDB indisponivel (%). Seguindo em Postgres puro.', SQLERRM;
END $$;

CREATE SCHEMA IF NOT EXISTS na;

COMMENT ON SCHEMA na IS
    'netanomaly. O datasource do Grafana precisa de search_path=na, senao '
    'nenhuma tabela aparece.';

SET LOCAL search_path = na, public;

-- O search_path precisa valer para conexoes FUTURAS, nao so para esta
-- transacao: o datasource do Grafana nao roda `SET search_path`, e sem isto
-- ele conecta, autentica e nao lista tabela nenhuma. Fica no papel (role) em
-- vez de no banco para funcionar tambem quando a migracao roda como um
-- usuario sem direito de ALTER DATABASE.
DO $grafana$
BEGIN
    EXECUTE format('ALTER ROLE %I SET search_path = na, public', current_user);
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'sem permissao para ALTER ROLE %; configure search_path=na '
                 'manualmente no datasource do Grafana', current_user;
END $grafana$;


-- ----------------------------------------------------------------------------
-- 1. Parametros operacionais
-- ----------------------------------------------------------------------------
-- Esta e a tabela que o Business Forms panel do Grafana escreve. Tudo que o
-- analista regula em tempo de operacao (cortes, limiares, quarentena, meia-vida)
-- vive aqui, e as views leem daqui -- nunca de constante embutida em codigo.

CREATE TABLE na.parameters (
    key           text PRIMARY KEY,
    value         jsonb       NOT NULL,
    value_type    text        NOT NULL
                  CHECK (value_type IN ('number','integer','boolean','string')),
    min_value     numeric,
    max_value     numeric,
    unidade       text,
    descricao     text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    text
);

-- Historico de mudanca de parametro. Nao e burocracia: quando o volume de
-- alertas muda de patamar, a primeira pergunta e "alguem mexeu no corte?", e
-- essa tabela responde sem depender de memoria de analista.
CREATE TABLE na.parameters_history (
    history_id  bigserial PRIMARY KEY,
    key         text        NOT NULL,
    old_value   jsonb,
    new_value   jsonb       NOT NULL,
    changed_by  text,
    changed_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON na.parameters_history (key, changed_at DESC);

CREATE OR REPLACE FUNCTION na.trg_parameters_history() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- UPDATE que nao muda o valor nao vira linha de historico.
    IF TG_OP = 'UPDATE' AND NEW.value IS NOT DISTINCT FROM OLD.value THEN
        RETURN NEW;
    END IF;

    INSERT INTO na.parameters_history (key, old_value, new_value, changed_by)
    VALUES (NEW.key,
            CASE WHEN TG_OP = 'UPDATE' THEN OLD.value END,
            NEW.value,
            NEW.updated_by);

    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER parameters_history
    BEFORE INSERT OR UPDATE ON na.parameters
    FOR EACH ROW EXECUTE FUNCTION na.trg_parameters_history();

-- Acessores. STABLE (nao IMMUTABLE): leem tabela, mas nao mudam dentro da
-- mesma consulta -- e o que permite usa-los dentro de view sem recalcular
-- por linha.
CREATE OR REPLACE FUNCTION na.param_num(p_key text) RETURNS numeric
LANGUAGE sql STABLE AS $$
    SELECT (value #>> '{}')::numeric FROM na.parameters WHERE key = p_key;
$$;

CREATE OR REPLACE FUNCTION na.param_txt(p_key text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT value #>> '{}' FROM na.parameters WHERE key = p_key;
$$;


-- ----------------------------------------------------------------------------
-- 2. Pool de treino: indice dos parquets
-- ----------------------------------------------------------------------------
-- Substitui o pool.json do lifecycle. Uma linha por janela extraida; o parquet
-- em si fica em disco.
--
-- QUARENTENA: uma janela nao entra no pool no instante em que e extraida. Ela
-- espera `quarantine_days` -- tempo para um IOC retroativo aparecer. Se o
-- comprometimento for descoberto depois, a janela e DESPEJADA (pool_state =
-- 'evicted') e o detector e retreinado sem ela. Isso e impossivel num modelo
-- que aprende incrementalmente, e e a razao de o pool ser curado em vez de
-- deslizante.

CREATE TABLE na.feature_windows (
    window_id       text        PRIMARY KEY,   -- ex.: 20260812T0300Z-flow
    visao           text        NOT NULL CHECK (visao IN ('flow','host')),
    sensor          text        NOT NULL,
    t_start         timestamptz NOT NULL,
    t_end           timestamptz NOT NULL,

    -- artefato em disco
    path            text        NOT NULL UNIQUE,
    sha256          text,
    n_rows          bigint      NOT NULL CHECK (n_rows >= 0),
    n_packets       bigint,
    bytes_on_disk   bigint,

    -- contrato de features: se o feature_set mudar, o parquet nao e mais
    -- treinavel junto com os antigos sem reprocessar.
    feature_set     text        NOT NULL,
    feature_cols    text[]      NOT NULL,
    extractor       text        CHECK (extractor IN ('nfstream','scapy','streaming')),

    -- curadoria
    pool_state      text        NOT NULL DEFAULT 'active'
                    CHECK (pool_state IN ('active','evicted')),
    evicted_at      timestamptz,
    evicted_by      text,
    evicted_reason  text,

    created_at      timestamptz NOT NULL DEFAULT now(),

    CHECK (t_end > t_start),
    CHECK ((pool_state = 'evicted') = (evicted_at IS NOT NULL)),
    CHECK (pool_state <> 'evicted' OR evicted_reason IS NOT NULL)
);

COMMENT ON COLUMN na.feature_windows.pool_state IS
    'active = elegivel assim que sair da quarentena; evicted = removido por '
    'IOC retroativo, nunca mais entra em treino.';

CREATE INDEX ON na.feature_windows (visao, t_end DESC);
CREATE INDEX ON na.feature_windows (pool_state) WHERE pool_state = 'evicted';
CREATE INDEX ON na.feature_windows (feature_set);


-- ----------------------------------------------------------------------------
-- 3. Modelos
-- ----------------------------------------------------------------------------
-- Estagio 1 = Isolation Forest (nao supervisionado, decide o alerta).
-- Estagio 2 = classificador supervisionado treinado nos vereditos do analista.
-- Surrogate = arvore de decisao que EXPLICA o estagio 1. Ela nao decide nada,
-- e as metricas dela (fidelidade, estabilidade) medem a qualidade da
-- explicacao -- nunca a da deteccao.

CREATE TABLE na.models (
    model_id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    stage            smallint    NOT NULL CHECK (stage IN (1,2)),
    -- Estagio 2 clusteriza e depois traca um hiperplano, entao ha dois tipos
    -- de artefato ali: o clusterizador e o separador que ele alimenta.
    kind             text        NOT NULL
                     CHECK (kind IN ('isolation_forest','decision_tree_surrogate',
                                     'kmeans','dbscan','hdbscan',
                                     'linear_svm','svm_rbf','one_class_svm',
                                     'logistic_regression')),
    visao            text        CHECK (visao IN ('flow','host')),

    artifact_path    text        NOT NULL UNIQUE,   -- .joblib salvo por save_model()
    artifact_sha256  text,
    sklearn_version  text,

    feature_set      text        NOT NULL,
    feature_cols     text[]      NOT NULL,
    hyperparams      jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- limiar CONGELADO no treino, o mesmo que netanomaly_live.py aplica.
    threshold        double precision,
    contamination    double precision,

    -- surrogate: aponta para o modelo de estagio 1 que ele descreve.
    explains_model_id uuid REFERENCES na.models(model_id) ON DELETE CASCADE,

    status           text        NOT NULL DEFAULT 'candidate'
                     CHECK (status IN ('candidate','shadow','promoted','retired','rejected')),
    trained_at       timestamptz NOT NULL DEFAULT now(),
    promoted_at      timestamptz,
    promoted_by      text,
    retired_at       timestamptz,
    notes            text,

    CHECK ((kind = 'decision_tree_surrogate') = (explains_model_id IS NOT NULL)),
    CHECK (status <> 'promoted' OR promoted_at IS NOT NULL),
    CHECK (status <> 'retired'  OR retired_at  IS NOT NULL)
);

-- Um unico modelo em producao por (estagio, visao). Surrogate fica de fora:
-- ele acompanha o detector, nao concorre por producao.
CREATE UNIQUE INDEX models_um_promovido
    ON na.models (stage, COALESCE(visao, ''))
    WHERE status = 'promoted' AND kind <> 'decision_tree_surrogate';

CREATE INDEX ON na.models (status, stage, trained_at DESC);

-- Quais janelas entraram no treino, e com que peso de recencia. Sem isto,
-- despejar uma janela nao diz QUAIS modelos ficaram contaminados por ela.
CREATE TABLE na.model_training_windows (
    model_id   uuid   NOT NULL REFERENCES na.models(model_id) ON DELETE CASCADE,
    window_id  text   NOT NULL REFERENCES na.feature_windows(window_id) ON DELETE RESTRICT,
    weight     double precision NOT NULL CHECK (weight > 0),
    PRIMARY KEY (model_id, window_id)
);

CREATE INDEX ON na.model_training_windows (window_id);


-- ----------------------------------------------------------------------------
-- 4. Golden set e portao de promocao
-- ----------------------------------------------------------------------------
-- O golden set e o pre-requisito de tudo: sem rotulo positivo real, falso
-- negativo nao e mensuravel e o resto e conversa.

CREATE TABLE na.golden_scenarios (
    scenario       text    PRIMARY KEY,
    descricao      text    NOT NULL,
    -- piso absoluto por cenario, alem da regra de queda relativa do portao.
    recall_minimo  double precision CHECK (recall_minimo BETWEEN 0 AND 1),
    obrigatorio    boolean NOT NULL DEFAULT true
);

COMMENT ON TABLE na.golden_scenarios IS
    'Cenario e a unidade do portao. Recall agregado pode ficar em 0.91 '
    'enquanto beacon-6h despenca de 0.80 para 0.20 -- essa e a assinatura do '
    'envenenamento lento, e a media a esconde.';

CREATE TABLE na.golden_captures (
    capture_id    text        PRIMARY KEY,      -- ex.: nmap-ss-2026-08
    scenario      text        NOT NULL REFERENCES na.golden_scenarios(scenario),
    label         smallint    NOT NULL CHECK (label IN (0,1)),  -- 1 = ataque, 0 = controle benigno
    visao         text        NOT NULL CHECK (visao IN ('flow','host')),

    pcap_path     text,
    parquet_path  text        NOT NULL UNIQUE,
    sha256        text,
    n_rows        bigint      NOT NULL CHECK (n_rows >= 0),
    feature_set   text        NOT NULL,

    ferramenta    text,                          -- nmap -sS, hydra, dnscat2...
    alvo          text,
    captured_at   timestamptz,
    descricao     text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON na.golden_captures (scenario, visao);

-- Uma linha por (modelo, escopo). scope='aggregate' e o resumo; 'scenario' e
-- o que o portao le; 'capture' e o detalhe para depurar qual captura caiu.
-- Nomes das metricas iguais aos de metricas_deteccao() em netanomaly.py, para
-- o dict Python entrar aqui quase direto.
CREATE TABLE na.model_evaluations (
    eval_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id       uuid        NOT NULL REFERENCES na.models(model_id) ON DELETE CASCADE,
    scope          text        NOT NULL CHECK (scope IN ('aggregate','scenario','capture')),
    scenario       text        REFERENCES na.golden_scenarios(scenario),
    capture_id     text        REFERENCES na.golden_captures(capture_id),

    threshold      double precision,
    n              bigint      NOT NULL CHECK (n >= 0),
    n_ataque_real  bigint,
    tp             bigint      NOT NULL DEFAULT 0,
    fp             bigint      NOT NULL DEFAULT 0,
    fn             bigint      NOT NULL DEFAULT 0,
    tn             bigint      NOT NULL DEFAULT 0,

    -- derivadas: geradas pelo banco para nunca divergirem da matriz de confusao.
    recall              double precision GENERATED ALWAYS AS
                        (tp::double precision / NULLIF(tp + fn, 0)) STORED,
    precisao            double precision GENERATED ALWAYS AS
                        (tp::double precision / NULLIF(tp + fp, 0)) STORED,
    taxa_falso_positivo double precision GENERATED ALWAYS AS
                        (fp::double precision / NULLIF(fp + tn, 0)) STORED,

    -- independem do limiar; sao a leitura mais justa de um detector cujo
    -- limiar veio de `contamination` e nao dos dados.
    roc_auc         double precision,
    precisao_media  double precision,

    evaluated_at   timestamptz NOT NULL DEFAULT now(),

    CHECK (scope <> 'scenario'  OR scenario   IS NOT NULL),
    CHECK (scope <> 'capture'   OR capture_id IS NOT NULL),
    CHECK (scope <> 'aggregate' OR (scenario IS NULL AND capture_id IS NULL))
);

-- COALESCE em vez de NULLS NOT DISTINCT, que so existe do PG15 em diante.
CREATE UNIQUE INDEX model_evaluations_unica
    ON na.model_evaluations (model_id, scope,
                             COALESCE(scenario, ''), COALESCE(capture_id, ''));

CREATE INDEX ON na.model_evaluations (model_id, scope);

-- Decisao de promocao. Fica registrada mesmo quando reprova: a serie de
-- reprovacoes por cenario e o sinal de envenenamento lento.
CREATE TABLE na.promotions (
    promotion_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    candidate_model_id  uuid        NOT NULL REFERENCES na.models(model_id) ON DELETE CASCADE,
    incumbent_model_id  uuid        REFERENCES na.models(model_id) ON DELETE SET NULL,
    decisao             text        NOT NULL
                        CHECK (decisao IN ('aprovado','reprovado','sobreposto')),
    gate_report         jsonb       NOT NULL,   -- delta por cenario, congelado
    motivo              text,
    decided_by          text        NOT NULL,
    decided_at          timestamptz NOT NULL DEFAULT now(),

    -- 'sobreposto' = portao reprovou e um humano promoveu assim mesmo.
    -- Exigir justificativa e o unico freio que faz sentido aqui.
    CHECK (decisao <> 'sobreposto' OR motivo IS NOT NULL)
);

CREATE INDEX ON na.promotions (candidate_model_id, decided_at DESC);


-- ----------------------------------------------------------------------------
-- 5. Alertas
-- ----------------------------------------------------------------------------
-- So entra aqui o que passou de `ingest_floor_percentile`. O piso e generoso
-- de proposito: o corte do analista e aplicado depois, na consulta, e so tem
-- efeito retroativo dentro do que foi gravado. Subir o piso economiza disco e
-- encurta o alcance retroativo -- e exatamente esse o trade-off a medir antes
-- de fixar o valor (ver na.v_ingest_volume).

CREATE TABLE na.alerts (
    alert_id      uuid        NOT NULL DEFAULT gen_random_uuid(),
    ts            timestamptz NOT NULL,          -- t0 do fluxo; chave de particao
    window_id     text        NOT NULL,
    model_id      uuid        NOT NULL,
    sensor        text        NOT NULL,
    visao         text        NOT NULL CHECK (visao IN ('flow','host')),

    -- entidade. Na visao 'host' so src_ip esta preenchido.
    src_ip        inet        NOT NULL,
    dst_ip        inet,
    src_port      integer     CHECK (src_port BETWEEN 0 AND 65535),
    dst_port      integer     CHECK (dst_port BETWEEN 0 AND 65535),
    proto         smallint,

    -- MAIOR = MAIS ANOMALO, nas duas colunas.
    score         double precision NOT NULL,
    percentile    double precision NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    threshold     double precision NOT NULL,

    -- explicabilidade: a regra da arvore que descreve esta decisao, congelada
    -- no momento do alerta. Guardar o texto e nao so o id do surrogate importa
    -- porque promover um detector novo invalida o surrogate antigo -- e o
    -- alerta antigo precisa continuar explicavel depois disso.
    surrogate_model_id uuid,
    surrogate_rule     text,

    features      jsonb       NOT NULL,
    label_cic     smallint    CHECK (label_cic IN (0,1)),  -- verdade do CIC-IDS-2017 em replay

    created_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (ts, alert_id)
);

COMMENT ON COLUMN na.alerts.percentile IS
    'Posicao do score DENTRO da janela, 0..1, maior = mais anomalo. E o que '
    'permite o analista expressar o corte em porcentagem; o score bruto e o '
    'que o modelo de estagio 2 consome.';

COMMENT ON CONSTRAINT alerts_pkey ON na.alerts IS
    'Hypertable exige a coluna de particao na PK, entao alert_id sozinho nao '
    'tem UNIQUE do banco. E uuid v4 gerado pela aplicacao; colisao e '
    'desprezivel, mas nao ha rede de protecao do banco aqui.';

-- Sem FK apontando PARA alerts: chave estrangeira referenciando hypertable e
-- territorio de limitacao dependendo da versao do Timescale. verdicts e
-- stage2_assignments carregam alert_id solto, com integridade na aplicacao.
-- Se preferir garantia do banco, basta NAO transformar em hypertable (pular o
-- bloco abaixo) e adicionar as FKs -- o resto do schema continua identico.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('na.alerts', 'ts',
                                  chunk_time_interval => INTERVAL '1 day',
                                  if_not_exists       => TRUE);

        -- CONFERIR contra a politica de retencao exigida antes de subir. Em
        -- ambiente regulado esse numero costuma vir imposto de fora.
        PERFORM add_retention_policy('na.alerts', INTERVAL '180 days',
                                     if_not_exists => TRUE);
    ELSE
        RAISE NOTICE 'Sem TimescaleDB: na.alerts fica tabela comum, sem '
                     'particionamento nem retencao automatica.';
    END IF;
END $$;

CREATE INDEX ON na.alerts (percentile DESC, ts DESC);
CREATE INDEX ON na.alerts (src_ip, ts DESC);
CREATE INDEX ON na.alerts (window_id);
CREATE INDEX ON na.alerts (model_id, ts DESC);


-- ----------------------------------------------------------------------------
-- 6. Vereditos do analista
-- ----------------------------------------------------------------------------
-- Fonte de rotulo do sistema inteiro. Revisao NAO sobrescreve: cria linha nova
-- apontando para a anterior via `supersedes`. Analista muda de ideia, e a
-- mudanca e informacao -- dois vereditos contraditorios sobre o mesmo alerta
-- indicam ou ambiguidade real no trafego ou divergencia de criterio na equipe.

CREATE TABLE na.verdicts (
    verdict_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    alert_id     uuid        NOT NULL,   -- sem FK: alerts e hypertable
    alert_ts     timestamptz NOT NULL,   -- carrega a chave de particao p/ o join

    veredito     text        NOT NULL CHECK (veredito IN ('ataque','benigno','indeterminado')),
    classe       text,                    -- taxonomia opcional: recon, c2, exfil...
    confianca    smallint    CHECK (confianca BETWEEN 1 AND 5),
    analista     text        NOT NULL,
    justificativa text,

    -- SNAPSHOT. A retencao derruba chunks inteiros de alerts aos 180 dias, e o
    -- veredito e rotulo de treino do estagio 2 -- precisa sobreviver ao alerta
    -- que o originou. Sem esta copia, o label fica sem vetor de feature.
    features     jsonb       NOT NULL,
    score        double precision NOT NULL,
    percentile   double precision NOT NULL,

    supersedes   uuid        REFERENCES na.verdicts(verdict_id) ON DELETE RESTRICT,
    created_at   timestamptz NOT NULL DEFAULT now(),

    CHECK (verdict_id <> supersedes)
);

-- Um veredito so pode ser substituido por um: sem isso a cadeia bifurca e
-- "qual e o veredito atual" deixa de ter resposta.
CREATE UNIQUE INDEX verdicts_cadeia_linear
    ON na.verdicts (supersedes) WHERE supersedes IS NOT NULL;

CREATE INDEX ON na.verdicts (alert_id);
CREATE INDEX ON na.verdicts (created_at DESC);
CREATE INDEX ON na.verdicts (veredito, created_at DESC);


-- ----------------------------------------------------------------------------
-- 7. Fila do estagio 2
-- ----------------------------------------------------------------------------

CREATE TABLE na.stage2_assignments (
    assignment_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        uuid        NOT NULL,   -- sem FK: alerts e hypertable
    alert_ts        timestamptz NOT NULL,
    model_id        uuid        NOT NULL REFERENCES na.models(model_id) ON DELETE CASCADE,

    decision_value  double precision NOT NULL,   -- distancia com sinal ao hiperplano
    -- Ordenar a fila por margem CRESCENTE poe na frente os casos mais proximos
    -- da fronteira, que sao onde o veredito mais move o hiperplano. E active
    -- learning basico: custa um ORDER BY. Sem isso o analista revisa casos
    -- obvios e o modelo quase nao aprende.
    margin          double precision GENERATED ALWAYS AS (abs(decision_value)) STORED,
    predicted       text        CHECK (predicted IN ('ataque','benigno')),

    state           text        NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','in_review','done','skipped')),
    assigned_to     text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    closed_at       timestamptz,

    CHECK ((state IN ('done','skipped')) = (closed_at IS NOT NULL))
);

CREATE UNIQUE INDEX ON na.stage2_assignments (alert_id, model_id);
CREATE INDEX stage2_fila ON na.stage2_assignments (margin ASC)
    WHERE state = 'pending';


-- ----------------------------------------------------------------------------
-- 7b. Pedidos de retreino
-- ----------------------------------------------------------------------------
-- O botao de retreino manual do analista aterrissa aqui; o relogio diario do
-- lifecycle consome a fila. Pedido NAO promove nada -- ele so antecipa o
-- treino de um candidato, que continua tendo de passar pelo portao.
--
-- `near_misses_ultimos_7d` e gravado junto no momento do pedido: a
-- justificativa "esta dando muito falso negativo" precisa vir com o numero
-- que a sustentava (na.v_stage1_near_misses), senao nao ha como avaliar
-- depois se o retreino resolveu.

CREATE TABLE na.retrain_requests (
    request_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    stage        smallint    NOT NULL CHECK (stage IN (1,2)),
    visao        text        CHECK (visao IN ('flow','host')),
    origem       text        NOT NULL CHECK (origem IN ('analista','agendado','despejo')),
    motivo       text        NOT NULL,
    solicitado_por text      NOT NULL,

    near_misses_ultimos_7d integer,
    corte_no_momento       double precision,

    state        text        NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending','running','done','failed','cancelled')),
    model_id     uuid        REFERENCES na.models(model_id) ON DELETE SET NULL,
    erro         text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,

    CHECK (state <> 'failed' OR erro IS NOT NULL),
    CHECK ((state IN ('done','failed','cancelled')) = (finished_at IS NOT NULL))
);

-- Um pedido pendente por (estagio, visao): clicar o botao tres vezes nao
-- enfileira tres treinos.
CREATE UNIQUE INDEX retrain_um_pendente
    ON na.retrain_requests (stage, COALESCE(visao, ''))
    WHERE state IN ('pending','running');

CREATE INDEX ON na.retrain_requests (state, created_at);

-- ----------------------------------------------------------------------------
-- 8. Views
-- ----------------------------------------------------------------------------

-- Pool de treino: janelas fora da quarentena, nao despejadas, com o peso de
-- recencia ja calculado. Meia-vida e o mecanismo certo para acompanhar mudanca
-- legitima de trafego sem descartar historico -- treinar so na ultima janela
-- nao e, porque faz o ataque presente na janela virar parte do "normal".
CREATE OR REPLACE VIEW na.v_training_pool AS
SELECT
    w.*,
    w.t_end + (na.param_num('quarantine_days') || ' days')::interval AS liberado_em,
    power(0.5, EXTRACT(EPOCH FROM (now() - w.t_end))
               / (na.param_num('recency_halflife_days') * 86400.0)) AS peso_recencia
FROM na.feature_windows w
WHERE w.pool_state = 'active'
  AND now() >= w.t_end + (na.param_num('quarantine_days') || ' days')::interval;

-- Modelos treinados sobre janela que foi despejada depois. Estes precisam de
-- retreino: o comprometimento daquele periodo esta dentro do baseline deles.
CREATE OR REPLACE VIEW na.v_models_contaminados AS
SELECT DISTINCT
    m.model_id, m.stage, m.kind, m.visao, m.status, m.trained_at,
    count(*)          OVER (PARTITION BY m.model_id) AS n_janelas_despejadas,
    min(w.evicted_at) OVER (PARTITION BY m.model_id) AS primeiro_despejo
FROM na.models m
JOIN na.model_training_windows mtw ON mtw.model_id = m.model_id
JOIN na.feature_windows w          ON w.window_id  = mtw.window_id
WHERE w.pool_state = 'evicted'
  AND m.status IN ('candidate','shadow','promoted');

-- Veredito corrente: o que ninguem substituiu.
CREATE OR REPLACE VIEW na.v_current_verdicts AS
SELECT v.*
FROM na.verdicts v
WHERE NOT EXISTS (SELECT 1 FROM na.verdicts s WHERE s.supersedes = v.verdict_id);

-- Alertas acima do corte do analista. E ESTA a lista operacional -- mover o
-- parametro muda o passado junto, sem reprocessar nada.
CREATE OR REPLACE VIEW na.v_alertas_correntes AS
SELECT
    a.*,
    cv.veredito,
    cv.analista,
    cv.created_at AS veredito_em
FROM na.alerts a
LEFT JOIN na.v_current_verdicts cv ON cv.alert_id = a.alert_id
WHERE a.percentile >= na.param_num('analyst_cut_percentile');

-- QUASE-ACERTOS: alerta que o analista confirmou como ataque real mas que
-- ficou ABAIXO do corte -- ou seja, o operador nunca teria visto. Esta view e
-- a medida operacional de falso negativo do estagio 1. Quando ela cresce, ou
-- o corte esta alto demais ou o modelo envelheceu; e este numero, e nao
-- sensacao de analista, que deve estar por tras do botao de retreino.
CREATE OR REPLACE VIEW na.v_stage1_near_misses AS
SELECT
    a.ts, a.alert_id, a.sensor, a.visao, a.src_ip, a.dst_ip, a.dst_port,
    a.score, a.percentile,
    na.param_num('analyst_cut_percentile') - a.percentile AS distancia_do_corte,
    a.surrogate_rule,
    cv.analista, cv.classe, cv.created_at AS veredito_em
FROM na.alerts a
JOIN na.v_current_verdicts cv ON cv.alert_id = a.alert_id
WHERE cv.veredito = 'ataque'
  AND a.percentile < na.param_num('analyst_cut_percentile')
ORDER BY a.ts DESC;

-- Portao de promocao, por cenario. Reprova queda maior que
-- `gate_max_scenario_drop` em QUALQUER cenario isolado, independente do
-- agregado, e tambem quem furar o piso absoluto do cenario.
CREATE OR REPLACE VIEW na.v_gate_check AS
SELECT
    c.model_id                    AS candidate_model_id,
    p.model_id                    AS incumbent_model_id,
    c.stage, c.visao,
    ec.scenario,
    gs.obrigatorio,
    ec.recall                     AS recall_candidato,
    ep.recall                     AS recall_producao,
    ec.recall - ep.recall         AS delta,
    gs.recall_minimo,
    ec.taxa_falso_positivo,
    (   (ep.recall IS NOT NULL
         AND ec.recall - ep.recall < -na.param_num('gate_max_scenario_drop'))
     OR (gs.recall_minimo IS NOT NULL AND ec.recall < gs.recall_minimo)
     -- Sem esta terceira condicao, um candidato que alerta em TUDO teria
     -- recall 1.0 em todo cenario de ataque e passaria limpo. O cenario
     -- 'benigno' e quem tem tn+fp > 0 e portanto quem carrega esta medida.
     OR (ec.taxa_falso_positivo IS NOT NULL
         AND ec.taxa_falso_positivo > na.param_num('gate_max_fpr'))
    )                             AS reprova
FROM na.models c
JOIN na.model_evaluations ec  ON ec.model_id = c.model_id
                             AND ec.scope    = 'scenario'
JOIN na.golden_scenarios gs   ON gs.scenario = ec.scenario
LEFT JOIN na.models p         ON p.status = 'promoted'
                             AND p.stage  = c.stage
                             AND p.visao IS NOT DISTINCT FROM c.visao
                             AND p.kind  <> 'decision_tree_surrogate'
LEFT JOIN na.model_evaluations ep ON ep.model_id = p.model_id
                                 AND ep.scope    = 'scenario'
                                 AND ep.scenario = ec.scenario
WHERE c.status IN ('candidate','shadow');

-- Veredito do portao: um candidato so passa se nenhum cenario reprovar e se
-- todo cenario obrigatorio tiver sido avaliado.
CREATE OR REPLACE VIEW na.v_gate_verdict AS
SELECT
    g.candidate_model_id,
    g.incumbent_model_id,
    g.stage, g.visao,
    count(*)                                        AS cenarios_avaliados,
    count(*) FILTER (WHERE g.reprova)               AS cenarios_reprovados,
    min(g.delta)                                    AS pior_delta,
    (   NOT bool_or(g.reprova)
        AND NOT EXISTS (
            SELECT 1 FROM na.golden_scenarios gs
            WHERE gs.obrigatorio
              AND gs.scenario NOT IN (
                  SELECT g2.scenario FROM na.v_gate_check g2
                  WHERE g2.candidate_model_id = g.candidate_model_id))
    )                                               AS aprovado
FROM na.v_gate_check g
GROUP BY g.candidate_model_id, g.incumbent_model_id, g.stage, g.visao;

-- Fila de revisao ordenada por margem: fronteira primeiro.
CREATE OR REPLACE VIEW na.v_fila_stage2 AS
SELECT s.*, a.ts, a.src_ip, a.dst_ip, a.dst_port, a.percentile, a.surrogate_rule
FROM na.stage2_assignments s
JOIN na.alerts a ON a.alert_id = s.alert_id AND a.ts = s.alert_ts
WHERE s.state = 'pending'
ORDER BY s.margin ASC;

-- Dimensionamento do piso de gravacao. Responde a pergunta que ficou em
-- aberto: quantos fluxos por dia os 5% mais anomalos representam de fato.
-- Rodar contra algumas janelas reais ANTES de fixar ingest_floor_percentile.
CREATE OR REPLACE VIEW na.v_ingest_volume AS
SELECT
    w.visao,
    date_trunc('day', w.t_start)                                   AS dia,
    count(*)                                                       AS n_janelas,
    sum(w.n_rows)                                                  AS fluxos_extraidos,
    round(sum(w.n_rows) * (1 - na.param_num('ingest_floor_percentile')))
                                                                   AS linhas_previstas,
    sum(w.bytes_on_disk)                                           AS parquet_bytes
FROM na.feature_windows w
GROUP BY 1, 2;


-- ----------------------------------------------------------------------------
-- 9. Seeds
-- ----------------------------------------------------------------------------

INSERT INTO na.parameters (key, value, value_type, min_value, max_value, unidade, descricao) VALUES
  ('ingest_floor_percentile', '0.95',  'number',  0.50, 1.00, 'percentil',
   'Piso de GRAVACAO. Fluxo abaixo deste percentil nunca vira linha em alerts. '
   'Fixo e generoso: define o alcance maximo de qualquer corte retroativo. '
   'MEDIR em janela real (na.v_ingest_volume) antes de fixar.'),

  ('analyst_cut_percentile', '0.99',  'number',  0.50, 1.00, 'percentil',
   'Corte de EXIBICAO, mexivel pelo analista. Aplicado em view, portanto '
   'retroativo dentro do que o piso gravou.'),

  ('quarantine_days',        '7',     'integer', 0,    90,   'dias',
   'Espera antes de uma janela entrar no pool de treino, para dar tempo de um '
   'IOC retroativo aparecer.'),

  ('recency_halflife_days',  '14',    'integer', 1,    365,  'dias',
   'Meia-vida do peso de recencia no pool. Acompanha mudanca legitima de '
   'trafego sem descartar historico.'),

  ('gate_max_scenario_drop', '0.10',  'number',  0.00, 1.00, 'recall',
   'Queda de recall que reprova a promocao em QUALQUER cenario isolado, '
   'independente do agregado.'),

  ('gate_max_fpr',           '0.02',  'number',  0.00, 1.00, 'taxa',
   'Taxa de falso positivo que reprova a promocao. Medida no cenario de '
   'controle benigno -- e o que impede um candidato degenerado, que alerta '
   'em tudo e por isso tem recall 1.0, de passar pelo portao.'),

  ('window_seconds',         '780',   'integer', 60,   86400, 'segundos',
   'Duracao da janela de agregacao ao vivo.'),

  ('stage2_queue_size',      '50',    'integer', 1,    1000, 'itens',
   'Quantos casos de menor margem entram na fila de revisao por rodada.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO na.golden_scenarios (scenario, descricao, recall_minimo, obrigatorio) VALUES
  ('recon',        'Varredura de portas e hosts (nmap -sS, -sU, -sV).',        0.90, true),
  ('brute_force',  'Forca bruta em servico autenticado (SSH, FTP, HTTP).',     0.85, true),
  ('exfil',        'Exfiltracao de volume por canal incomum (DNS, ICMP, HTTP POST).', 0.80, true),
  ('beacon_1h',    'C2 com batida horaria.',                                   0.75, true),
  -- Cenario de horizonte longo: invisivel numa janela de 13 minutos. So
  -- aparece com feature agregada por par origem/destino ao longo de dias
  -- (regularidade do intervalo, jitter, razao up/down). Fica no golden set
  -- desde ja para o portao acusar quando ele degradar.
  ('beacon_6h',    'C2 com batida de 6h. Exige feature de horizonte longo.',   0.60, true),
  ('lateral',      'Movimento lateral interno (SMB, RDP, WinRM).',             0.80, true),
  ('benigno',      'Controle: trafego limpo. Mede taxa de falso positivo.',    NULL, true)
ON CONFLICT (scenario) DO NOTHING;
