# Sistema de detecção de intrusão — arquitetura e estado da implementação

Documento de referência do projeto. Descreve o que existe, por que foi feito
assim, e o que foi efetivamente medido. Atualizado em 2026-09-08.

---

## 1. Visão geral

O sistema é um IDS com **pipeline de dois modelos em cascata**, mais uma
interface para analistas.

| estágio | função | situação |
|---|---|---|
| **1 detector** | classifica tráfego em tempo real: "possível ataque" ou não | implementado e exercitado |
| **surrogate** | traduz as decisões do estágio 1 em regras legíveis | implementado, embarcado no artefato do detector |
| **2 refinador** | clusteriza os possíveis ataques e traça o hiperplano que separa ataque real de normal | esquema pronto, sem código |
| **frontend** | painel do analista: acompanhar, exportar gráficos, reajustar parâmetros | não iniciado |

O estágio 1 é não supervisionado porque não há rótulo disponível no tráfego de
produção. O estágio 2 é onde o rótulo entra: ele consome os **vereditos do
analista** e refina o hiperplano continuamente.

### Prioridade das três frentes

1. Estágio 1 — **mais importante**
2. Frontend — **mais importante**
3. Estágio 2

---

## 2. Arquitetura

```
   pcap histórico ──> lifecycle extract ──┐
                                           ├──> pool de parquets
   tráfego ao vivo ──> netanomaly_live ───┘     + na.feature_windows
                              │                       (via sink.py)
                              ├──> na.alerts   (percentil ≥ piso de ingestão)
                              └──> stdout      (alerta + regra da árvore)

   pool ──> v_training_pool ──> lifecycle candidate ──> na.models
                                                       + na.model_evaluations
                                                              │
   golden set ──────────────────> v_gate_check / v_gate_verdict
                                                              │
                                                     lifecycle promote
                                                              │
                                            symlink current_<visão>.joblib
                                                              │
                                                netanomaly_live recarrega
```

### Componentes

| arquivo | papel |
|---|---|
| `netanomaly.py` | extração de features, treino, métricas, rótulos do CIC-IDS-2017 |
| `netanomaly_live.py` | analisador em tempo real; aplica o modelo congelado |
| `sink.py` | persistência do analisador: pool de treino + alertas |
| `lifecycle.py` | ciclo de vida do modelo: pool, treino, portão, promoção, despejo |
| `migrations/001_init.sql` | esquema Postgres/TimescaleDB (13 tabelas, 9 views) |
| `docker/migrar.py` | controlador de migração (aplica uma vez cada) |

Cerca de 3.900 linhas no total.

### Duas visões de agregação

Ambas suportadas em todo o pipeline:

- **`flow`** — 17 features por fluxo (5-tupla bidirecional): contagens,
  tamanhos, intervalos entre pacotes, razões de flags TCP.
- **`host`** — 11 features agregadas por IP de origem: `n_dst`, `n_dports`,
  `dports_per_dst`, `syn_ack_gap`. Captura leque de conexões (*fan-out*), que a
  visão por fluxo não enxerga.

Só a visão `flow` foi exercitada de ponta a ponta.

---

## 3. Modelos em uso

### Estágio 1 — detector

`StandardScaler` + `IsolationForest(n_estimators=200)`, ambos ajustados com
`sample_weight` igual ao peso de recência da janela de origem de cada linha.

```python
scores    = -iso.score_samples(scaler.transform(X))   # MAIOR = mais anômalo
threshold = quantil_ponderado(scores, 1 - contamination, pesos)
```

Duas propriedades que não são óbvias:

- **O limiar é congelado no artefato.** O analisador ao vivo aplica o mesmo
  número, nunca recalcula. Recalcular ao vivo faria a taxa de alerta depender
  da composição da janela corrente em vez do treino.
- **O quantil é ponderado**, diferente do `np.quantile` simples que
  `netanomaly.detect()` usa. Com pesos, o quantil simples faria o limiar
  responder a linhas que o modelo mal usou — o limiar diria uma coisa e o
  ajuste teria feito outra.

### Surrogate — explicabilidade

`DecisionTreeClassifier(max_depth=4)`, treinada no X **cru** (não escalado)
contra o rótulo que o próprio Isolation Forest atribuiu. Produz regras como
`n_dports>50 & duration<=2.1`. Treina no X cru de propósito: a explicação
precisa sair em unidade que o analista reconheça, não em desvios-padrão.

**A árvore explica, não decide.** E a fidelidade dela é cega à qualidade da
detecção — ver §7.

### Estágio 2 — refinador

Sem implementação. O esquema já aceita `kmeans`, `dbscan`, `hdbscan`,
`linear_svm`, `svm_rbf`, `one_class_svm`, `logistic_regression`, e as tabelas
`verdicts` e `stage2_assignments` existem, com fila de revisão ordenada por
**margem crescente** — os casos mais próximos da fronteira primeiro, que é onde
o veredito do analista mais move o hiperplano.

---

## 4. Ciclo de vida do modelo

### Por que o pool é curado, e não deslizante

**Retreinar na janela de tráfego mais recente aumenta o falso negativo.** O
Isolation Forest aprende "normal" como sendo a massa dos dados que recebeu; se
a janela contém ataque, o ataque passa a fazer parte do normal aprendido e
deixa de ser marcado na janela seguinte.

Pior: é explorável de forma gradual. Um C2 com batida de 6h é absorvido um
pouco mais no *baseline* a cada retreino, e em duas semanas o canal fica
indistinguível de normal. O atacante não precisa evadir nada — só precisa ser
paciente e deixar o laço treinar nele.

O que o dado recente compra de verdade é **redução de falso positivo**
(servidor novo, mudança de horário de backup, faixa de IP nova). Isso reduz a
fadiga do analista, e só por esse caminho indireto ajuda o falso negativo.

Por isso o detector nunca treina numa janela só. Treina num **pool curado**:

- **quarentena** — a janela só entra depois de `quarantine_days` (7) sem IOC
  retroativo;
- **despejo** — descoberto comprometimento depois, a janela sai do pool e o
  modelo é retreinado sem ela. Isso é impossível num modelo que aprende
  incrementalmente;
- **recência** — peso com meia-vida de 14 dias, para acompanhar mudança
  legítima de tráfego sem descartar histórico.

### Três relógios separados

| relógio | cadência | automático? |
|---|---|---|
| surrogate / explicabilidade | a cada janela | sim |
| candidato + avaliação | diário | sim — só treina e mede |
| **promoção para produção** | semanal ou sob demanda | **não — passa pelo portão** |

Um portão que se auto-aprova não é portão. A promoção é deliberadamente manual
e fica fora do laço automático.

### Passo a passo do `lifecycle candidate`

1. **Seleciona o pool** (`v_training_pool`): janelas com `pool_state='active'`
   e `now() >= t_end + quarantine_days`. Despejadas ficam fora.
2. **Calcula o peso de recência**: `0.5^(idade/meia_vida)`, **normalizado pela
   janela mais nova do pool**. Sem a normalização, captura histórica de 2017
   daria peso ~1e-64 e o pool sairia vazio — o módulo não rodaria sobre os
   datasets do CIC.
3. **Corta o rabo**: descarta janela com peso abaixo de `--peso-minimo` (0.05,
   ≈4,3 meias-vidas contadas da janela mais nova).
4. **Homogeneíza**: recusa misturar `feature_set` diferentes. Treinar sobre
   contratos de coluna distintos produz um modelo cujo vetor de entrada não
   existe em lugar nenhum — falha silenciosa, que é o pior tipo.
5. **Monta a matriz** com dois mecanismos de papéis separados:
   - a **amostragem** é proporcional ao tamanho da janela e existe *só* para
     limitar memória (teto `--max-rows`, 2 milhões);
   - o **`sample_weight`** carrega a recência.

   Confundi-los aplicaria a recência duas vezes.
6. **Treina** scaler + Isolation Forest + árvore, todos ponderados.
7. **Avalia no golden set**, por captura, por cenário e agregado.
8. **Grava** o modelo como `candidate` e a procedência em
   `model_training_windows` — é isso que torna o despejo auditável: sem ela,
   saber que uma janela estava contaminada não diz *quais* modelos a
   absorveram.

Nunca promove.

### O portão

`lifecycle promote` lê `v_gate_check` / `v_gate_verdict`. Reprova se
**qualquer** cenário isolado:

- cair mais de `gate_max_scenario_drop` (0.10) em relação à produção vigente,
  **ou**
- ficar abaixo do piso absoluto do cenário (`golden_scenarios.recall_minimo`),
  **ou**
- exceder `gate_max_fpr` (0.02) no controle benigno.

O terceiro critério existe porque um candidato degenerado que alerta em tudo
teria recall 1.00 em todo cenário de ataque e passaria limpo.

**A checagem por cenário, e não agregada, é o ponto.** O recall agregado pode
ficar em 0.91 enquanto `beacon_6h` despenca de 0.80 para 0.20 — essa é a
assinatura do envenenamento lento, e a média a esconde.

Aprovando: aposenta o modelo antigo e os surrogates que o descreviam, troca o
symlink com `rename()` atômico, registra em `promotions`. Reprovando: registra
a reprovação e sai. `--force` exige `--reason`.

### Despejo

```bash
lifecycle.py evict --windows 20260812T0300Z --reason "C2 no host .47, INC-441"
```

Marca a janela e lista, via `v_models_contaminados`, quais modelos a
absorveram. Retreinar sem ela restaura os valores originais — verificado.

### Retreino manual do analista

`na.retrain_requests` recebe o pedido e grava junto o número de quase-acertos
que o sustentava. A justificativa "está dando muito falso negativo" precisa vir
com o número que a sustentava, senão não há como avaliar depois se o retreino
resolveu. Um índice parcial impede que três cliques enfileirem três treinos.

---

## 5. Persistência

### As quatro decisões fundadoras do esquema

1. **Fluxos não vão para o Postgres.** Uma janela de 10 GB dá milhões de
   fluxos; treino de ML quer formato colunar comprimido, não linha
   transacional. Os parquets ficam em disco e o banco guarda um **índice** deles
   (`na.feature_windows`). Só o que vira alerta entra como linha.
2. **O corte do analista é aplicado na consulta, não na ingestão.** Dois
   limiares distintos: `ingest_floor_percentile` (fixo e generoso, grava os ~5%
   mais anômalos) e `analyst_cut_percentile` (mexível, aplicado numa view).
   Assim mover o corte tem efeito **retroativo** sem reprocessar nada — se a
   ingestão filtrasse, baixar o corte depois não traria nada de volta.
3. **Escore contínuo e percentil, os dois.** O percentil permite expressar o
   parâmetro em porcentagem, como o analista quer; o escore bruto é o que o
   estágio 2 consome.
4. **Sem FK apontando para `alerts`.** Ela é hypertable do TimescaleDB, e chave
   estrangeira referenciando hypertable é território de limitação conforme a
   versão. `verdicts` e `stage2_assignments` carregam `alert_id` sem
   *constraint*, com integridade na aplicação.

### Duas cadências no sink

| | duração | papel |
|---|---|---|
| janela de análise | `--window`, 10 s | latência do alerta |
| janela de pool | `window_seconds`, 780 s | unidade de treino, quarentena, despejo |

Confundi-las quebra os dois lados: uma janela de 10 s tem fluxos de menos para
ser unidade de treino e geraria 8.640 linhas por dia em `feature_windows`; uma
de 13 minutos como latência de alerta seria inaceitável num IDS.

O balde é alinhado por `t0 // window_seconds` — o **mesmo** que
`lifecycle extract` usa, para que janela vinda de pcap e janela vinda de
captura ao vivo sejam a mesma coisa.

### Percentil contra o treino, não contra a janela

`alerts.percentile` vem de uma grade de quantis **congelada no artefato**, não
da posição do fluxo dentro da sua janela.

Percentil relativo à janela é uma armadilha: numa janela de 13 minutos sem
ataque nenhum, o "1% mais anômalo" é tráfego perfeitamente normal, e o corte do
analista geraria alerta **por construção** — falso positivo garantido em toda
janela tranquila. Contra a grade do treino, janela tranquila não gera alerta.

De quebra o alerta sai na hora, sem esperar a janela de pool fechar: o
percentil de um fluxo não depende dos fluxos que ainda vão chegar.

### Vereditos guardam cópia do vetor de features

A retenção derruba *chunks* de `alerts` aos 180 dias, mas o veredito é rótulo
de treino do estágio 2 e precisa sobreviver ao alerta que o originou. Sem a
cópia, o rótulo fica sem vetor de feature.

Revisão de veredito **não sobrescreve**: cria linha nova apontando para a
anterior via `supersedes`. Analista muda de ideia, e a mudança é informação —
dois vereditos contraditórios sobre o mesmo alerta indicam ou ambiguidade real
no tráfego ou divergência de critério na equipe.

### Objetos do esquema

**Tabelas (13):** `parameters`, `parameters_history`, `feature_windows`,
`models`, `model_training_windows`, `golden_scenarios`, `golden_captures`,
`model_evaluations`, `promotions`, `alerts`, `verdicts`,
`stage2_assignments`, `retrain_requests`.

**Views (9):** `v_training_pool`, `v_models_contaminados`,
`v_current_verdicts`, `v_alertas_correntes`, `v_stage1_near_misses`,
`v_gate_check`, `v_gate_verdict`, `v_fila_stage2`, `v_ingest_volume`.

Duas merecem destaque:

- **`v_stage1_near_misses`** — alertas que o analista confirmou como ataque
  real mas que ficaram **abaixo** do corte, ou seja, que o operador nunca teria
  visto. É a medida operacional de falso negativo do estágio 1, e é este número
  que deve estar por trás do botão de retreino, não sensação de analista.
- **`v_ingest_volume`** — dimensiona o piso de gravação: quantas linhas os 5%
  mais anômalos representam por dia. Rodar contra janelas reais antes de fixar
  `ingest_floor_percentile`.

**Parâmetros operacionais** (tabela `parameters`, editável pelo analista):
`ingest_floor_percentile`, `analyst_cut_percentile`, `quarantine_days`,
`recency_halflife_days`, `gate_max_scenario_drop`, `gate_max_fpr`,
`window_seconds`, `stage2_queue_size`.

---

## 6. Execução em container

Uma imagem para os três papéis — detector, treinador e utilitários rodam o
mesmo código e a mesma versão de scikit-learn, o que importa porque o artefato
`.joblib` é serializado por versão.

**Nenhum container roda como root.** As capacidades de captura são *file
capabilities* no `/usr/bin/tcpdump` (`cap_net_raw`, `cap_net_admin`), então o
processo é uid 1000 e ainda abre socket de captura. Efeito colateral bom: os
parquets no bind mount saem com o dono do host, não de root.

### Captura de tráfego

Um container só fareja o que chega ao *namespace de rede* dele. Isso descarta a
opção mais intuitiva:

> **`macvlan` em modo bridge não serve para IDS.** Dá ao container MAC e IP
> próprios na LAN — uma "interface paralela à física" — mas o kernel entrega a
> ele apenas o tráfego destinado ao seu MAC, mais broadcast e multicast. Um IDS
> precisa do tráfego *dos outros*.

| perfil | como | custo |
|---|---|---|
| `sensor` | `network_mode: host` — vê todas as interfaces, inclusive uma promíscua no espelho do switch | sem isolamento de rede |
| `sensor-isolado` | `macvlan` em modo **passthru** — entrega a NIC inteira ao container | exige NIC dedicada |
| `replay` | lê um pcap | nenhuma captura |

Na máquina dedicada, o arranjo clássico são duas placas: `eth0` de gerência
(SSH, Grafana, banco) e `eth1` sem IP, promíscua, ligada ao espelho.

### Migrações

As migrações **não** são idempotentes (`001_init.sql` tem 13 `CREATE TABLE` sem
`IF NOT EXISTS`). Quem garante "aplica uma vez cada" é o `docker/migrar.py`,
via `na.schema_migrations`, com cada migração numa transação junto com o
próprio registro. Falha aborta o container de propósito: treinador rodando
contra esquema incerto grava dado que depois ninguém sabe interpretar.

O `search_path = na` é definido pela migração com `ALTER ROLE`. Sem ele o
Grafana conecta, autentica e não lista tabela nenhuma.

### Frontend planejado

Híbrido, não tudo no Grafana:

- **parâmetros** → *Business Forms panel* (`volkovlabs-form-panel`) dentro do
  Grafana. Fala com a API direto, sem iframe e sem desligar sanitização.
- **veredito do analista** → aplicação própria, na **mesma origem** via reverse
  proxy. É o fluxo de trabalho principal e a fonte de rótulo do sistema
  inteiro; não deve depender de plugin de terceiro.
- **gráficos e export** → Grafana nativo lendo Postgres.

Embutir a própria página via *Text panel* exigiria `disable_sanitize_html`, que
é **global** — qualquer um com permissão de editar dashboard passaria a poder
injetar HTML/JS em qualquer painel. Em ambiente de SOC isso é caminho de
escalação óbvio.

---

## 7. O que foi medido

Todos os números abaixo vêm de execução, não de estimativa.

### A explicabilidade não serve como gatilho de retreino

Fidelidade da árvore surrogate e recall real, medidos nos **mesmos** pools:

| regime | fidelidade (acur.) | f1 | recall bcn1h | bcn6h |
|---|---|---|---|---|
| pool limpo | 0.997 | 0.838 | 0.85 | 0.98 |
| pool **envenenado** (10% C2) | 0.996 | 0.780 | **0.00** | **0.01** |
| pool com deriva legítima | 0.997 | 0.827 | 0.70 | 0.92 |

A fidelidade se moveu um décimo de ponto percentual enquanto a detecção ia a
zero. A causa é estrutural: quando o C2 vira normal, a floresta para de
marcá-lo e a árvore reproduz esse silêncio com fidelidade perfeita. As duas
concordam em estar erradas.

E a queda de f1 causada pelo envenenamento (0.058) é **menor** que o desvio
entre dobras do modelo limpo (0.131) — não existe limiar que separe os dois
casos.

Portanto a validação do retreino tem de medir **detecção** (recall por
cenário), que é o que o portão faz.

### Orçamento do atacante contra o portão

Pool sintético de 120.000 fluxos, 5 sementes, injetando beacon-6h:

| dose C2 | n | bcn1h | bcn6h | Δ(1h) | portão |
|---|---|---|---|---|---|
| 0.00% | 0 | 0.891 | 0.984 | +0.000 | passa (base ±0.029) |
| 0.05% | 60 | 0.827 | 0.987 | −0.064 | **passa** — invisível |
| 0.10% | 120 | 0.645 | 0.976 | −0.246 | REPROVA |
| 0.30% | 360 | 0.159 | 0.948 | −0.732 | REPROVA |
| 1.00% | 1200 | 0.000 | 0.520 | −0.891 | REPROVA |

**O portão pega a partir de 0,10% do pool.** O orçamento invisível é ≈0,05%, e
mesmo ali o dano é real: 6 pontos de detecção perdidos.

Três consequências:

1. **O canário não é o cenário envenenado.** Injetando beacon de **6h**, quem
   morre é o de **1h** (0.891 → 0.005 em 0,5%), enquanto o de 6h só cai para
   0.860. Injetar qualquer tráfego de intervalo regular ensina "intervalo
   regular é normal", e cai primeiro o cenário mais próximo da fronteira de
   decisão. `recon` fica em 1.00 em toda a curva — varredura é imune.
   **Cobertura do golden set é cobertura da fronteira, não contagem de
   cenários.**
2. **O falso positivo melhora sob envenenamento** (0.0055 → 0.0005 em 1%). O
   modelo fica permissivo, o painel mostra menos alerta falso, e qualquer
   monitoramento por taxa de falso positivo reportaria melhora enquanto o
   detector cega.
3. **A checagem de delta relativo é catraca.** `v_gate_check` compara o
   candidato contra a produção *vigente*, que degrada junto. Um atacante em dose
   invisível tira ~6 pontos por retreino e cada passo passa; quem impede a
   acumulação é **só o piso absoluto**. O sangramento total disponível é
   exatamente `produção − piso`.

Logo, `golden_scenarios.recall_minimo` é **parâmetro de segurança**, não
detalhe de QA, e deve ficar próximo da base medida — não com margem
confortável.

Não vale apertar `gate_max_scenario_drop` de 0.10 para 0.05: o desvio da
diferença entre duas estimativas é ~0.041, então 0.05 fica a 1.2σ e daria ~11%
de reprovação espúria. O caminho é reduzir a **variância** do cenário canário.

### O Isolation Forest não detecta ataque de alto volume

Golden set real (FTP-Patator da terça do CIC-IDS-2017: 3.958 fluxos de ataque
contra 93.883 de fundo da mesma rede e horário), modelo treinado sobre 26.507
fluxos da mesma captura:

- **recall 0.00** contra o piso de 0.85 do cenário `brute_force`
- ROC-AUC 0.781, AP 0.0887 contra base 0.0405
- para **qualquer** recall o custo é **22% de falso positivo** — o limiar que
  pega 50% do ataque é o mesmo que pega 99% (0.4689 contra 0.4679)

As features *separam* bem (duração 147×, `std_iat` 68×, `mean_iat` 13×,
`n_packets` 7× contra a mediana benigna) — o problema não é o vetor de entrada.
É que 3.958 fluxos quase idênticos formam um **aglomerado denso**, e o Isolation
Forest isola pontos *raros*. Um ataque homogêneo e volumoso é, por construção,
normal para um método baseado em isolamento: quanto mais o atacante repete,
mais normal ele fica. O ranking resultante é *benigno atípico > ataque >
benigno típico*, e nenhum limiar separa.

É da mesma família do beacon de 6h: ataque cuja assinatura está na **repetição
ao longo do tempo**, não no fluxo individual. Não se resolve ajustando
`contamination`.

### Coerência entre `contamination` e o teto de falso positivo

Num pool majoritariamente limpo, o falso positivo tende ao valor de
`contamination` — é literalmente a fração que o modelo foi instruído a marcar.
Medido: 0.03 → 0.026; 0.01 → 0.006; 0.005 → 0.001.

Com `gate_max_fpr` abaixo de `contamination`, **nenhum** candidato passa,
nunca, e o sintoma parece degradação de modelo quando é aritmética. O
`lifecycle candidate` avisa quando isso acontece.

O portão delimita uma faixa utilizável estreita: 0.03 reprova por falso
positivo, 0.01 passa, 0.005 reprova porque o recall dos beacons desaba.

---

## 8. Estado da implementação

### Implementado e verificado

- extração de features (`scapy`, streaming, `nfstream`) nas duas visões
- treino do estágio 1 com peso de recência e limiar por quantil ponderado
- árvore surrogate embarcada no artefato
- rótulos do CIC-IDS-2017 pelo cronograma oficial, com tratamento de NAT
- esquema Postgres/TimescaleDB completo, com hypertable e retenção de 180 dias
- controlador de migração idempotente
- pool curado: quarentena, peso de recência normalizado, despejo, procedência
- golden set: registro manual e derivado do cronograma do CIC
- portão por cenário, com delta relativo, piso absoluto e teto de falso positivo
- promoção com troca atômica de artefato e registro da decisão
- sink: janelas para o pool e alertas para o banco, em duas cadências
- fila de retreino manual do analista
- containerização completa, sem root, com as três opções de captura
- Grafana com datasource provisionado

### Não implementado

| item | por que importa |
|---|---|
| **golden set real além de `brute_force`** | o portão só vê o que foi capturado, e a cobertura efetiva hoje é zero — o único cenário real está com recall 0.00 |
| **features de horizonte longo** | agregadas por par origem/destino ao longo de dias (regularidade de intervalo, jitter, razão up/down). É a causa do recall 0.00 e do beacon de 6h invisível |
| **marca de bootstrap** | quando a primeira janela de captura própria sair da quarentena, as janelas de 2017 somem do pool de uma vez, porque estão a ~3.400 dias de distância. Demonstrado |
| **estágio 2** | clusterização + hiperplano, alimentado por `verdicts` |
| **frontend** | painel do analista |
| **detector de deriva** | gatilho legítimo de retreino, para reduzir falso positivo |
| **visão `host` de ponta a ponta** | nunca testada; é provavelmente onde `brute_force` aparece |

### Ordem sugerida

1. Golden set real — pré-requisito de tudo o mais; sem rótulo positivo o falso
   negativo não é mensurável.
2. Visão `host` de ponta a ponta — barata, e pode resolver o `brute_force`.
3. Features de horizonte longo — maior retorno em falso negativo.
4. Marca de bootstrap — antes de colocar em produção.
5. Frontend.
6. Estágio 2.

---

## 9. Referências de operação

- `docker/README.md` — perfis do Compose, opções de captura, operação diária
- `scripts/teste_e2e.sh` — teste de ponta a ponta com os pcaps do CIC
- `scripts/gerar_sintetico.py` — pool e golden set sintéticos, para exercitar a
  lógica sem esperar extração
- `scripts/banco_dev.sh` — Postgres de desenvolvimento em container

**Aviso sobre os dados sintéticos:** as distribuições de
`scripts/gerar_sintetico.py` são inventadas. Os números que saem delas medem o
**código**, nunca o detector. Só golden set real mede detecção.
