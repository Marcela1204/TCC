# Estágio 2 — refinador supervisionado (preparação)

Documento de design. Escrito antes do código, para fixar decisões. 2026-09-11.

## 1. Qual é o trabalho do estágio 2

O estágio 1 (Isolation Forest) é **não supervisionado** e de propósito
**alto recall, baixa precisão**: marca muito, e o corte do analista filtra. Ele
tem um ponto cego estrutural — ataque de **volume homogêneo** (força bruta,
beacon denso) é um aglomerado que o isolamento trata como normal.

O estágio 2 é um classificador **supervisionado** que opera **só sobre os
alertas do estágio 1**, com dois objetivos:

1. **recuperar falso negativo** em formas de ataque já conhecidas — inclusive
   as que o estágio 1 é cego;
2. **reduzir falso positivo** — separar ataque real de anomalia benigna entre o
   que o estágio 1 marcou.

### Premissa validada

Nas mesmas features, mesmo dado, conjuntos de teste limpos:

| cenário | IF (não sup.) | SVM (sup.) |
|---|---|---|
| recon | 0.36 | 1.00 |
| beacon_6h | 0.08 | 1.00 |
| **brute_force** | **0.00** | **1.00** |
| falso positivo | 0.001 | 0.000 |

O supervisionado recupera o cluster denso que o IF não vê. **Mas** só acerta a
forma de ataque que **já viu rotulada** — ataque novo continua com o estágio 1.
Por isso é um pipeline complementar, não uma troca.

## 2. Fluxo de dados

```
   estágio 1 --alertas--> na.alerts
                             │
              (aplica modelo estágio 2 promovido)
                             │
                             v
                   na.stage2_assignments   (predição + decision_value/margin)
                             │
                   v_fila_stage2 (ordenada por margem crescente)
                             │
                        analista revisa
                             │
                             v
                        na.verdicts  --rótulo--> treino do próximo estágio 2
                             ^                              │
                             └───── refina o hiperplano ───┘
```

O laço se fecha: predição → fila priorizada → veredito → retreino → predição
melhor. É *active learning* — a fila mostra primeiro os casos de menor margem,
onde o veredito mais move a fronteira.

## 3. Decisões de design

Marcadas **[definir]** as que precisam da sua palavra antes do código.

### D1. Features — os 17 + o score do estágio 1
Reusa `FEATURE_COLS` (já em `alerts.features`) mais `alerts.score`. Não o
percentil (redundante com o score). Recomendação, baixa polêmica.

### D2. Partida a frio dos rótulos **[definir]**
Hoje há **0 vereditos**. Sem rótulo não há hiperplano. É o mesmo problema do
golden set no estágio 1. Opções:
- **(a) bootstrap pelo golden set** — ele já é ataque/benigno rotulado. Treina o
  primeiro hiperplano, depois refina com vereditos ao vivo. *Recomendada.*
- **(b) rotulagem assistida por cluster** — clusteriza os alertas, o analista
  rotula o cluster inteiro em vez de ponto a ponto. Barato, mas exige UI.
- **(c) esperar vereditos acumularem** — nada funciona até lá.
Recomendo (a) agora, (b) quando houver frontend.

### D3. Papel da clusterização
A descrição do projeto diz "clusteriza e traça o hiperplano". A clusterização
**não** dá `decision_value` — então ela é **apoio de rotulagem** (agrupar para o
analista rotular em lote), e o classificador promovido é o **SVM/logística**,
que dá a distância com sinal que `stage2_assignments.margin` espera. O schema já
aceita `hdbscan` como kind se quisermos registrar o clusterizador como
sub-modelo.

### D4. Predição por-alerta, treino em lote
- **predição:** aplica o SVM promovido a cada alerta novo → grava
  `stage2_assignments`. Rápido, no caminho do sink ou logo após.
- **treino:** reusa o ciclo do estágio 1 — `candidate → gate → promote` em
  `stage2.py`. O **portão** do estágio 2 mede precisão/recall contra **vereditos
  retidos** (não contra o golden set), com validação temporal (treina no
  passado, testa no futuro) para não inflar com vazamento.

### D5. Operacional: anotar, não suprimir **[definir]**
O estágio 2 pode (a) **anotar** cada alerta com sua predição e reordenar a fila,
ou (b) **suprimir** automaticamente o que julga benigno. Recomendo começar em
(a): suprimir cria falso negativo silencioso, e um estágio 2 recém-treinado com
poucos vereditos erra. Suprimir vira opção depois, atrás de portão e com piso de
recall — decisão sua.

### D6. Layout de código
- `stage2.py` — espelha `lifecycle.py`: `train` (candidato), `evaluate`, `gate`,
  `promote`, e `predict` (aplica aos alertas → fila).
- `verdict` — CLI para o analista submeter veredito (`na.verdicts`), com a
  cadeia `supersedes` para revisão. Frontend depois.
- migração `003` se o schema precisar de ajuste (ver §5).

## 4. Partida a frio — o bloqueador honesto

Igual ao estágio 1: **sem rótulo, o estágio 2 não mede nada**. O golden set
(D2a) destrava o primeiro treino, mas a qualidade real depende de vereditos
acumulando — que só vêm do uso. O primeiro hiperplano será fraco e melhora com o
tempo. Isso é esperado e deve ser dito no TCC, não escondido.

## 5. O que falta checar no schema antes de codar

- `stage2_assignments` referencia `model_id` e guarda `decision_value`/`margin`
  — ok para SVM.
- `models` com `stage=2` e o índice `models_um_promovido` já separa produção por
  estágio — ok, um SVM promovido por vez.
- **A definir:** o portão (`v_gate_check`) hoje lê `golden_scenarios`. O estágio
  2 precisa de um portão próprio contra vereditos retidos — provável migração
  `003` com uma view nova, sem tocar na do estágio 1.

## 6. Ordem de implementação proposta

1. `verdict` CLI + confirmar a gravação em `na.verdicts` (a matéria-prima).
2. `stage2.py train` bootstrap pelo golden set → SVM promovido (stage=2).
3. `stage2.py predict` → popula `stage2_assignments` a partir de `na.alerts`.
4. portão do estágio 2 (migração 003) + `evaluate`/`gate`/`promote`.
5. refino: consumir vereditos da fila e retreinar.
6. frontend (fila + submissão de veredito) — junto da frente de frontend.

## 7. Decisões que preciso de você

- **D2** — bootstrap pelo golden set agora? (recomendo sim)
- **D5** — anotar apenas, sem suprimir, na primeira versão? (recomendo sim)

Com essas duas, começo pela ordem acima (passo 1: `verdict` + gravação).
