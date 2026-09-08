#!/usr/bin/env python3
"""
lifecycle.py -- rotacao do pool de janelas e retreino do Isolation Forest.

Este e o modulo que decide QUAIS ARQUIVOS entram no treino do detector, e
retreina a partir deles. Ele nao serve o trafego ao vivo (isso e
netanomaly_live.py) nem extrai features (isso e netanomaly.py); ele so
administra o ciclo de vida do modelo.

TRES RELOGIOS SEPARADOS
-----------------------
O ponto inteiro deste arquivo e que essas tres coisas tem cadencias
diferentes e NAO devem virar um loop so:

    surrogate / explicabilidade   a cada janela     automatico
    candidato + avaliacao         diario            automatico (so treina e mede)
    promocao para producao        semanal/sob demanda   NUNCA automatico -- portao

POR QUE O POOL E CURADO E NAO DESLIZANTE
----------------------------------------
Retreinar na janela mais recente AUMENTA falso negativo. O Isolation Forest
aprende "normal" = a massa dos dados que recebeu; se a janela contem ataque,
o ataque vira parte do normal aprendido e deixa de ser marcado na proxima
janela. Pior, e exploravel de forma gradual: um C2 com beacon de 6h e
absorvido um pouco mais no baseline a cada retreino, e em duas semanas o
canal fica indistinguivel de normal. O atacante nao precisa evadir nada, so
precisa ser paciente.

Por isso o detector nunca treina numa janela so. Ele treina num POOL CURADO:

    quarentena   uma janela so entra depois de N dias sem IOC retroativo
    despejo      descoberto comprometimento depois, a janela sai e o modelo
                 e retreinado sem ela -- impossivel num modelo incremental
    recencia     peso com meia-vida, para acompanhar mudanca legitima de
                 trafego sem descartar historico

O que o dado recente compra de verdade e reducao de FALSO POSITIVO (servidor
novo, mudanca de horario de backup, novo range de IP). Isso reduz fadiga do
analista, e so por esse caminho indireto ajuda o falso negativo.

Uso:
    # ver o que entraria no treino agora, e com que peso
    ./lifecycle.py pool --view flow

    # alimentar o pool a partir de um pcap
    ./lifecycle.py extract --pcap captura.pcap --sensor eth0 --view flow

    # relogio diario: treina candidato e mede. NAO promove.
    ./lifecycle.py candidate --view flow

    # ler o portao antes de decidir
    ./lifecycle.py gate --model <uuid>

    # promocao: passa pelo portao ou exige --force com motivo
    ./lifecycle.py promote --model <uuid> --by lucas

    # IOC retroativo: despeja janelas e mostra quem ficou contaminado
    ./lifecycle.py evict --windows 20260812T0300Z-flow --reason "C2 no .47, INC-441"

    # consumir o botao de retreino do analista
    ./lifecycle.py requests --view flow

Banco: variavel NETANOMALY_DSN, ou --dsn.
Requisitos: psycopg[binary], pyarrow, alem do que netanomaly.py ja pede.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

DSN_PADRAO = os.environ.get("NETANOMALY_DSN", "postgresql:///netanomaly")
POOL_PADRAO = Path(os.environ.get("NETANOMALY_POOL", "/var/lib/netanomaly"))


# ----------------------------------------------------------------------------
# 1. Banco
# ----------------------------------------------------------------------------

def conectar(dsn):
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(dsn, row_factory=dict_row)
    with conn.cursor() as cur:
        cur.execute("SET search_path = na, public")
    return conn


def parametro(cur, chave):
    """Le um parametro operacional. Nunca embutir esses valores em constante:
    o analista mexe neles pelo painel e o codigo tem de enxergar a mudanca."""
    cur.execute("SELECT na.param_num(%s) AS v", (chave,))
    v = cur.fetchone()["v"]
    if v is None:
        raise SystemExit(f"[!] parametro ausente em na.parameters: {chave}")
    return float(v)


def sha256(caminho, bloco=1 << 20):
    h = hashlib.sha256()
    with open(caminho, "rb") as fo:
        for pedaco in iter(lambda: fo.read(bloco), b""):
            h.update(pedaco)
    return h.hexdigest()


# ----------------------------------------------------------------------------
# 2. Selecao do pool
# ----------------------------------------------------------------------------

def selecionar_pool(cur, visao, peso_minimo):
    """Janelas elegiveis AGORA, com o peso de recencia NORMALIZADO.

    A view na.v_training_pool ja aplica quarentena e exclui despejadas, e
    calcula o peso contra now(). Aqui esse peso e renormalizado para que a
    janela mais recente DO POOL valha 1.0.

    Sem isso o modulo nao roda sobre captura historica: o CIC-IDS-2017 e de
    julho de 2017, o que da peso ~1e-64 contra now(), e todo o pool cairia no
    corte de `peso_minimo`. So a razao entre pesos importa para o fit, entao
    normalizar nao muda nada no uso ao vivo e torna o historico utilizavel.

    Com a normalizacao, `peso_minimo` passa a significar "pelo menos 5% do
    peso da janela mais nova do pool" -- 4.3 meias-vidas contadas a partir
    dela, e nao de hoje. E a semantica mais util das duas.
    """
    cur.execute(
        """
        SELECT window_id, path, n_rows, feature_set, feature_cols,
               t_start, t_end, peso_recencia
        FROM na.v_training_pool
        WHERE visao = %s
        ORDER BY t_end DESC
        """,
        (visao,),
    )
    janelas = cur.fetchall()
    if not janelas:
        return []

    # a mais recente do pool vira a referencia
    maior = max(float(j["peso_recencia"]) for j in janelas)
    if maior <= 0:
        # todas tao antigas que o peso zerou em ponto flutuante: cai para
        # peso uniforme em vez de devolver pool vazio.
        print("[!] pool inteiro fora do alcance da meia-vida; usando peso "
              "uniforme. Confira recency_halflife_days.", file=sys.stderr)
        for j in janelas:
            j["peso_recencia"] = 1.0
        return janelas

    mantidas = []
    for j in janelas:
        j["peso_recencia"] = float(j["peso_recencia"]) / maior
        if j["peso_recencia"] >= peso_minimo:
            mantidas.append(j)
    return mantidas


def homogeneizar(janelas):
    """Recusa misturar feature_set. Treinar sobre colunas de contratos
    diferentes produz um modelo cujo vetor de entrada nao existe em lugar
    nenhum -- falha silenciosa, que e o pior tipo."""
    if not janelas:
        return [], None
    conjuntos = {}
    for j in janelas:
        conjuntos.setdefault(j["feature_set"], []).append(j)

    # o contrato dominante e o da janela mais recente
    fs_atual = janelas[0]["feature_set"]
    mantidas = conjuntos[fs_atual]

    for fs, grupo in conjuntos.items():
        if fs != fs_atual:
            print(f"[!] ignorando {len(grupo)} janela(s) de feature_set='{fs}' "
                  f"(atual e '{fs_atual}'); reprocesse-as para reaproveitar",
                  file=sys.stderr)
    return mantidas, fs_atual


# ----------------------------------------------------------------------------
# 3. Montagem da matriz de treino
# ----------------------------------------------------------------------------

def _ler_amostra(caminho, colunas, n_take, semente):
    """Le no maximo n_take linhas do parquet sem carregar o arquivo inteiro.

    Percorre por row group e tira uma fatia proporcional de cada um, entao o
    pico de memoria e o tamanho de UM row group, nao o do arquivo. Amostra
    sistematica ao longo do arquivo, e nao as primeiras n linhas: um parquet
    de janela esta ordenado por tempo, e pegar do inicio traria so o comeco
    da janela.
    """
    import pyarrow.parquet as pq

    pf = pq.ParquetFile(caminho)
    total = pf.metadata.num_rows
    if total == 0:
        return None
    if n_take >= total:
        return pf.read(columns=colunas).to_pandas()

    frac = n_take / total
    partes, obtidos = [], 0
    for i in range(pf.num_row_groups):
        if obtidos >= n_take:
            break
        rg = pf.read_row_group(i, columns=colunas).to_pandas()
        k = min(len(rg), int(round(len(rg) * frac)), n_take - obtidos)
        if k > 0:
            partes.append(rg.sample(n=k, random_state=semente + i))
            obtidos += k
        del rg
    return pd.concat(partes, ignore_index=True) if partes else None


def montar_matriz(janelas, feature_cols, max_rows, semente=42):
    """Le os parquets do pool e devolve (X, pesos, procedencia).

    DOIS MECANISMOS COM PAPEIS SEPARADOS -- confundi-los aplica a recencia
    duas vezes:

      amostragem     decide QUANTAS linhas ler de cada janela. Proporcional
                     ao tamanho da janela, para a amostra continuar
                     representativa. So existe para limitar memoria.

      sample_weight  carrega a recencia para dentro do fit. E aqui, e SO
                     aqui, que a meia-vida atua.
    """
    total_disponivel = sum(int(j["n_rows"]) for j in janelas)
    if total_disponivel == 0:
        raise SystemExit("[!] pool vazio: nenhuma linha nas janelas elegiveis")

    fator = min(1.0, max_rows / total_disponivel)
    blocos, pesos, procedencia = [], [], []

    for j in janelas:
        n_take = max(1, int(round(int(j["n_rows"]) * fator)))
        df = _ler_amostra(j["path"], feature_cols, n_take, semente)
        if df is None or len(df) == 0:
            print(f"[!] janela {j['window_id']} nao rendeu linhas; pulando",
                  file=sys.stderr)
            continue
        faltando = [c for c in feature_cols if c not in df.columns]
        if faltando:
            raise SystemExit(
                f"[!] {j['path']} nao tem as colunas {faltando}. "
                f"feature_set do banco nao corresponde ao arquivo.")
        blocos.append(df[feature_cols])
        pesos.append(np.full(len(df), float(j["peso_recencia"])))
        procedencia.append((j["window_id"], len(df), float(j["peso_recencia"])))

    if not blocos:
        raise SystemExit("[!] nenhuma janela do pool pode ser lida")

    X = pd.concat(blocos, ignore_index=True)
    X = X.fillna(0.0).replace([np.inf, -np.inf], 0.0).values.astype(float)
    w = np.concatenate(pesos)
    return X, w, procedencia


def _cdf_ponderada(valores, pesos):
    """Distribuicao acumulada ponderada: (score ordenado, posicao 0..1)."""
    ordem = np.argsort(valores)
    v, p = np.asarray(valores)[ordem], np.asarray(pesos)[ordem]
    acumulado = (np.cumsum(p) - 0.5 * p) / np.sum(p)
    return v, acumulado


def quantil_ponderado(valores, q, pesos):
    """Quantil que respeita o peso de recencia.

    netanomaly.detect() usa np.quantile simples porque la todas as linhas
    valem igual. Aqui nao valem: uma linha de 30 dias atras pesa 0.23 de uma
    de hoje. Usar o quantil simples faria o limiar responder a linhas que o
    modelo mal usou -- o limiar diria uma coisa e o fit teria feito outra.
    """
    v, acumulado = _cdf_ponderada(valores, pesos)
    return float(np.interp(q, acumulado, v))


def grade_de_referencia(valores, pesos, n=1001):
    """Grade de quantis do score no TREINO, para o sink converter score em
    percentil sem depender da janela em que o fluxo caiu.

    Percentil relativo a janela e uma armadilha: numa janela de 13 minutos sem
    nenhum ataque, o "1% mais anomalo" e trafego perfeitamente normal, e o
    corte do analista produziria alerta por construcao. Contra a grade do
    treino, uma janela tranquila simplesmente nao gera alerta -- que e o
    comportamento correto.

    Congelada no artefato: assim o mesmo score da o mesmo percentil hoje e
    daqui a um mes, e alertas de janelas diferentes sao comparaveis.
    """
    v, acumulado = _cdf_ponderada(valores, pesos)
    grade = np.linspace(0.0, 1.0, n)
    return {"percentil": grade.tolist(),
            "score": np.interp(grade, acumulado, v).tolist()}


# ----------------------------------------------------------------------------
# 4. Treino do candidato
# ----------------------------------------------------------------------------

def treinar(X, pesos, feature_cols, visao, contamination, tree_depth,
            random_state=42, n_jobs=-1):
    """Treina scaler + Isolation Forest + arvore surrogate, ponderados.

    O bundle sai no MESMO formato que netanomaly.save_model() grava e que
    netanomaly_live.load_model() consome -- mesmas chaves, mesma semantica de
    limiar. Trocar o formato aqui quebraria o analisador ao vivo sem aviso.

    Convencao de sinal, identica a netanomaly.py: score = -score_samples,
    entao MAIOR = MAIS ANOMALO.

    A arvore treina no X CRU e o IF no X ESCALADO, tambem como em
    netanomaly.detect() -- a explicacao precisa sair em unidade que o analista
    reconheca ("n_dports > 50"), nao em desvios-padrao.
    """
    import sklearn
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier, export_text

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X, sample_weight=pesos)

    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=n_jobs,
    )
    iso.fit(Xs, sample_weight=pesos)

    scores = -iso.score_samples(Xs)
    threshold = quantil_ponderado(scores, 1.0 - contamination, pesos)
    rotulo = (scores >= threshold).astype(int)

    tree, tree_rules = None, None
    if len(np.unique(rotulo)) == 2:
        tree = DecisionTreeClassifier(max_depth=tree_depth,
                                      random_state=random_state)
        tree.fit(X, rotulo, sample_weight=pesos)
        tree_rules = export_text(tree, feature_names=list(feature_cols))

    bundle = {
        "kind": visao,
        "scaler": scaler,
        "iso": iso,
        "tree": tree,
        "feature_cols": list(feature_cols),
        "threshold": threshold,
        "contamination": contamination,
        "tree_depth": tree_depth,
        "sklearn_version": sklearn.__version__,
        # o sink usa isto para converter score em percentil (ver sink.py)
        "score_quantis": grade_de_referencia(scores, pesos),
    }
    return bundle, tree_rules, scores, rotulo


# ----------------------------------------------------------------------------
# 5. Avaliacao no golden set
# ----------------------------------------------------------------------------

def avaliar_golden(cur, bundle, visao):
    """Mede o candidato contra as capturas rotuladas.

    O golden set e o PRE-REQUISITO de tudo: sem rotulo positivo real, falso
    negativo nao e mensuravel e nenhum numero deste arquivo significa nada.
    As capturas sao de pentest do proprio time -- varredura, brute force,
    exfil, beacon -- filtradas ao host alvo, e por isso o rotulo vale para a
    captura inteira.
    """
    cur.execute(
        """
        SELECT capture_id, scenario, label, parquet_path, feature_set
        FROM na.golden_captures WHERE visao = %s ORDER BY scenario, capture_id
        """,
        (visao,),
    )
    capturas = cur.fetchall()
    if not capturas:
        print("[!] golden set VAZIO. Sem ele o portao nao mede nada e "
              "promocao vira aposta.", file=sys.stderr)
        return []

    cols = bundle["feature_cols"]
    limiar = bundle["threshold"]
    por_captura = []

    for c in capturas:
        if c["feature_set"] != bundle.get("_feature_set"):
            print(f"[!] {c['capture_id']}: feature_set '{c['feature_set']}' "
                  f"difere do modelo ('{bundle.get('_feature_set')}'); pulando",
                  file=sys.stderr)
            continue
        try:
            df = pd.read_parquet(c["parquet_path"], columns=cols)
        except Exception as e:
            print(f"[!] {c['capture_id']}: {e}", file=sys.stderr)
            continue
        if len(df) == 0:
            continue

        X = df.fillna(0.0).replace([np.inf, -np.inf], 0.0).values.astype(float)
        scores = -bundle["iso"].score_samples(bundle["scaler"].transform(X))
        pred = (scores >= limiar).astype(int)
        n = len(pred)
        n_pos = int(pred.sum())

        if c["label"] == 1:
            tp, fn, fp, tn = n_pos, n - n_pos, 0, 0
        else:                                   # controle benigno
            tp, fn, fp, tn = 0, 0, n_pos, n - n_pos

        por_captura.append({
            "capture_id": c["capture_id"], "scenario": c["scenario"],
            "n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "n_ataque_real": n if c["label"] == 1 else 0,
        })

    # agrega por cenario e no total
    linhas = list(por_captura)
    for chave in ("scenario", None):
        grupos = {}
        for r in por_captura:
            g = r["scenario"] if chave else "__all__"
            acc = grupos.setdefault(g, {"n": 0, "tp": 0, "fp": 0, "fn": 0,
                                        "tn": 0, "n_ataque_real": 0})
            for k in acc:
                acc[k] += r[k]
        for g, acc in grupos.items():
            linhas.append({**acc,
                           "scenario": g if chave else None,
                           "capture_id": None,
                           "_scope": "scenario" if chave else "aggregate"})
    for r in linhas:
        r.setdefault("_scope", "capture")
    return linhas


# ----------------------------------------------------------------------------
# 6. Registro no banco
# ----------------------------------------------------------------------------

def registrar_candidato(cur, bundle, caminho_artefato, janelas, procedencia,
                        feature_set, stage, visao, avaliacoes, notas):
    cur.execute(
        """
        INSERT INTO na.models
            (stage, kind, visao, artifact_path, artifact_sha256, sklearn_version,
             feature_set, feature_cols, hyperparams, threshold, contamination,
             status, notes)
        VALUES (%s,'isolation_forest',%s,%s,%s,%s,%s,%s,%s,%s,%s,'candidate',%s)
        RETURNING model_id
        """,
        (stage, visao, str(caminho_artefato), sha256(caminho_artefato),
         bundle["sklearn_version"], feature_set, bundle["feature_cols"],
         json.dumps({"n_estimators": 200, "tree_depth": bundle["tree_depth"]}),
         bundle["threshold"], bundle["contamination"], notas),
    )
    model_id = cur.fetchone()["model_id"]

    # A procedencia e o que torna o despejo auditavel: sem ela, saber que uma
    # janela estava contaminada nao diz QUAIS modelos a absorveram.
    cur.executemany(
        "INSERT INTO na.model_training_windows (model_id, window_id, weight) "
        "VALUES (%s,%s,%s)",
        [(model_id, w, peso) for (w, _n, peso) in procedencia],
    )

    for a in avaliacoes:
        cur.execute(
            """
            INSERT INTO na.model_evaluations
                (model_id, scope, scenario, capture_id, threshold,
                 n, n_ataque_real, tp, fp, fn, tn)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (model_id, a["_scope"], a.get("scenario"), a.get("capture_id"),
             bundle["threshold"], a["n"], a["n_ataque_real"],
             a["tp"], a["fp"], a["fn"], a["tn"]),
        )
    return model_id


# ----------------------------------------------------------------------------
# 7. Portao
# ----------------------------------------------------------------------------

def ler_portao(cur, model_id):
    cur.execute(
        """
        SELECT scenario, obrigatorio, recall_candidato, recall_producao,
               delta, recall_minimo, taxa_falso_positivo, reprova
        FROM na.v_gate_check WHERE candidate_model_id = %s ORDER BY scenario
        """,
        (model_id,),
    )
    detalhe = cur.fetchall()
    cur.execute(
        """
        SELECT incumbent_model_id, cenarios_avaliados, cenarios_reprovados,
               pior_delta, aprovado
        FROM na.v_gate_verdict WHERE candidate_model_id = %s
        """,
        (model_id,),
    )
    return detalhe, cur.fetchone()


def imprimir_portao(detalhe, veredito):
    if not detalhe:
        print("  (sem avaliacao por cenario -- golden set vazio?)")
        return
    print(f"  {'cenario':<14}{'cand':>7}{'prod':>7}{'delta':>8}"
          f"{'min':>7}{'fpr':>8}  ")
    for d in detalhe:
        f = lambda v, p=".2f": "     -" if v is None else format(v, p)
        marca = "REPROVA" if d["reprova"] else ""
        print(f"  {d['scenario']:<14}{f(d['recall_candidato']):>7}"
              f"{f(d['recall_producao']):>7}{f(d['delta'],'+.2f'):>8}"
              f"{f(d['recall_minimo']):>7}{f(d['taxa_falso_positivo'],'.3f'):>8}"
              f"  {marca}")
    if veredito:
        print(f"\n  {veredito['cenarios_reprovados']}/"
              f"{veredito['cenarios_avaliados']} cenario(s) reprovado(s) -> "
              f"{'APROVADO' if veredito['aprovado'] else 'REPROVADO'}")


# ----------------------------------------------------------------------------
# 8. Comandos
# ----------------------------------------------------------------------------

def cmd_pool(conn, args):
    with conn.cursor() as cur:
        meia_vida = parametro(cur, "recency_halflife_days")
        quarentena = parametro(cur, "quarantine_days")
        janelas = selecionar_pool(cur, args.view, args.peso_minimo)

        cur.execute(
            "SELECT count(*) AS n FROM na.feature_windows "
            "WHERE visao=%s AND pool_state='evicted'", (args.view,))
        n_desp = cur.fetchone()["n"]

    print(f"pool '{args.view}': quarentena {quarentena:.0f}d, "
          f"meia-vida {meia_vida:.0f}d, peso minimo {args.peso_minimo}")
    if not janelas:
        print("  vazio -- nenhuma janela saiu da quarentena ainda")
        return
    print(f"  {'janela':<28}{'linhas':>12}{'peso':>8}   ate")
    total = 0
    for j in janelas:
        total += int(j["n_rows"])
        print(f"  {j['window_id']:<28}{int(j['n_rows']):>12,}"
              f"{float(j['peso_recencia']):>8.4f}   {j['t_end']:%Y-%m-%d %H:%M}")
    print(f"  {'':<28}{total:>12,} linhas em {len(janelas)} janela(s)")
    if n_desp:
        print(f"  ({n_desp} janela(s) despejada(s), fora do pool)")


def cmd_extract(conn, args):
    """pcap -> janelas parquet no pool -> linhas em na.feature_windows."""
    import netanomaly as na

    with conn.cursor() as cur:
        janela_s = parametro(cur, "window_seconds")

    t0 = time.time()
    print(f"[+] extraindo {args.pcap} via nfstream...")
    df_flow, df_host = na.from_nfstream(args.pcap)
    df = df_flow if args.view == "flow" else df_host
    cols = na.FEATURE_COLS if args.view == "flow" else na.HOST_FEATURE_COLS
    print(f"[+] {len(df)} linhas em {time.time()-t0:.1f}s")

    if len(df) == 0 or "t0" not in df.columns:
        raise SystemExit("[!] extracao nao produziu linhas com coluna t0")

    destino = POOL_PADRAO / "pool" / args.sensor / args.view
    destino.mkdir(parents=True, exist_ok=True)

    # Fatia por tempo de pacote, nao por contagem: a janela precisa ter
    # significado temporal para a quarentena e o despejo por incidente
    # poderem se referir a ela.
    balde = (df["t0"] // janela_s).astype("int64")
    gravadas = 0

    with conn.cursor() as cur:
        for b, parte in df.groupby(balde):
            ini, fim = float(b) * janela_s, (float(b) + 1) * janela_s
            marca = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ini))
            window_id = f"{marca}-{args.sensor}-{args.view}"
            caminho = destino / f"{marca}.parquet"

            cur.execute("SELECT 1 FROM na.feature_windows WHERE window_id=%s",
                        (window_id,))
            if cur.fetchone():
                print(f"    {window_id}: ja registrada, pulando")
                continue

            parte.to_parquet(caminho, index=False)
            cur.execute(
                """
                INSERT INTO na.feature_windows
                    (window_id, visao, sensor, t_start, t_end, path, sha256,
                     n_rows, bytes_on_disk, feature_set, feature_cols, extractor)
                VALUES (%s,%s,%s, to_timestamp(%s), to_timestamp(%s), %s,%s,
                        %s,%s,%s,%s,'nfstream')
                """,
                (window_id, args.view, args.sensor, ini, fim, str(caminho),
                 sha256(caminho), len(parte), caminho.stat().st_size,
                 args.feature_set, list(cols)),
            )
            gravadas += 1
    conn.commit()
    print(f"[+] {gravadas} janela(s) gravada(s) em {destino}")


def cmd_golden(conn, args):
    """Registra uma captura no golden set.

    Sem golden set nao existe rotulo positivo real, falso negativo nao e
    mensuravel e o portao nao mede nada -- promocao vira aposta. Este comando
    e o caminho para transformar uma captura de pentest em rotulo.

    Dois modos:

      manual    voce diz o cenario e o rotulo. Para captura sua, filtrada ao
                alvo (`tcpdump host 10.0.0.5`), onde a captura inteira e o
                ataque.

      --cicids  o rotulo vem do cronograma oficial do CIC-IDS-2017 ja embutido
                em netanomaly.py: um fluxo e ataque quando cai na janela de
                tempo E o par de enderecos bate com atacante/vitima. A captura
                e dividida em duas -- os fluxos de ataque e o trafego de fundo
                do mesmo periodo, que vira controle benigno. Esse controle e
                melhor que trafego sintetico: e a mesma rede, mesmo horario.
    """
    import netanomaly as na

    print(f"[+] extraindo {args.pcap} via nfstream...")
    t0 = time.time()
    df_flow, df_host = na.from_nfstream(args.pcap)
    df = df_flow if args.view == "flow" else df_host
    cols = na.FEATURE_COLS if args.view == "flow" else na.HOST_FEATURE_COLS
    print(f"[+] {len(df)} linhas em {time.time()-t0:.1f}s")
    if len(df) == 0:
        raise SystemExit("[!] a captura nao produziu linhas")

    destino = POOL_PADRAO / "golden"
    destino.mkdir(parents=True, exist_ok=True)
    base = args.capture_id or Path(args.pcap).stem

    if args.cicids:
        if args.view != "flow":
            raise SystemExit("[!] --cicids so vale para --view flow: o rotulo "
                             "casa par origem/destino num instante, e a visao "
                             "de host agrega a captura inteira")
        janelas = na.compilar_cronograma()
        rotulos = np.array([
            1 if na.rotular_fluxo(t, a, b, janelas) else 0
            for t, a, b in zip(df["t0"], df["src"], df["dst"])
        ])
        n_atq = int(rotulos.sum())
        print(f"[+] cronograma CIC: {n_atq}/{len(df)} fluxos de ataque "
              f"({100*n_atq/len(df):.2f}%)")
        if n_atq == 0:
            raise SystemExit("[!] nenhum fluxo de ataque na janela de tempo "
                             "desta captura -- confira o recorte")
        partes = [(f"{base}-ataque", args.scenario, 1, df[rotulos == 1]),
                  (f"{base}-benigno", "benigno",    0, df[rotulos == 0])]
    else:
        partes = [(base, args.scenario, args.label, df)]

    with conn.cursor() as cur:
        for cid, cenario, rotulo, parte in partes:
            if len(parte) == 0:
                continue
            caminho = destino / f"{cid}.parquet"
            parte[[c for c in cols if c in parte.columns]].to_parquet(
                caminho, index=False)
            cur.execute(
                """INSERT INTO na.golden_captures
                   (capture_id, scenario, label, visao, pcap_path, parquet_path,
                    sha256, n_rows, feature_set, ferramenta, descricao)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (capture_id) DO UPDATE SET
                     parquet_path=EXCLUDED.parquet_path, n_rows=EXCLUDED.n_rows,
                     sha256=EXCLUDED.sha256""",
                (cid, cenario, rotulo, args.view, args.pcap, str(caminho),
                 sha256(caminho), len(parte), args.feature_set,
                 args.ferramenta, args.descricao))
            print(f"    {cid:<28} {cenario:<12} label={rotulo}  "
                  f"{len(parte):>8,} linhas")
    conn.commit()


def cmd_golden_list(conn, args):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT gs.scenario, gs.obrigatorio, gs.recall_minimo,
                   count(gc.capture_id) AS n_capturas,
                   coalesce(sum(gc.n_rows),0) AS linhas
            FROM na.golden_scenarios gs
            LEFT JOIN na.golden_captures gc ON gc.scenario = gs.scenario
            GROUP BY 1,2,3 ORDER BY 1""")
        linhas = cur.fetchall()
    print(f"  {'cenario':<14}{'obrig':>7}{'min':>7}{'capturas':>10}{'linhas':>12}")
    for r in linhas:
        rm = "  -" if r["recall_minimo"] is None else f"{r['recall_minimo']:.2f}"
        marca = "  <- SEM CAPTURA" if r["n_capturas"] == 0 and r["obrigatorio"] else ""
        print(f"  {r['scenario']:<14}{str(r['obrigatorio']):>7}{rm:>7}"
              f"{r['n_capturas']:>10}{int(r['linhas']):>12,}{marca}")


def cmd_candidate(conn, args):
    import joblib

    with conn.cursor() as cur:
        contamination = args.contamination

        # Armadilha de configuracao: num pool majoritariamente limpo, a taxa de
        # falso positivo do detector sobre trafego benigno tende a
        # `contamination` -- e literalmente a fracao que ele foi instruido a
        # marcar. Com gate_max_fpr abaixo disso, NENHUM candidato passa, nunca,
        # e o sintoma e uma fila de reprovacoes que parece problema de modelo
        # quando e aritmetica.
        teto_fpr = parametro(cur, "gate_max_fpr")
        if teto_fpr < contamination:
            print(f"[!] gate_max_fpr={teto_fpr:.3f} < contamination="
                  f"{contamination:.3f}: o portao vai reprovar por falso "
                  f"positivo sempre. Baixe contamination ou suba o parametro.",
                  file=sys.stderr)

        janelas = selecionar_pool(cur, args.view, args.peso_minimo)
        if not janelas:
            raise SystemExit("[!] pool vazio: nada saiu da quarentena ainda")
        janelas, feature_set = homogeneizar(janelas)
        feature_cols = list(janelas[0]["feature_cols"])

        print(f"[+] pool: {len(janelas)} janela(s), "
              f"{sum(int(j['n_rows']) for j in janelas):,} linhas disponiveis")

        X, pesos, procedencia = montar_matriz(
            janelas, feature_cols, args.max_rows, args.seed)
        print(f"[+] matriz de treino: {X.shape[0]:,} x {X.shape[1]} "
              f"(peso efetivo {pesos.sum():,.0f})")

        t0 = time.time()
        bundle, regras, scores, rotulo = treinar(
            X, pesos, feature_cols, args.view, contamination,
            args.tree_depth, args.seed, args.n_jobs)
        bundle["_feature_set"] = feature_set
        print(f"[+] treinado em {time.time()-t0:.1f}s  "
              f"threshold={bundle['threshold']:.4f}  "
              f"anomalos no treino={int(rotulo.sum()):,}")

        avaliacoes = avaliar_golden(cur, bundle, args.view)

        destino = POOL_PADRAO / "models"
        destino.mkdir(parents=True, exist_ok=True)
        nome = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_{args.view}.joblib"
        caminho = destino / nome
        salvavel = {k: v for k, v in bundle.items() if not k.startswith("_")}
        joblib.dump(salvavel, caminho)

        model_id = registrar_candidato(
            cur, bundle, caminho, janelas, procedencia, feature_set,
            args.stage, args.view, avaliacoes, args.notes)
    conn.commit()

    print(f"[+] candidato {model_id}")
    print(f"    artefato: {caminho}")
    if regras and args.rules:
        print("\n[+] regras da arvore surrogate (explicacao, NAO deteccao):")
        print(regras)

    with conn.cursor() as cur:
        detalhe, veredito = ler_portao(cur, model_id)
    print("\n[+] portao:")
    imprimir_portao(detalhe, veredito)
    print(f"\n    NAO promovido. Para promover: "
          f"./lifecycle.py promote --model {model_id} --by SEU_NOME")


def cmd_gate(conn, args):
    with conn.cursor() as cur:
        detalhe, veredito = ler_portao(cur, args.model)
    imprimir_portao(detalhe, veredito)


def cmd_promote(conn, args):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM na.models WHERE model_id=%s", (args.model,))
        cand = cur.fetchone()
        if not cand:
            raise SystemExit(f"[!] modelo {args.model} nao existe")
        if cand["status"] == "promoted":
            raise SystemExit("[!] esse modelo ja esta em producao")

        detalhe, veredito = ler_portao(cur, args.model)
        imprimir_portao(detalhe, veredito)
        aprovado = bool(veredito and veredito["aprovado"])

        if not aprovado and not args.force:
            cur.execute(
                """
                INSERT INTO na.promotions
                    (candidate_model_id, incumbent_model_id, decisao,
                     gate_report, decided_by)
                VALUES (%s,%s,'reprovado',%s,%s)
                """,
                (args.model, veredito["incumbent_model_id"] if veredito else None,
                 json.dumps([dict(d) for d in detalhe], default=str), args.by),
            )
            conn.commit()
            raise SystemExit(
                "\n[!] portao REPROVOU. Reprovacao registrada.\n"
                "    Para sobrepor: --force --reason \"...\" (exige justificativa).")

        # despromove o antigo e aposenta os surrogates que o descreviam: a
        # arvore antiga explica um detector que nao decide mais nada.
        cur.execute(
            """
            UPDATE na.models SET status='retired', retired_at=now()
            WHERE status='promoted' AND stage=%s
              AND visao IS NOT DISTINCT FROM %s
              AND kind <> 'decision_tree_surrogate'
            RETURNING model_id
            """,
            (cand["stage"], cand["visao"]),
        )
        antigo = cur.fetchone()
        if antigo:
            cur.execute(
                "UPDATE na.models SET status='retired', retired_at=now() "
                "WHERE kind='decision_tree_surrogate' AND explains_model_id=%s "
                "AND status <> 'retired'", (antigo["model_id"],))

        cur.execute(
            "UPDATE na.models SET status='promoted', promoted_at=now(), "
            "promoted_by=%s WHERE model_id=%s", (args.by, args.model))

        cur.execute(
            """
            INSERT INTO na.promotions
                (candidate_model_id, incumbent_model_id, decisao, gate_report,
                 motivo, decided_by)
            VALUES (%s,%s,%s,%s,%s,%s)
            """,
            (args.model, antigo["model_id"] if antigo else None,
             "aprovado" if aprovado else "sobreposto",
             json.dumps([dict(d) for d in detalhe], default=str),
             args.reason, args.by),
        )

        # troca atomica do arquivo que netanomaly_live.py carrega: symlink
        # novo + rename(), para o live nunca ver um caminho inexistente.
        alvo = POOL_PADRAO / "models" / f"current_{cand['visao']}.joblib"
        temp = alvo.with_suffix(".joblib.novo")
        if temp.is_symlink() or temp.exists():
            temp.unlink()
        # Alvo RELATIVO, nao absoluto: o artefato mora no mesmo diretorio, e
        # um link absoluto ao caminho do container (/var/lib/netanomaly/...)
        # fica pendurado quando o mesmo diretorio e visto do host pelo bind
        # mount (./dados/models/...). Relativo resolve nos dois lados.
        temp.symlink_to(Path(cand["artifact_path"]).name)
        os.replace(temp, alvo)
    conn.commit()

    print(f"\n[+] promovido: {args.model}"
          f"{' (SOBREPOSTO -- portao havia reprovado)' if not aprovado else ''}")
    if antigo:
        print(f"    aposentado: {antigo['model_id']}")
    print(f"    {alvo} -> {cand['artifact_path']}")
    print("    reinicie netanomaly_live.py para carregar o modelo novo")


def cmd_evict(conn, args):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE na.feature_windows
            SET pool_state='evicted', evicted_at=now(), evicted_by=%s,
                evicted_reason=%s
            WHERE window_id = ANY(%s) AND pool_state <> 'evicted'
            RETURNING window_id, n_rows
            """,
            (args.by, args.reason, args.windows),
        )
        despejadas = cur.fetchall()
        cur.execute("SELECT * FROM na.v_models_contaminados")
        contaminados = cur.fetchall()
    conn.commit()

    if not despejadas:
        print("[!] nenhuma janela despejada (ja despejadas ou inexistentes)")
    for d in despejadas:
        print(f"[+] despejada {d['window_id']} ({int(d['n_rows']):,} linhas)")

    if contaminados:
        print(f"\n[!] {len(contaminados)} modelo(s) treinaram sobre janela "
              f"despejada -- o comprometimento esta no baseline deles:")
        for m in contaminados:
            print(f"    {m['model_id']}  {m['status']:<10} "
                  f"{m['n_janelas_despejadas']} janela(s)")
        print("\n    Retreine: ./lifecycle.py candidate --view <flow|host>")


def cmd_requests(conn, args):
    """Consome o botao de retreino manual do analista."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM na.retrain_requests
            WHERE state='pending' AND stage=%s
              AND visao IS NOT DISTINCT FROM %s
            ORDER BY created_at LIMIT 1
            """,
            (args.stage, args.view),
        )
        pedido = cur.fetchone()
        if not pedido:
            print("nenhum pedido pendente")
            return
        print(f"[+] pedido {pedido['request_id']} de {pedido['solicitado_por']} "
              f"({pedido['origem']}): {pedido['motivo']}")
        if pedido["near_misses_ultimos_7d"] is not None:
            print(f"    quase-acertos citados: {pedido['near_misses_ultimos_7d']}"
                  f"  corte na epoca: {pedido['corte_no_momento']}")
        cur.execute(
            "UPDATE na.retrain_requests SET state='running', started_at=now() "
            "WHERE request_id=%s", (pedido["request_id"],))
    conn.commit()

    try:
        cmd_candidate(conn, args)
        estado, erro = "done", None
    except SystemExit as e:
        estado, erro = "failed", str(e)
        print(f"[!] {e}", file=sys.stderr)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE na.retrain_requests SET state=%s, finished_at=now(), erro=%s "
            "WHERE request_id=%s", (estado, erro, pedido["request_id"]))
    conn.commit()
    print(f"[+] pedido {estado}")


# ----------------------------------------------------------------------------
# 9. CLI
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Rotacao do pool de janelas e retreino do Isolation Forest.")
    ap.add_argument("--dsn", default=DSN_PADRAO,
                    help=f"conexao Postgres (padrao: {DSN_PADRAO})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def comuns(p, treino=False):
        p.add_argument("--view", default="flow", choices=["flow", "host"])
        if treino:
            p.add_argument("--stage", type=int, default=1, choices=[1, 2])
            p.add_argument("--peso-minimo", type=float, default=0.05,
                           dest="peso_minimo",
                           help="descarta janela com peso de recencia abaixo "
                                "disto (0.05 ~ 4.3 meias-vidas)")
            p.add_argument("--max-rows", type=int, default=2_000_000,
                           dest="max_rows",
                           help="teto de linhas na matriz de treino")
            p.add_argument("--contamination", type=float, default=0.03)
            p.add_argument("--tree-depth", type=int, default=4, dest="tree_depth")
            p.add_argument("--n-jobs", type=int, default=-1, dest="n_jobs")
            p.add_argument("--seed", type=int, default=42)
            p.add_argument("--notes")
            p.add_argument("--rules", action="store_true",
                           help="imprime as regras da arvore surrogate")

    p = sub.add_parser("pool", help="mostra o que entraria no treino agora")
    comuns(p)
    p.add_argument("--peso-minimo", type=float, default=0.05, dest="peso_minimo")
    p.set_defaults(fn=cmd_pool)

    p = sub.add_parser("extract", help="pcap -> parquet no pool -> feature_windows")
    comuns(p)
    p.add_argument("--pcap", required=True)
    p.add_argument("--sensor", required=True)
    p.add_argument("--feature-set", default="flow-v1", dest="feature_set")
    p.set_defaults(fn=cmd_extract)

    p = sub.add_parser("golden", help="registra uma captura no golden set")
    p.add_argument("--pcap", required=True)
    p.add_argument("--view", default="flow", choices=["flow", "host"])
    p.add_argument("--scenario", required=True,
                   help="cenario de na.golden_scenarios")
    p.add_argument("--label", type=int, default=1, choices=[0, 1],
                   help="1=ataque, 0=controle benigno (ignorado com --cicids)")
    p.add_argument("--cicids", action="store_true",
                   help="rotula pelo cronograma oficial do CIC-IDS-2017 e "
                        "divide em captura de ataque + controle benigno")
    p.add_argument("--capture-id", dest="capture_id")
    p.add_argument("--feature-set", default="flow-v1", dest="feature_set")
    p.add_argument("--ferramenta")
    p.add_argument("--descricao")
    p.set_defaults(fn=cmd_golden)

    p = sub.add_parser("golden-list", help="cobertura do golden set por cenario")
    p.set_defaults(fn=cmd_golden_list)

    p = sub.add_parser("candidate", help="treina candidato e mede. NAO promove.")
    comuns(p, treino=True)
    p.set_defaults(fn=cmd_candidate)

    p = sub.add_parser("gate", help="le o portao de um candidato")
    p.add_argument("--model", required=True)
    p.set_defaults(fn=cmd_gate)

    p = sub.add_parser("promote", help="promove um candidato (passa pelo portao)")
    p.add_argument("--model", required=True)
    p.add_argument("--by", required=True, help="quem esta promovendo")
    p.add_argument("--force", action="store_true",
                   help="promove mesmo com portao reprovado (exige --reason)")
    p.add_argument("--reason", help="justificativa da sobreposicao")
    p.set_defaults(fn=cmd_promote)

    p = sub.add_parser("evict", help="despeja janelas por IOC retroativo")
    p.add_argument("--windows", nargs="+", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--by", default=os.environ.get("USER", "desconhecido"))
    p.set_defaults(fn=cmd_evict)

    p = sub.add_parser("requests", help="consome a fila de retreino do analista")
    comuns(p, treino=True)
    p.set_defaults(fn=cmd_requests)

    args = ap.parse_args()
    if args.cmd == "promote" and args.force and not args.reason:
        ap.error("--force exige --reason: sobrepor o portao sem justificativa "
                 "registrada nao e uma opcao")

    conn = conectar(args.dsn)
    try:
        args.fn(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
