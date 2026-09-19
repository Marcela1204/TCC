#!/usr/bin/env python3
"""
netclassify.py -- ESTAGIO 2 do pipeline: refinador supervisionado.

O estagio 1 (netanomaly / Isolation Forest) e nao supervisionado e de proposito
alto recall / baixa precisao. Ele tem um ponto cego ESTRUTURAL: ataque de volume
homogeneo (forca bruta, beacon denso) e um aglomerado que o isolamento trata
como normal -- recall ~0, medido.

O estagio 2 e um classificador SUPERVISIONADO que opera SO sobre os alertas do
estagio 1. Ele aprende a fronteira a partir de rotulo (golden set + vereditos do
analista) e recupera justamente o que o estagio 1 nao ve. Medido, mesmas
features: brute_force de 0.00 (IF) para 1.00 (SVM).

O modelo promovido e um SVM linear: `decision_function` da a DISTANCIA COM SINAL
ao hiperplano, que e exatamente o `decision_value`/`margin` que
na.stage2_assignments espera. A clusterizacao, quando entrar, e apoio de
rotulagem (agrupar para o analista rotular em lote), nao o classificador.

LIMITE HONESTO: o SVM so acerta forma de ataque que JA VIU rotulada. Ataque novo
continua com o estagio 1. Os dois sao complementares -- e por isso um pipeline.

Comandos:
    # analista rotula um alerta (a materia-prima do treino)
    ./netclassify.py verdict --alert <uuid> --veredito ataque --analista lucas

    # treina o candidato: golden set + vereditos -> SVM. NAO promove.
    ./netclassify.py train --view flow

    # le a avaliacao antes de decidir
    ./netclassify.py eval --model <uuid>

    # promove (bootstrap do golden entra como 'adotado'; nao passou por portao)
    ./netclassify.py promote --model <uuid> --by lucas

    # aplica o SVM promovido aos alertas -> fila de revisao (NAO suprime nada)
    ./netclassify.py predict --view flow

    # mostra a fila, ordenada por margem (casos de fronteira primeiro)
    ./netclassify.py fila

Banco: NETANOMALY_DSN. Artefatos: NETANOMALY_POOL. Requisitos: os do lifecycle.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

# Reusa infra do estagio 1 -- mesma conexao, mesmo search_path, mesmo hash.
from lifecycle import conectar, sha256
from netanomaly import FEATURE_COLS, HOST_FEATURE_COLS

POOL_PADRAO = Path(os.environ.get("NETANOMALY_POOL", "/var/lib/netanomaly"))


def _cols(visao):
    return FEATURE_COLS if visao == "flow" else HOST_FEATURE_COLS


def _matriz(df, cols):
    return (df[cols].fillna(0.0).replace([np.inf, -np.inf], 0.0)
            .values.astype(float))


# ----------------------------------------------------------------------------
# 1. Coleta de rotulos: golden set + vereditos do analista
# ----------------------------------------------------------------------------

def rotulos_golden(cur, cols, visao):
    """Le as capturas rotuladas do golden set. label 1 = ataque, 0 = benigno.

    E a partida a frio (D2a): o golden set ja e rotulo, e destrava o primeiro
    hiperplano antes de existir veredito de analista. Devolve blocos por
    cenario, para a avaliacao poder medir por cenario depois.
    """
    cur.execute(
        "SELECT capture_id, scenario, label, parquet_path, feature_set "
        "FROM na.golden_captures WHERE visao=%s ORDER BY scenario", (visao,))
    blocos = []
    for c in cur.fetchall():
        try:
            df = pd.read_parquet(c["parquet_path"], columns=cols)
        except Exception as e:
            print(f"[!] {c['capture_id']}: {e}", file=sys.stderr)
            continue
        if len(df) == 0:
            continue
        blocos.append({"origem": "golden", "scenario": c["scenario"],
                       "X": _matriz(df, cols),
                       "y": np.full(len(df), int(c["label"]))})
    return blocos


def rotulos_verdicts(cur, cols):
    """Le os vereditos correntes do analista (a cadeia supersedes ja resolvida
    por v_current_verdicts). 'indeterminado' fica de fora: nao e rotulo.

    Vereditos sao o rotulo REAL da rede implantada -- valem mais que o golden
    sintetico. Por ora concatenados; ponderar mais alto fica para depois.
    """
    cur.execute(
        "SELECT veredito, classe, features FROM na.v_current_verdicts "
        "WHERE veredito IN ('ataque','benigno')")
    linhas = cur.fetchall()
    if not linhas:
        return None
    X, y, cen = [], [], []
    for r in linhas:
        f = r["features"] if isinstance(r["features"], dict) else json.loads(r["features"])
        X.append([float(f.get(c, 0.0)) for c in cols])
        y.append(1 if r["veredito"] == "ataque" else 0)
        cen.append(r["classe"] or "veredito")
    return {"origem": "veredito", "scenario": "veredito",
            "X": np.array(X, dtype=float), "y": np.array(y), "cenarios": cen}


# ----------------------------------------------------------------------------
# 2. Treino do SVM
# ----------------------------------------------------------------------------

def treinar_svm(X, y, random_state=42):
    """StandardScaler + LinearSVC. class_weight='balanced' porque ataque e
    minoria -- sem isso o SVM aprende a chutar 'benigno' e tem recall baixo.

    LinearSVC de proposito: decision_function da distancia com sinal, que e o
    decision_value/margin do schema. predict_proba nao existe aqui e nao e
    necessario -- a fila usa margem, nao probabilidade.
    """
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import LinearSVC
    import sklearn

    from sklearn.decomposition import PCA

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    svm = LinearSVC(C=1.0, class_weight="balanced", max_iter=10000,
                    random_state=random_state)
    svm.fit(Xs, y)
    # PCA(2) para o dashboard projetar 17D -> 2D. Ajustado aqui e congelado no
    # bundle, para todos os pontos usarem a mesma transformacao.
    pca = PCA(n_components=2, random_state=random_state).fit(Xs)
    return {
        "kind": "linear_svm",
        "stage": 2,
        "scaler": scaler,
        "svm": svm,
        "pca": pca,
        "feature_cols": list(FEATURE_COLS),  # sobrescrito p/ host em train
        "sklearn_version": sklearn.__version__,
    }


def matriz_confusao(y_true, y_pred):
    from sklearn.metrics import confusion_matrix
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]).ravel()
    return int(tp), int(fp), int(fn), int(tn)


# ----------------------------------------------------------------------------
# 3. Comandos
# ----------------------------------------------------------------------------

def cmd_verdict(conn, args):
    """Grava um veredito do analista sobre um alerta -- a materia-prima do
    estagio 2. Copia o snapshot de features/score do alerta para o veredito
    (a retencao derruba o alerta aos 180 dias, o rotulo tem de sobreviver).
    Revisao nao sobrescreve: encadeia via supersedes."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT ts, features, score, percentile FROM na.alerts "
            "WHERE alert_id=%s ORDER BY ts DESC LIMIT 1", (args.alert,))
        a = cur.fetchone()
        if not a:
            raise SystemExit(f"[!] alerta {args.alert} nao encontrado")

        # revisao: aponta para o veredito corrente do mesmo alerta, se houver
        cur.execute(
            "SELECT verdict_id FROM na.v_current_verdicts WHERE alert_id=%s",
            (args.alert,))
        anterior = cur.fetchone()

        feats = a["features"] if isinstance(a["features"], str) \
            else json.dumps(a["features"])
        cur.execute(
            """
            INSERT INTO na.verdicts
                (alert_id, alert_ts, veredito, classe, confianca, analista,
                 justificativa, features, score, percentile, supersedes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING verdict_id
            """,
            (args.alert, a["ts"], args.veredito, args.classe, args.confianca,
             args.analista, args.justificativa, feats, a["score"],
             a["percentile"], anterior["verdict_id"] if anterior else None))
        vid = cur.fetchone()["verdict_id"]
    conn.commit()
    acao = "revisao de veredito" if anterior else "veredito"
    print(f"[+] {acao} gravado: {vid} ({args.veredito}) por {args.analista}")


def cmd_train(conn, args):
    import joblib

    cols = _cols(args.view)
    with conn.cursor() as cur:
        blocos = rotulos_golden(cur, cols, args.view)
        vd = rotulos_verdicts(cur, cols)
        if vd:
            blocos.append(vd)

    if not blocos:
        raise SystemExit(
            "[!] sem rotulo nenhum: golden set vazio e sem vereditos.\n"
            "    Registre capturas (lifecycle.py golden) ou rotule alertas "
            "(netclassify.py verdict).")

    X = np.vstack([b["X"] for b in blocos])
    y = np.concatenate([b["y"] for b in blocos])
    n_atq, n_ben = int((y == 1).sum()), int((y == 0).sum())
    origens = {}
    for b in blocos:
        origens[b["origem"]] = origens.get(b["origem"], 0) + len(b["y"])
    print(f"[+] rotulos: {len(y):,} ({n_atq} ataque, {n_ben} benigno) "
          f"de {origens}")
    if n_atq == 0 or n_ben == 0:
        raise SystemExit("[!] preciso das DUAS classes para traçar o hiperplano")

    # --- avaliacao em particao retida: treina no passado do rotulo, mede no
    #     resto. Para golden sintetico e split estratificado; validacao
    #     temporal de verdade entra quando o rotulo for veredito datado.
    from sklearn.model_selection import train_test_split
    Xtr, Xte, ytr, yte, itr, ite = train_test_split(
        X, y, np.arange(len(y)), test_size=0.30, random_state=args.seed,
        stratify=y)
    b_ret = treinar_svm(Xtr, ytr, args.seed)
    pred = b_ret["svm"].predict(b_ret["scaler"].transform(Xte))
    tp, fp, fn, tn = matriz_confusao(yte, pred)
    rec = tp / max(tp + fn, 1)
    prec = tp / max(tp + fp, 1)
    print(f"[+] retido: recall={rec:.3f} precisao={prec:.3f} "
          f"(tp={tp} fp={fp} fn={fn} tn={tn})")

    # cenario a cenario, so para o golden (tem scenario por linha)
    scen_por_linha = {}
    base = 0
    for b in blocos:
        for i in range(len(b["y"])):
            scen_por_linha[base + i] = b["scenario"]
        base += len(b["y"])
    aval_scen = {}
    for pos, idx in enumerate(ite):
        s = scen_por_linha[idx]
        d = aval_scen.setdefault(s, {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "n": 0})
        real, prev = int(yte[pos]), int(pred[pos])
        d["n"] += 1
        if real == 1 and prev == 1: d["tp"] += 1
        elif real == 1: d["fn"] += 1
        elif prev == 1: d["fp"] += 1
        else: d["tn"] += 1

    # --- modelo FINAL treinado em TUDO (melhor fronteira para producao)
    bundle = treinar_svm(X, y, args.seed)
    bundle["feature_cols"] = list(cols)
    bundle["_treino"] = {"n": len(y), "n_ataque": n_atq, "origens": origens}

    destino = POOL_PADRAO / "models"
    destino.mkdir(parents=True, exist_ok=True)
    nome = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}_s2_{args.view}.joblib"
    caminho = destino / nome
    joblib.dump(bundle, caminho)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO na.models
                (stage, kind, visao, artifact_path, artifact_sha256,
                 sklearn_version, feature_set, feature_cols, hyperparams,
                 status, notes)
            VALUES (2,'linear_svm',%s,%s,%s,%s,%s,%s,%s,'candidate',%s)
            RETURNING model_id
            """,
            (args.view, str(caminho), sha256(caminho), bundle["sklearn_version"],
             args.feature_set, list(cols),
             json.dumps({"C": 1.0, "class_weight": "balanced"}),
             args.notes or f"estagio 2, {len(y)} rotulos de {origens}"))
        model_id = cur.fetchone()["model_id"]

        # avaliacao agregada
        cur.execute(
            "INSERT INTO na.model_evaluations "
            "(model_id, scope, n, n_ataque_real, tp, fp, fn, tn) "
            "VALUES (%s,'aggregate',%s,%s,%s,%s,%s,%s)",
            (model_id, len(yte), int((yte == 1).sum()), tp, fp, fn, tn))
        # por cenario: so os que existem em golden_scenarios (FK)
        cur.execute("SELECT scenario FROM na.golden_scenarios")
        validos = {r["scenario"] for r in cur.fetchall()}
        for s, d in aval_scen.items():
            if s not in validos:
                continue
            cur.execute(
                "INSERT INTO na.model_evaluations "
                "(model_id, scope, scenario, n, n_ataque_real, tp, fp, fn, tn) "
                "VALUES (%s,'scenario',%s,%s,%s,%s,%s,%s,%s)",
                (model_id, s, d["n"], d["tp"] + d["fn"],
                 d["tp"], d["fp"], d["fn"], d["tn"]))
    conn.commit()

    print(f"[+] candidato estagio 2: {model_id}")
    print(f"    artefato: {caminho}")
    print(f"    promover: ./netclassify.py promote --model {model_id} --by SEU_NOME")


def cmd_eval(conn, args):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT scope, scenario, n, tp, fp, fn, tn, "
            "round(recall::numeric,3) AS recall, "
            "round(precisao::numeric,3) AS precisao "
            "FROM na.model_evaluations WHERE model_id=%s "
            "ORDER BY scope, scenario", (args.model,))
        linhas = cur.fetchall()
    if not linhas:
        raise SystemExit("[!] sem avaliacao para esse modelo")
    print(f"  {'escopo/cenario':<18}{'recall':>8}{'precisao':>10}{'n':>8}")
    for r in linhas:
        nome = r["scenario"] or r["scope"]
        print(f"  {nome:<18}{str(r['recall']):>8}{str(r['precisao']):>10}{r['n']:>8}")


def cmd_promote(conn, args):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM na.models WHERE model_id=%s AND stage=2",
                    (args.model,))
        m = cur.fetchone()
        if not m:
            raise SystemExit(f"[!] modelo estagio 2 {args.model} nao existe")
        if m["status"] == "promoted":
            raise SystemExit("[!] ja esta em producao")

        # aposenta o SVM anterior da mesma visao
        cur.execute(
            "UPDATE na.models SET status='retired', retired_at=now() "
            "WHERE status='promoted' AND stage=2 AND visao IS NOT DISTINCT FROM %s "
            "RETURNING model_id", (m["visao"],))
        antigo = cur.fetchone()

        cur.execute(
            "UPDATE na.models SET status='promoted', promoted_at=now(), "
            "promoted_by=%s WHERE model_id=%s", (args.by, args.model))

        # bootstrap pelo golden nao passou por portao de veredito: 'adotado'.
        # Quando o portao por vereditos existir (migracao 003), vira 'aprovado'.
        cur.execute(
            "INSERT INTO na.promotions "
            "(candidate_model_id, incumbent_model_id, decisao, gate_report, "
            " motivo, decided_by) VALUES (%s,%s,'adotado','{}'::jsonb,%s,%s)",
            (args.model, antigo["model_id"] if antigo else None,
             args.reason or "estagio 2, bootstrap pelo golden set", args.by))

        alvo = POOL_PADRAO / "models" / f"current_s2_{m['visao']}.joblib"
        temp = alvo.with_suffix(".joblib.novo")
        if temp.is_symlink() or temp.exists():
            temp.unlink()
        temp.symlink_to(Path(m["artifact_path"]).name)   # relativo
        os.replace(temp, alvo)
    conn.commit()
    print(f"[+] estagio 2 promovido: {args.model}")
    if antigo:
        print(f"    aposentado: {antigo['model_id']}")
    print(f"    {alvo} -> {Path(m['artifact_path']).name}")
    print("    rode ./netclassify.py predict para popular a fila")


def _carregar_promovido(conn, visao):
    import joblib
    with conn.cursor() as cur:
        cur.execute(
            "SELECT model_id, artifact_path, feature_cols FROM na.models "
            "WHERE stage=2 AND status='promoted' AND visao=%s", (visao,))
        m = cur.fetchone()
    if not m:
        raise SystemExit(f"[!] nenhum SVM estagio 2 promovido para visao={visao}")
    return m["model_id"], joblib.load(m["artifact_path"])


def cmd_predict(conn, args):
    """Aplica o SVM promovido aos alertas ainda sem predicao e grava a fila.
    D5: ANOTA, nao suprime -- so escreve stage2_assignments, nunca fecha alerta.
    """
    model_id, bundle = _carregar_promovido(conn, args.view)
    cols = bundle["feature_cols"]

    with conn.cursor() as cur:
        # alertas desta visao ainda sem assignment para este modelo
        cur.execute(
            """
            SELECT a.alert_id, a.ts, a.features
            FROM na.alerts a
            WHERE a.visao=%s
              AND NOT EXISTS (
                  SELECT 1 FROM na.stage2_assignments s
                  WHERE s.alert_id=a.alert_id AND s.model_id=%s)
            ORDER BY a.ts DESC
            LIMIT %s
            """,
            (args.view, model_id, args.limite))
        alertas = cur.fetchall()

    if not alertas:
        print("[+] nenhum alerta novo para classificar")
        return

    X = np.array([[float((r["features"] if isinstance(r["features"], dict)
                          else json.loads(r["features"])).get(c, 0.0))
                   for c in cols] for r in alertas], dtype=float)
    Xs = bundle["scaler"].transform(X)
    dv = bundle["svm"].decision_function(Xs)
    # projecao 2D para o dashboard; modelo antigo sem pca -> coords nulas
    pca = bundle.get("pca")
    xy = pca.transform(Xs) if pca is not None else np.full((len(X), 2), None)

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO na.stage2_assignments
                (alert_id, alert_ts, model_id, decision_value, predicted, state,
                 coord_x, coord_y)
            VALUES (%s,%s,%s,%s,%s,'pending',%s,%s)
            ON CONFLICT (alert_id, model_id) DO NOTHING
            """,
            [(r["alert_id"], r["ts"], model_id, float(v),
              "ataque" if v > 0 else "benigno",
              float(c[0]) if pca is not None else None,
              float(c[1]) if pca is not None else None)
             for r, v, c in zip(alertas, dv, xy)])
    conn.commit()
    n_atq = int((dv > 0).sum())
    print(f"[+] {len(alertas)} alerta(s) classificado(s): "
          f"{n_atq} ataque, {len(alertas)-n_atq} benigno")
    print(f"    fila de revisao: ./netclassify.py fila")


def cmd_fila(conn, args):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT assignment_id, predicted, round(decision_value::numeric,3) AS dv, "
            "round(margin::numeric,3) AS margem, host(src_ip) AS origem, "
            "host(dst_ip) AS destino, dst_port, ts "
            "FROM na.v_fila_stage2 LIMIT %s", (args.limite,))
        linhas = cur.fetchall()
    if not linhas:
        print("fila vazia")
        return
    print(f"  {'predito':<9}{'margem':>8}{'dec':>8}  origem -> destino:porta  "
          f"(margem baixa = fronteira, revise primeiro)")
    for r in linhas:
        alvo = f"{r['origem']}->{r['destino']}:{r['dst_port']}"
        print(f"  {r['predicted']:<9}{str(r['margem']):>8}{str(r['dv']):>8}  {alvo}")


# ----------------------------------------------------------------------------
# 4. CLI
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Estagio 2: classificador supervisionado (SVM) sobre os "
                    "alertas do estagio 1.")
    ap.add_argument("--dsn", default=os.environ.get(
        "NETANOMALY_DSN", "postgresql:///netanomaly"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("verdict", help="analista rotula um alerta")
    p.add_argument("--alert", required=True)
    p.add_argument("--veredito", required=True,
                   choices=["ataque", "benigno", "indeterminado"])
    p.add_argument("--analista", required=True)
    p.add_argument("--classe")
    p.add_argument("--confianca", type=int, choices=range(1, 6))
    p.add_argument("--justificativa")
    p.set_defaults(fn=cmd_verdict)

    p = sub.add_parser("train", help="treina o SVM (golden + vereditos). NAO promove.")
    p.add_argument("--view", default="flow", choices=["flow", "host"])
    p.add_argument("--feature-set", default="flow-v1", dest="feature_set")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_train)

    p = sub.add_parser("eval", help="le a avaliacao de um candidato")
    p.add_argument("--model", required=True)
    p.set_defaults(fn=cmd_eval)

    p = sub.add_parser("promote", help="promove um SVM do estagio 2")
    p.add_argument("--model", required=True)
    p.add_argument("--by", required=True)
    p.add_argument("--reason")
    p.set_defaults(fn=cmd_promote)

    p = sub.add_parser("predict", help="aplica o SVM aos alertas -> fila")
    p.add_argument("--view", default="flow", choices=["flow", "host"])
    p.add_argument("--limite", type=int, default=100000)
    p.set_defaults(fn=cmd_predict)

    p = sub.add_parser("fila", help="mostra a fila de revisao (por margem)")
    p.add_argument("--limite", type=int, default=20)
    p.set_defaults(fn=cmd_fila)

    args = ap.parse_args()
    conn = conectar(args.dsn)
    try:
        args.fn(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
