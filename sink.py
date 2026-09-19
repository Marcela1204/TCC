#!/usr/bin/env python3
"""
sink.py -- persistencia do analisador ao vivo.

O netanomaly_live.py classifica e imprime; este modulo e o que faz o resultado
sobreviver. Duas saidas, com propositos e cadencias diferentes:

    parquet + na.feature_windows   o DATASET NOVO, que alimenta o retreino
    na.alerts                      o que o analista ve

DUAS CADENCIAS, NAO UMA
-----------------------
    janela de analise   --window, padrao 10s. E de quanto em quanto tempo o
                        live agrega fluxos e classifica. Curta de proposito:
                        e a latencia do alerta.

    janela de pool      parametro window_seconds no banco, padrao 780s (13min).
                        E a unidade de TREINO -- o que a quarentena segura, o
                        que o despejo remove, o que o peso de recencia pondera.

Confundi-las quebra os dois lados: uma janela de 10s tem fluxos de menos para
ser unidade de treino e geraria 8640 linhas por dia em feature_windows; uma de
13 minutos como latencia de alerta seria inaceitavel num IDS.

Por isso o sink acumula varias janelas de analise e so fecha o parquet na
fronteira da janela de pool, alinhada por `t0 // window_seconds` -- o MESMO
balde que lifecycle.py extract usa, para que janela vinda de pcap e janela
vinda de captura ao vivo sejam a mesma coisa.

PERCENTIL: CONTRA O TREINO, NAO CONTRA A JANELA
-----------------------------------------------
alerts.percentile vem da grade de quantis congelada no artefato
(bundle["score_quantis"]), nao da posicao do fluxo dentro da sua janela.

Percentil relativo a janela e uma armadilha: numa janela de 13 minutos sem
ataque nenhum, o "1% mais anomalo" e trafego normal, e o corte do analista
geraria alerta por construcao -- falso positivo garantido em toda janela
tranquila. Contra a grade do treino, janela tranquila nao gera alerta.

De quebra o alerta sai NA HORA, sem esperar a janela de pool fechar: o
percentil de um fluxo nao depende dos fluxos que ainda vao chegar.

RESILIENCIA
-----------
O parquet e escrito em disco antes de qualquer INSERT. Se o banco cair no meio
da captura, o dataset de treino continua sendo gerado e pode ser reconciliado
depois; o que se perde sao os alertas daquele periodo, e o sink diz quantos.
"""

import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd


class PoolSink:
    """Acumula janelas de analise, fecha janelas de pool, grava alertas."""

    def __init__(self, dsn, pool_dir, sensor, bundle, modelo_path,
                 visao, verbose=True):
        import psycopg
        from psycopg.rows import dict_row

        self.pool_dir = Path(pool_dir)
        self.sensor = sensor
        self.visao = visao
        self.bundle = bundle
        self.verbose = verbose

        self.conn = psycopg.connect(dsn, row_factory=dict_row)
        with self.conn.cursor() as cur:
            cur.execute("SET search_path = na, public")
            cur.execute("SELECT na.param_num('window_seconds') AS v")
            self.janela_s = float(cur.fetchone()["v"])
            cur.execute("SELECT na.param_num('ingest_floor_percentile') AS v")
            self.piso = float(cur.fetchone()["v"])

            # Identidade do modelo pelo caminho REAL do artefato: o live
            # carrega current_<visao>.joblib, que e symlink para o promovido.
            # Resolver o link e consultar o banco garante que o alerta aponte
            # para o modelo que de fato o produziu.
            real = os.path.realpath(modelo_path)
            cur.execute(
                "SELECT model_id, status, feature_set, feature_cols "
                "FROM na.models WHERE artifact_path = %s", (real,))
            m = cur.fetchone()
            if not m:
                raise SystemExit(
                    f"[!] o artefato {real} nao esta registrado em na.models.\n"
                    f"    Treine e promova por lifecycle.py, ou o alerta nao "
                    f"tem a que modelo se referir.")
            if m["status"] != "promoted":
                print(f"[!] atencao: modelo em status '{m['status']}', nao "
                      f"'promoted'. Gravando assim mesmo.", file=sys.stderr)
            if list(m["feature_cols"]) != list(bundle["feature_cols"]):
                raise SystemExit(
                    "[!] feature_cols do artefato diverge do registro no banco. "
                    "O .joblib nao e o que foi registrado.")
            self.model_id = m["model_id"]
            self.feature_set = m["feature_set"]

        # grade de referencia score -> percentil
        grade = bundle.get("score_quantis")
        if grade:
            self.q_score = np.asarray(grade["score"], dtype=float)
            self.q_pct = np.asarray(grade["percentil"], dtype=float)
        else:
            self.q_score = self.q_pct = None
            print("[!] o modelo nao tem score_quantis: os fluxos continuam "
                  "indo para o pool, mas NENHUM alerta sera gravado -- sem a "
                  "grade de referencia o percentil nao tem significado "
                  "estavel. Retreine com lifecycle.py candidate.",
                  file=sys.stderr)

        self.baldes = {}          # balde -> lista de dataframes
        self.fechados = set()
        self.n_janelas = self.n_alertas = self.n_atrasados = 0
        self.falhas_banco = 0

    # ------------------------------------------------------------------
    def percentil(self, scores):
        """Score -> percentil pela grade do treino. Fora da faixa satura em
        0 ou 1, que e o comportamento correto: um score acima de tudo que se
        viu no treino e o percentil 1.0, nao um extrapolado sem sentido."""
        return np.interp(scores, self.q_score, self.q_pct)

    def adicionar(self, df):
        """Recebe uma janela de analise JA classificada (com coluna score)."""
        if len(df) == 0 or "t0" not in df.columns:
            return
        if self.q_score is not None:
            self._gravar_alertas(df)

        balde = (df["t0"] // self.janela_s).astype("int64")
        for b, parte in df.groupby(balde):
            b = int(b)
            if b in self.fechados:
                self.n_atrasados += len(parte)
                continue
            self.baldes.setdefault(b, []).append(parte)

        # fecha todo balde anterior ao mais recente visto
        atual = int(balde.max())
        for b in sorted(k for k in self.baldes if k < atual):
            self._fechar_balde(b)

    # ------------------------------------------------------------------
    def _gravar_alertas(self, df):
        """Grava, NA HORA, o que passou do piso de ingestao.

        O piso e generoso e fixo; o corte do analista e outro parametro,
        aplicado em view. Gravar so o que passa do corte tornaria impossivel
        baixa-lo depois com efeito retroativo.
        """
        pcts = self.percentil(df["score"].values)
        acima = pcts >= self.piso
        if not acima.any():
            return

        from netanomaly_live import explain
        cols = self.bundle["feature_cols"]
        limiar = float(self.bundle["threshold"])
        e_fluxo = self.visao == "flow"
        linhas = []

        for (_, row), pct in zip(df[acima].iterrows(), pcts[acima]):
            balde = int(row["t0"] // self.janela_s)
            marca = time.strftime("%Y%m%dT%H%M%SZ",
                                  time.gmtime(balde * self.janela_s))
            linhas.append((
                pd.Timestamp(row["t0"], unit="s", tz="UTC"),
                f"{marca}-{self.sensor}-{self.visao}",
                self.model_id, self.sensor, self.visao,
                str(row["src"]),
                str(row["dst"]) if e_fluxo and "dst" in row else None,
                int(row["portA"]) if e_fluxo and pd.notna(row.get("portA")) else None,
                int(row["portB"]) if e_fluxo and pd.notna(row.get("portB")) else None,
                int(row["proto"]) if e_fluxo and pd.notna(row.get("proto")) else None,
                float(row["score"]), float(pct), limiar,
                explain(row, self.bundle) or None,
                __import__("json").dumps(
                    {c: float(row[c]) for c in cols if c in row}),
            ))

        try:
            with self.conn.cursor() as cur:
                cur.executemany(
                    """INSERT INTO na.alerts
                       (ts, window_id, model_id, sensor, visao, src_ip, dst_ip,
                        src_port, dst_port, proto, score, percentile, threshold,
                        surrogate_rule, features)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    linhas)
            self.conn.commit()
            self.n_alertas += len(linhas)
        except Exception as e:
            self.conn.rollback()
            self.falhas_banco += 1
            if self.falhas_banco <= 3:
                print(f"[!] falha ao gravar alertas: {e}", file=sys.stderr)

    # ------------------------------------------------------------------
    def _fechar_balde(self, balde):
        """Fecha uma janela de pool: parquet no disco, depois linha no banco."""
        partes = self.baldes.pop(balde)
        self.fechados.add(balde)
        df = pd.concat(partes, ignore_index=True)

        ini = balde * self.janela_s
        marca = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ini))
        window_id = f"{marca}-{self.sensor}-{self.visao}"
        destino = self.pool_dir / "pool" / self.sensor / self.visao
        destino.mkdir(parents=True, exist_ok=True)
        caminho = destino / f"{marca}.parquet"

        # so as colunas de feature + t0: score e anomaly sao decisao do modelo
        # atual e nao devem entrar no dataset de treino do proximo.
        cols = [c for c in (["t0"] + list(self.bundle["feature_cols"]))
                if c in df.columns]
        df[cols].to_parquet(caminho, index=False)

        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO na.feature_windows
                       (window_id, visao, sensor, t_start, t_end, path, sha256,
                        n_rows, bytes_on_disk, feature_set, feature_cols, extractor)
                       VALUES (%s,%s,%s, to_timestamp(%s), to_timestamp(%s),
                               %s,%s,%s,%s,%s,%s,'scapy')
                       ON CONFLICT (window_id) DO NOTHING""",
                    (window_id, self.visao, self.sensor, ini, ini + self.janela_s,
                     str(caminho), _sha256(caminho), len(df),
                     caminho.stat().st_size, self.feature_set,
                     list(self.bundle["feature_cols"])))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            self.falhas_banco += 1
            print(f"[!] {window_id}: parquet gravado em disco mas NAO "
                  f"registrado no banco ({e}). Reconcilie depois.",
                  file=sys.stderr)

        self.n_janelas += 1
        if self.verbose:
            print(f"[pool] {window_id}: {len(df):,} fluxos -> {caminho.name}",
                  file=sys.stderr)

    # ------------------------------------------------------------------
    def fechar(self):
        for b in sorted(self.baldes):
            self._fechar_balde(b)
        self.conn.close()
        print(f"\n[sink] {self.n_janelas} janela(s) de pool, "
              f"{self.n_alertas} alerta(s) gravado(s)", file=sys.stderr)
        if self.n_atrasados:
            print(f"[sink] {self.n_atrasados} fluxo(s) descartado(s) por "
                  f"chegarem depois do fechamento da janela", file=sys.stderr)
        if self.falhas_banco:
            print(f"[sink] {self.falhas_banco} falha(s) de banco -- os parquets "
                  f"estao no disco", file=sys.stderr)


def _sha256(caminho, bloco=1 << 20):
    import hashlib
    h = hashlib.sha256()
    with open(caminho, "rb") as fo:
        for pedaco in iter(lambda: fo.read(bloco), b""):
            h.update(pedaco)
    return h.hexdigest()
