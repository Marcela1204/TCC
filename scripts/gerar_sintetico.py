#!/usr/bin/env python3
"""
gerar_sintetico.py -- pool e golden set sinteticos para exercitar o lifecycle.

Serve para testar o ciclo inteiro (rotacao do pool, retreino, portao, despejo)
sem depender de captura real, que leva horas para extrair. NAO substitui o
golden set de verdade: as distribuicoes aqui sao inventadas, entao os numeros
que saem daqui medem o CODIGO, nunca o detector.

    ./scripts/gerar_sintetico.py                    # pool limpo + golden set
    ./scripts/gerar_sintetico.py --envenenar        # + janela com 10% de C2
    ./scripts/gerar_sintetico.py --historico        # janelas datadas de 2017

`--historico` existe para exercitar a normalizacao do peso de recencia: com
captura antiga o peso absoluto contra now() vira ~1e-64, e so a razao entre
janelas mantem sentido.
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netanomaly import FEATURE_COLS

rng = np.random.default_rng(7)


def normal(n):
    """Trafego comum: handshake completo, pacotes de tamanho medio."""
    d = {}
    d["n_packets"]     = rng.lognormal(3.2, 0.8, n)
    d["n_bytes"]       = d["n_packets"] * rng.lognormal(6.2, 0.5, n)
    d["duration"]      = rng.lognormal(1.0, 1.0, n)
    d["bytes_per_sec"] = d["n_bytes"] / np.maximum(d["duration"], 0.01)
    d["pkts_per_sec"]  = d["n_packets"] / np.maximum(d["duration"], 0.01)
    d["mean_len"]      = rng.normal(620, 180, n).clip(60, 1500)
    d["std_len"]       = rng.normal(240, 80, n).clip(0)
    d["min_len"]       = rng.normal(70, 12, n).clip(40)
    d["max_len"]       = rng.normal(1400, 90, n).clip(60, 1514)
    d["mean_iat"]      = rng.lognormal(-1.5, 1.0, n)
    d["std_iat"]       = d["mean_iat"] * rng.uniform(0.3, 1.5, n)
    d["syn_ratio"]     = rng.beta(1.5, 30, n)
    d["ack_ratio"]     = rng.beta(9, 3, n)
    d["fin_ratio"]     = rng.beta(1.5, 30, n)
    d["rst_ratio"]     = rng.beta(1, 60, n)
    d["psh_ratio"]     = rng.beta(3, 8, n)
    d["syn_no_ack"]    = np.zeros(n)
    return pd.DataFrame(d)[FEATURE_COLS]


def scan(n):
    """Varredura SYN: fluxos minusculos, so SYN, sem ACK, rajada rapida."""
    d = normal(n)
    d["n_packets"]  = rng.integers(1, 3, n).astype(float)
    d["n_bytes"]    = d["n_packets"] * rng.normal(60, 4, n)
    d["duration"]   = rng.uniform(0, 0.05, n)
    d["pkts_per_sec"]  = d["n_packets"] / np.maximum(d["duration"], 0.001)
    d["bytes_per_sec"] = d["n_bytes"]   / np.maximum(d["duration"], 0.001)
    d["mean_len"] = d["min_len"] = d["max_len"] = rng.normal(60, 3, n)
    d["std_len"]  = np.zeros(n)
    d["mean_iat"] = rng.uniform(0, 0.01, n)
    d["std_iat"]  = np.zeros(n)
    d["syn_ratio"] = rng.uniform(0.9, 1.0, n)
    d["ack_ratio"] = np.zeros(n)
    d["fin_ratio"] = np.zeros(n)
    d["rst_ratio"] = rng.beta(2, 5, n)
    d["psh_ratio"] = np.zeros(n)
    d["syn_no_ack"] = np.ones(n)
    return d


def beacon(n, periodo):
    """C2: poucos pacotes, intervalo regularissimo, jitter quase nulo."""
    d = normal(n)
    d["n_packets"] = rng.integers(4, 10, n).astype(float)
    d["n_bytes"]   = d["n_packets"] * rng.normal(300, 30, n)
    d["duration"]  = rng.normal(periodo, periodo * 0.01, n).clip(1)
    d["mean_iat"]  = d["duration"] / d["n_packets"]
    d["std_iat"]   = d["mean_iat"] * rng.uniform(0.0, 0.02, n)
    d["pkts_per_sec"]  = d["n_packets"] / d["duration"]
    d["bytes_per_sec"] = d["n_bytes"] / d["duration"]
    return d


def gravar_janela(conn, pool, wid, df, dias_atras, historico):
    caminho = os.path.join(pool, "pool", "eth0", "flow", f"{wid}.parquet")
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    df.to_parquet(caminho, index=False)
    if historico:
        # ancora em julho de 2017, como o CIC-IDS-2017
        base = "timestamp '2017-07-07 09:00:00+00' - make_interval(days=>%s)"
    else:
        base = "now() - make_interval(days=>%s)"
    conn.execute(
        f"""INSERT INTO feature_windows (window_id,visao,sensor,t_start,t_end,
            path,n_rows,bytes_on_disk,feature_set,feature_cols,extractor)
            VALUES (%s,'flow','eth0', {base},
                    {base} + interval '13 minutes', %s,%s,%s,
                    'flow-v1',%s,'nfstream')""",
        (wid, dias_atras, dias_atras, caminho, len(df),
         os.path.getsize(caminho), FEATURE_COLS))
    return caminho


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pool", default=os.environ.get("NETANOMALY_POOL",
                                                     "/var/lib/netanomaly"))
    ap.add_argument("--dsn", default=os.environ.get("NETANOMALY_DSN",
                                                    "postgresql:///netanomaly"))
    ap.add_argument("--envenenar", action="store_true",
                    help="adiciona janela com 10%% de beacon-6h como 'normal'")
    ap.add_argument("--historico", action="store_true",
                    help="data as janelas em 2017, como uma captura do CIC")
    args = ap.parse_args()

    import psycopg
    conn = psycopg.connect(args.dsn)
    conn.execute("SET search_path=na,public")

    if args.envenenar:
        # O atacante nao evade nada: so deixa o loop treinar no beacon dele.
        df = pd.concat([normal(36000), beacon(4000, 21600)], ignore_index=True)
        gravar_janela(conn, args.pool, "W-envenenada", df, 8, args.historico)
        conn.commit()
        print("[+] W-envenenada: 10% de beacon-6h dentro do 'normal'")
        return

    for dias in (30, 22, 15, 9):
        # 0.4% de contaminacao residual: nenhuma captura de producao e limpa
        df = pd.concat([normal(40000), scan(160)], ignore_index=True)
        gravar_janela(conn, args.pool, f"W-{dias}d", df, dias, args.historico)

    golden = [("nmap-ss",   "recon",     1, scan(3000)),
              ("beacon-1h", "beacon_1h", 1, beacon(2000, 3600)),
              ("beacon-6h", "beacon_6h", 1, beacon(2000, 21600)),
              ("limpo",     "benigno",   0, normal(20000))]
    os.makedirs(os.path.join(args.pool, "golden"), exist_ok=True)
    for cid, cenario, rotulo, df in golden:
        caminho = os.path.join(args.pool, "golden", f"{cid}.parquet")
        df.to_parquet(caminho, index=False)
        conn.execute(
            """INSERT INTO golden_captures (capture_id,scenario,label,visao,
               parquet_path,n_rows,feature_set)
               VALUES (%s,%s,%s,'flow',%s,%s,'flow-v1')""",
            (cid, cenario, rotulo, caminho, len(df)))

    # cenarios sem captura sintetica nao podem barrar o portao no teste
    conn.execute("UPDATE golden_scenarios SET obrigatorio=false "
                 "WHERE scenario IN ('brute_force','exfil','lateral')")
    # o seed sai incoerente de proposito (ver lifecycle.py); aqui deixamos
    # coerente para o teste nao reprovar por aritmetica de configuracao
    conn.execute("UPDATE parameters SET value='0.02'::jsonb, updated_by='teste' "
                 "WHERE key='gate_max_fpr'")
    conn.commit()
    print(f"[+] 4 janelas de pool + 4 capturas de golden set em {args.pool}")
    print("    proximo: ./lifecycle.py pool --view flow")


if __name__ == "__main__":
    main()
