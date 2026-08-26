#!/usr/bin/env python3
"""
netanomaly.py — Detecção NÃO SUPERVISIONADA de anomalias em tráfego de rede.

Arquitetura:
  1. Lê pacotes de um .pcap (via scapy) ou de saída de texto do tcpdump.
  2. Agrega pacotes em FLUXOS (5-tuple) e extrai features.
  3. Isolation Forest (árvores, não supervisionado) -> score + rótulo de anomalia.
  4. Decision Tree treinada sobre os rótulos do IF -> regras legíveis (explicabilidade).

Uso:
  python3 netanomaly.py captura.pcap
  python3 netanomaly.py captura.pcap --contamination 0.02
  python3 netanomaly.py --demo            # gera tráfego sintético e roda tudo
  tcpdump -nn -tt -r x.pcap | python3 netanomaly.py --from-text -

Requisitos: pip install scapy scikit-learn pandas numpy
"""

import argparse
import sys
import math
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text


# ----------------------------------------------------------------------------
# 1. LEITURA DE PACOTES
# ----------------------------------------------------------------------------

def read_pcap(path):
    """Lê um .pcap e devolve lista de dicts (um por pacote TCP/UDP/IP)."""
    from scapy.all import rdpcap, IP, TCP, UDP

    packets = rdpcap(path)
    records = []
    for pkt in packets:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        rec = {
            "ts": float(pkt.time),
            "src": ip.src,
            "dst": ip.dst,
            "proto": ip.proto,          # 6=TCP, 17=UDP
            "length": len(pkt),
            "sport": None,
            "dport": None,
            "flags": "",
        }
        if TCP in pkt:
            tcp = pkt[TCP]
            rec["sport"] = int(tcp.sport)
            rec["dport"] = int(tcp.dport)
            rec["flags"] = str(tcp.flags)   # ex: "S", "SA", "PA", "FA", "R"
        elif UDP in pkt:
            udp = pkt[UDP]
            rec["sport"] = int(udp.sport)
            rec["dport"] = int(udp.dport)
        records.append(rec)
    return records


def read_tcpdump_text(fileobj):
    """Parser tolerante para saída de `tcpdump -nn -tt`.
    Espera linhas tipo:
      1700000000.123456 IP 10.0.0.1.51514 > 10.0.0.2.443: Flags [S], length 0
    Formatos variam bastante; linhas que não casarem são ignoradas.
    """
    import re
    line_re = re.compile(
        r"^(?P<ts>\d+\.\d+)\s+IP6?\s+"
        r"(?P<src>[0-9a-fA-F\.:]+)\.(?P<sport>\d+)\s*>\s*"
        r"(?P<dst>[0-9a-fA-F\.:]+)\.(?P<dport>\d+):\s*"
        r"(?:Flags \[(?P<flags>[^\]]*)\])?"
        r".*?length\s+(?P<length>\d+)"
    )
    records = []
    for line in fileobj:
        m = line_re.search(line)
        if not m:
            continue
        d = m.groupdict()
        has_flags = d["flags"] is not None
        records.append({
            "ts": float(d["ts"]),
            "src": d["src"], "dst": d["dst"],
            "sport": int(d["sport"]), "dport": int(d["dport"]),
            "proto": 6 if has_flags else 17,
            "length": int(d["length"]),
            "flags": d["flags"] or "",
        })
    return records


# ----------------------------------------------------------------------------
# 2. AGREGAÇÃO EM FLUXOS + FEATURES
# ----------------------------------------------------------------------------

def build_flows(records):
    """Agrupa pacotes por 5-tuple (bidirecional) e calcula features por fluxo."""
    flows = defaultdict(list)
    for r in records:
        # chave canônica: ordena os endpoints para juntar ida e volta no mesmo fluxo
        a = (r["src"], r["sport"])
        b = (r["dst"], r["dport"])
        key = (tuple(sorted([a, b])), r["proto"])
        flows[key].append(r)

    rows = []
    for key, pkts in flows.items():
        pkts.sort(key=lambda x: x["ts"])
        (endpoints, proto) = key
        (ipA, portA), (ipB, portB) = endpoints

        lengths = np.array([p["length"] for p in pkts], dtype=float)
        ts = np.array([p["ts"] for p in pkts], dtype=float)
        duration = float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0
        iats = np.diff(ts) if len(ts) > 1 else np.array([0.0])

        # contagem de flags TCP
        flagstr = "".join(p["flags"] for p in pkts)
        n = len(pkts)
        syn = flagstr.count("S")
        ack = flagstr.count("A")
        fin = flagstr.count("F")
        rst = flagstr.count("R")
        psh = flagstr.count("P")

        rows.append({
            "src": ipA, "dst": ipB, "portA": portA, "portB": portB, "proto": proto,
            "n_packets": n,
            "n_bytes": float(lengths.sum()),
            "duration": duration,
            "bytes_per_sec": float(lengths.sum() / duration) if duration > 0 else lengths.sum(),
            "pkts_per_sec": float(n / duration) if duration > 0 else float(n),
            "mean_len": float(lengths.mean()),
            "std_len": float(lengths.std()),
            "min_len": float(lengths.min()),
            "max_len": float(lengths.max()),
            "mean_iat": float(iats.mean()),
            "std_iat": float(iats.std()),
            "syn_ratio": syn / n,
            "ack_ratio": ack / n,
            "fin_ratio": fin / n,
            "rst_ratio": rst / n,
            "psh_ratio": psh / n,
            "syn_no_ack": 1.0 if (syn > 0 and ack == 0) else 0.0,
        })
    return pd.DataFrame(rows)


FEATURE_COLS = [
    "n_packets", "n_bytes", "duration", "bytes_per_sec", "pkts_per_sec",
    "mean_len", "std_len", "min_len", "max_len", "mean_iat", "std_iat",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio", "psh_ratio", "syn_no_ack",
]


def build_host_profiles(records):
    """Agrega por IP DE ORIGEM. Captura scans / fan-out (um host falando com
    muitos destinos/portas), que a visão por-fluxo não enxerga."""
    hosts = defaultdict(lambda: {
        "pkts": 0, "bytes": 0, "dsts": set(), "dports": set(),
        "syn": 0, "ack": 0, "rst": 0, "ts": [],
    })
    for r in records:
        h = hosts[r["src"]]
        h["pkts"] += 1
        h["bytes"] += r["length"]
        h["dsts"].add(r["dst"])
        if r["dport"] is not None:
            h["dports"].add(r["dport"])
        f = r["flags"]
        h["syn"] += f.count("S")
        h["ack"] += f.count("A")
        h["rst"] += f.count("R")
        h["ts"].append(r["ts"])

    rows = []
    for ip, h in hosts.items():
        n = h["pkts"]
        ts = sorted(h["ts"])
        dur = (ts[-1] - ts[0]) if len(ts) > 1 else 0.0
        rows.append({
            "src": ip,
            "h_packets": n,
            "h_bytes": float(h["bytes"]),
            "n_dst": len(h["dsts"]),
            "n_dports": len(h["dports"]),
            "dports_per_dst": len(h["dports"]) / max(1, len(h["dsts"])),
            "h_syn_ratio": h["syn"] / n,
            "h_ack_ratio": h["ack"] / n,
            "h_rst_ratio": h["rst"] / n,
            "syn_ack_gap": (h["syn"] - h["ack"]) / n,   # scan: muitos SYN, poucos ACK
            "pkts_per_dst": n / max(1, len(h["dsts"])),
            "h_pkts_per_sec": n / dur if dur > 0 else float(n),
        })
    return pd.DataFrame(rows)


HOST_FEATURE_COLS = [
    "h_packets", "h_bytes", "n_dst", "n_dports", "dports_per_dst",
    "h_syn_ratio", "h_ack_ratio", "h_rst_ratio", "syn_ack_gap",
    "pkts_per_dst", "h_pkts_per_sec",
]


# ----------------------------------------------------------------------------
# 2b. AGREGAÇÃO EM STREAMING (para pcaps grandes) — 1 passe, memória O(fluxos)
# ----------------------------------------------------------------------------

def iter_pcap_records(path):
    """Itera pacotes de um pcap SEM carregar tudo na RAM (usa PcapReader)."""
    from scapy.all import PcapReader, IP, TCP, UDP
    with PcapReader(path) as pr:
        for pkt in pr:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            rec = {"ts": float(pkt.time), "src": ip.src, "dst": ip.dst,
                   "proto": ip.proto, "length": len(pkt),
                   "sport": None, "dport": None, "flags": ""}
            if TCP in pkt:
                rec["sport"] = int(pkt[TCP].sport); rec["dport"] = int(pkt[TCP].dport)
                rec["flags"] = str(pkt[TCP].flags)
            elif UDP in pkt:
                rec["sport"] = int(pkt[UDP].sport); rec["dport"] = int(pkt[UDP].dport)
            yield rec


def aggregate_streaming(record_iter, host_max_ports=100_000):
    """UM passe sobre os pacotes -> devolve (df_flow, df_host).
    Mantém só contadores por fluxo/host: memória O(nº de fluxos+hosts),
    não O(nº de pacotes). Variância via soma e soma-dos-quadrados.
    """
    flows = {}
    hosts = {}
    n_pkts = 0

    for r in record_iter:
        n_pkts += 1
        L = float(r["length"]); ts = r["ts"]; f = r["flags"]
        syn = f.count("S"); ack = f.count("A"); fin = f.count("F")
        rst = f.count("R"); psh = f.count("P")

        # ---- fluxo (5-tuple bidirecional) ----
        a = (r["src"], r["sport"]); b = (r["dst"], r["dport"])
        fk = (a, b) if a <= b else (b, a)
        fk = (fk, r["proto"])
        fl = flows.get(fk)
        if fl is None:
            (epA, epB) = fk[0]
            fl = flows[fk] = {
                "ipA": epA[0], "portA": epA[1], "ipB": epB[0], "portB": epB[1],
                "n": 0, "sum": 0.0, "sqsum": 0.0, "min": L, "max": L,
                "t0": ts, "tN": ts, "prev": None,
                "iat_sum": 0.0, "iat_sq": 0.0, "iat_n": 0,
                "syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0,
            }
        fl["n"] += 1; fl["sum"] += L; fl["sqsum"] += L * L
        if L < fl["min"]: fl["min"] = L
        if L > fl["max"]: fl["max"] = L
        fl["tN"] = ts
        if fl["prev"] is not None:
            iat = ts - fl["prev"]
            fl["iat_sum"] += iat; fl["iat_sq"] += iat * iat; fl["iat_n"] += 1
        fl["prev"] = ts
        fl["syn"] += syn; fl["ack"] += ack; fl["fin"] += fin
        fl["rst"] += rst; fl["psh"] += psh

        # ---- host (origem) ----
        h = hosts.get(r["src"])
        if h is None:
            h = hosts[r["src"]] = {
                "n": 0, "bytes": 0.0, "dsts": set(), "dports": set(),
                "syn": 0, "ack": 0, "rst": 0, "t0": ts, "tN": ts,
            }
        h["n"] += 1; h["bytes"] += L; h["tN"] = ts
        h["dsts"].add(r["dst"])
        if r["dport"] is not None and len(h["dports"]) < host_max_ports:
            h["dports"].add(r["dport"])
        h["syn"] += syn; h["ack"] += ack; h["rst"] += rst

    # ---- materializa fluxos ----
    def _std(s, sq, n):
        if n <= 0: return 0.0
        v = sq / n - (s / n) ** 2
        return math.sqrt(v) if v > 0 else 0.0

    frows = []
    for fl in flows.values():
        n = fl["n"]; dur = fl["tN"] - fl["t0"]
        frows.append({
            "src": fl["ipA"], "dst": fl["ipB"], "portA": fl["portA"],
            "portB": fl["portB"], "proto": 0,
            "n_packets": n, "n_bytes": fl["sum"], "duration": dur,
            "bytes_per_sec": fl["sum"] / dur if dur > 0 else fl["sum"],
            "pkts_per_sec": n / dur if dur > 0 else float(n),
            "mean_len": fl["sum"] / n, "std_len": _std(fl["sum"], fl["sqsum"], n),
            "min_len": fl["min"], "max_len": fl["max"],
            "mean_iat": fl["iat_sum"] / fl["iat_n"] if fl["iat_n"] else 0.0,
            "std_iat": _std(fl["iat_sum"], fl["iat_sq"], fl["iat_n"]),
            "syn_ratio": fl["syn"] / n, "ack_ratio": fl["ack"] / n,
            "fin_ratio": fl["fin"] / n, "rst_ratio": fl["rst"] / n,
            "psh_ratio": fl["psh"] / n,
            "syn_no_ack": 1.0 if (fl["syn"] > 0 and fl["ack"] == 0) else 0.0,
        })

    hrows = []
    for ip, h in hosts.items():
        n = h["n"]; dur = h["tN"] - h["t0"]; nd = max(1, len(h["dsts"]))
        hrows.append({
            "src": ip, "h_packets": n, "h_bytes": h["bytes"],
            "n_dst": len(h["dsts"]), "n_dports": len(h["dports"]),
            "dports_per_dst": len(h["dports"]) / nd,
            "h_syn_ratio": h["syn"] / n, "h_ack_ratio": h["ack"] / n,
            "h_rst_ratio": h["rst"] / n, "syn_ack_gap": (h["syn"] - h["ack"]) / n,
            "pkts_per_dst": n / nd,
            "h_pkts_per_sec": n / dur if dur > 0 else float(n),
        })
    return pd.DataFrame(frows), pd.DataFrame(hrows), n_pkts


# ----------------------------------------------------------------------------
# 2c. EXTRAÇÃO VIA NFSTREAM (backend em C) — recomendado p/ pcaps de vários GB
# ----------------------------------------------------------------------------

def from_nfstream(path, idle_timeout=15, active_timeout=120):
    """Usa o NFStreamer (engine C sobre libpcap) para extrair fluxos ~10-100x
    mais rápido que o scapy, e mapeia as colunas para as features do pipeline.
    Devolve (df_flow, df_host). Toda a agregação é vetorizada no pandas.

    Requer: pip install nfstream
    """
    from nfstream import NFStreamer

    raw = NFStreamer(
        source=path,
        statistical_analysis=True,       # habilita min/mean/std de tamanho e IAT
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
    ).to_pandas()

    if len(raw) == 0:
        return pd.DataFrame(), pd.DataFrame()

    n = raw["bidirectional_packets"].clip(lower=1).astype(float)
    b = raw["bidirectional_bytes"].astype(float)
    dur = raw["bidirectional_duration_ms"].astype(float) / 1000.0
    pos = dur > 0

    # ---- tabela por FLUXO (mesmas colunas de FEATURE_COLS) ----
    df_flow = pd.DataFrame({
        "src": raw["src_ip"], "dst": raw["dst_ip"],
        "portA": raw["src_port"], "portB": raw["dst_port"], "proto": raw["protocol"],
        "n_packets": raw["bidirectional_packets"].astype(float),
        "n_bytes": b,
        "duration": dur,
        "bytes_per_sec": np.where(pos, b / dur.where(pos, 1), b),
        "pkts_per_sec": np.where(pos, n / dur.where(pos, 1), n),
        "mean_len": raw["bidirectional_mean_ps"].astype(float),
        "std_len": raw["bidirectional_stddev_ps"].astype(float),
        "min_len": raw["bidirectional_min_ps"].astype(float),
        "max_len": raw["bidirectional_max_ps"].astype(float),
        "mean_iat": raw["bidirectional_mean_piat_ms"].astype(float) / 1000.0,
        "std_iat": raw["bidirectional_stddev_piat_ms"].astype(float) / 1000.0,
        "syn_ratio": raw["bidirectional_syn_packets"] / n,
        "ack_ratio": raw["bidirectional_ack_packets"] / n,
        "fin_ratio": raw["bidirectional_fin_packets"] / n,
        "rst_ratio": raw["bidirectional_rst_packets"] / n,
        "psh_ratio": raw["bidirectional_psh_packets"] / n,
        "syn_no_ack": ((raw["bidirectional_syn_packets"] > 0) &
                       (raw["bidirectional_ack_packets"] == 0)).astype(float),
    })

    # ---- tabela por HOST (agrega os fluxos por IP de origem, vetorizado) ----
    raw = raw.assign(
        _last=raw["bidirectional_first_seen_ms"] + raw["bidirectional_duration_ms"])
    g = raw.groupby("src_ip", sort=False)
    host = pd.DataFrame({
        "h_packets": g["bidirectional_packets"].sum(),
        "h_bytes": g["bidirectional_bytes"].sum().astype(float),
        "n_dst": g["dst_ip"].nunique(),
        "n_dports": g["dst_port"].nunique(),
        "_syn": g["bidirectional_syn_packets"].sum(),
        "_ack": g["bidirectional_ack_packets"].sum(),
        "_rst": g["bidirectional_rst_packets"].sum(),
        "_first": g["bidirectional_first_seen_ms"].min(),
        "_last": g["_last"].max(),
    }).reset_index().rename(columns={"src_ip": "src"})

    hp = host["h_packets"].clip(lower=1).astype(float)
    nd = host["n_dst"].clip(lower=1).astype(float)
    hdur = (host["_last"] - host["_first"]).astype(float) / 1000.0
    df_host = pd.DataFrame({
        "src": host["src"],
        "h_packets": host["h_packets"].astype(float),
        "h_bytes": host["h_bytes"],
        "n_dst": host["n_dst"].astype(float),
        "n_dports": host["n_dports"].astype(float),
        "dports_per_dst": host["n_dports"] / nd,
        "h_syn_ratio": host["_syn"] / hp,
        "h_ack_ratio": host["_ack"] / hp,
        "h_rst_ratio": host["_rst"] / hp,
        "syn_ack_gap": (host["_syn"] - host["_ack"]) / hp,
        "pkts_per_dst": host["h_packets"] / nd,
        "h_pkts_per_sec": np.where(hdur > 0, hp / hdur.where(hdur > 0, 1), hp),
    })
    return df_flow, df_host


# ----------------------------------------------------------------------------
# 3. ISOLATION FOREST (não supervisionado) + 4. DECISION TREE (explicabilidade)
# ----------------------------------------------------------------------------

def detect(df, feature_cols=FEATURE_COLS, contamination=0.03, random_state=42,
           kind="flow", n_jobs=-1):
    X = df[feature_cols].fillna(0.0).replace([np.inf, -np.inf], 0.0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)            # scaler AJUSTADO no treino -> precisa ser salvo

    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=n_jobs,          # -1 = todos os cores (paraleliza a construção das árvores)
    )
    iso.fit(Xs)
    scores = -iso.score_samples(Xs)         # quanto maior, mais anômalo
    df = df.copy()
    df["score"] = scores

    # Limiar FIXO derivado do treino: o percentil (1 - contamination) dos scores.
    # É ele que o analisador em tempo real vai usar (não a contamination).
    threshold = float(np.quantile(scores, 1.0 - contamination))
    df["anomaly"] = (scores >= threshold).astype(int)

    tree = None
    tree_rules = None
    importances = None
    # A árvore só faz sentido se houver as duas classes
    if df["anomaly"].nunique() == 2:
        tree = DecisionTreeClassifier(max_depth=4, random_state=random_state)
        tree.fit(X, df["anomaly"].values)
        tree_rules = export_text(tree, feature_names=list(feature_cols))
        importances = sorted(
            zip(feature_cols, tree.feature_importances_),
            key=lambda t: t[1], reverse=True,
        )

    # "artifacts" = tudo que o analisador em tempo real precisa pra reproduzir a decisão
    artifacts = {
        "kind": kind,
        "scaler": scaler,
        "iso": iso,
        "tree": tree,
        "feature_cols": list(feature_cols),
        "threshold": threshold,
        "contamination": contamination,
    }
    return df, tree_rules, importances, artifacts


def save_model(artifacts, path):
    """Serializa o pacote de modelo (scaler + iso + tree + limiar + features)."""
    import joblib
    import sklearn
    bundle = dict(artifacts)
    bundle["sklearn_version"] = sklearn.__version__
    joblib.dump(bundle, path)
    print(f"[+] modelo '{artifacts['kind']}' salvo em: {path} "
          f"(threshold={artifacts['threshold']:.4f}, "
          f"{len(artifacts['feature_cols'])} features)")


# ----------------------------------------------------------------------------
# DEMO: gera um pcap sintético com tráfego normal + port scan + exfiltração
# ----------------------------------------------------------------------------

def make_demo_pcap(path="demo.pcap"):
    from scapy.all import IP, TCP, UDP, wrpcap
    import random
    random.seed(1)
    pkts = []
    t = 1_700_000_000.0

    # --- tráfego "normal": navegação HTTPS de alguns clientes ---
    for client in range(5):
        src = f"10.0.0.{10+client}"
        for _ in range(random.randint(20, 40)):
            t += random.uniform(0.05, 0.5)
            sport = random.randint(40000, 60000)
            # SYN, SYN-ACK, dados...
            p = IP(src=src, dst="93.184.216.34") / TCP(sport=sport, dport=443, flags="S")
            p.time = t
            pkts.append(p)
            t += 0.02
            p2 = IP(src="93.184.216.34", dst=src) / TCP(sport=443, dport=sport, flags="SA")
            p2.time = t
            pkts.append(p2)
            for _ in range(random.randint(3, 8)):
                t += random.uniform(0.01, 0.1)
                payload = b"x" * random.randint(200, 1400)
                p3 = IP(src=src, dst="93.184.216.34") / TCP(sport=sport, dport=443, flags="PA") / payload
                p3.time = t
                pkts.append(p3)

    # --- ANOMALIA 1: port scan (muitos SYN, sem ACK, para muitas portas) ---
    attacker = "10.0.0.66"
    for port in range(1, 400):
        t += 0.001
        p = IP(src=attacker, dst="10.0.0.5") / TCP(sport=55555, dport=port, flags="S")
        p.time = t
        pkts.append(p)

    # --- ANOMALIA 2: exfiltração (fluxo único gigante, muitos bytes num destino externo) ---
    for _ in range(300):
        t += 0.005
        payload = b"D" * 1400
        p = IP(src="10.0.0.12", dst="185.220.101.1") / TCP(sport=51000, dport=8443, flags="PA") / payload
        p.time = t
        pkts.append(p)

    wrpcap(path, pkts)
    return path, len(pkts)


# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Detecção não supervisionada de anomalias de rede.")
    ap.add_argument("input", nargs="?", help="arquivo .pcap (ou - com --from-text)")
    ap.add_argument("--from-text", action="store_true", help="lê saída de texto do tcpdump em vez de pcap")
    ap.add_argument("--demo", action="store_true", help="gera tráfego sintético e roda a análise")
    ap.add_argument("--contamination", type=float, default=0.03,
                    help="proporção esperada de anomalias (0-0.5). Padrão 0.03")
    ap.add_argument("--top", type=int, default=15, help="quantas anomalias listar")
    ap.add_argument("--nfstream", action="store_true",
                    help="usa o nfstream (engine C) para extrair fluxos — muito mais "
                         "rápido em pcaps grandes. Requer: pip install nfstream")
    ap.add_argument("--stream", action="store_true",
                    help="modo streaming p/ pcaps grandes: 1 passe, sem carregar "
                         "tudo na RAM. Recomendado para arquivos de vários GB.")
    ap.add_argument("--sample-flows", type=int, default=0,
                    help="treina num subconjunto aleatório de N fluxos (0=todos). "
                         "Acelera o fit/score sem perder qualidade do detector.")
    ap.add_argument("--n-jobs", type=int, default=-1,
                    help="cores para o Isolation Forest. -1=todos (padrão), "
                         "1=single-thread. A Decision Tree é sempre single-thread.")
    ap.add_argument("--save-model", metavar="PREFIXO",
                    help="salva os modelos treinados. Gera PREFIXO_flow.joblib e "
                         "PREFIXO_host.joblib para uso no analisador em tempo real")
    args = ap.parse_args()

    # -------- caminho STREAMING (pcaps grandes): 1 passe, memória O(fluxos) --------
    pcap_path = None
    if args.demo:
        pcap_path, npk = make_demo_pcap()
        print(f"[demo] pcap sintético gerado: {pcap_path} ({npk} pacotes)\n")
    elif args.input and not args.from_text:
        pcap_path = args.input

    if args.nfstream and pcap_path:
        import time as _t
        t0 = _t.time()
        print(f"[+] extraindo fluxos de {pcap_path} via nfstream (engine C)...")
        df_flow, df_host = from_nfstream(pcap_path)
        print(f"[+] {len(df_flow)} fluxos, {len(df_host)} hosts em {_t.time()-t0:.1f}s")
        records = None
    elif args.stream and pcap_path:
        import time as _t
        t0 = _t.time()
        print(f"[+] streaming de {pcap_path} (sem carregar tudo na RAM)...")
        df_flow, df_host, n_pkts = aggregate_streaming(iter_pcap_records(pcap_path))
        print(f"[+] {n_pkts} pacotes processados em {_t.time()-t0:.1f}s "
              f"-> {len(df_flow)} fluxos, {len(df_host)} hosts")
        records = None
    else:
        if args.demo:
            records = read_pcap(pcap_path)
        elif args.from_text:
            fo = sys.stdin if args.input in (None, "-") else open(args.input)
            records = read_tcpdump_text(fo)
        elif args.input:
            records = read_pcap(args.input)
        else:
            ap.error("informe um .pcap, use --from-text, ou --demo")
        print(f"[+] {len(records)} pacotes lidos")
        df_flow = build_flows(records)
        df_host = build_host_profiles(records)

    def maybe_sample(df):
        if args.sample_flows and len(df) > args.sample_flows:
            print(f"    (treinando em amostra de {args.sample_flows}/{len(df)})")
            return df.sample(args.sample_flows, random_state=42)
        return df

    def report(df, feature_cols, show_cols, titulo, kind):
        df = maybe_sample(df)
        if len(df) < 5:
            print(f"\n### {titulo}: poucos registros ({len(df)}) para análise confiável.")
            return
        df, rules, importances, artifacts = detect(
            df, feature_cols, contamination=args.contamination, kind=kind,
            n_jobs=args.n_jobs)
        n_anom = int(df["anomaly"].sum())
        print(f"\n{'='*70}\n### {titulo}")
        print(f"{'='*70}")
        print(f"{len(df)} registros | {n_anom} anômalos ({100*n_anom/len(df):.1f}%)\n")
        top = df.sort_values("score", ascending=False).head(args.top)
        with pd.option_context("display.width", 200, "display.max_columns", None):
            print(top[show_cols].to_string(index=False))
        if importances:
            print("\n-- Features que mais explicam (Decision Tree) --")
            for name, imp in importances[:6]:
                if imp > 0:
                    print(f"  {name:16s} {imp:.3f}")
            print("\n-- Regras da árvore de decisão --")
            print(rules)
        if args.save_model:
            save_model(artifacts, f"{args.save_model}_{kind}.joblib")

    # Visão 1: por FLUXO (exfiltração, volumetria, conexões estranhas)
    print(f"[+] {len(df_flow)} fluxos agregados")
    report(
        df_flow, FEATURE_COLS,
        ["src", "dst", "portB", "proto", "n_packets", "n_bytes",
         "syn_ratio", "bytes_per_sec", "score"],
        "VISÃO POR FLUXO (5-tuple)", "flow",
    )

    # Visão 2: por HOST DE ORIGEM (port scan / fan-out)
    print(f"\n[+] {len(df_host)} hosts de origem")
    report(
        df_host, HOST_FEATURE_COLS,
        ["src", "h_packets", "n_dst", "n_dports", "dports_per_dst",
         "syn_ack_gap", "score"],
        "VISÃO POR HOST (scan / fan-out)", "host",
    )


if __name__ == "__main__":
    main()
