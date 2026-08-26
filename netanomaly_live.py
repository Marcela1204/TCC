#!/usr/bin/env python3
"""
netanomaly_live.py — Classificação de tráfego em TEMPO REAL.

Carrega os modelos treinados por `netanomaly.py --save-model` (scaler + Isolation
Forest + Decision Tree + limiar) e classifica tráfego ao vivo em JANELAS de tempo.

NÃO re-treina nada: só aplica os parâmetros congelados no treino.

Motor de captura = o próprio tcpdump (`tcpdump -w - -U`), canalizado para o scapy
via PcapReader. Mais robusto do que parsear a saída de texto.

Uso:
  # 1) treine e salve o modelo (uma vez, no pcap histórico):
  python3 netanomaly.py captura_treino.pcap --save-model modelo

  # 2) rode ao vivo numa interface (precisa de root p/ capturar):
  sudo python3 netanomaly_live.py --iface eth0 --model modelo_flow.joblib

  # visão de host (scans) em vez de fluxo:
  sudo python3 netanomaly_live.py --iface eth0 --model modelo_host.joblib --view host

  # teste offline, "reproduzindo" um pcap como se fosse ao vivo:
  python3 netanomaly_live.py --pcap demo.pcap --model modelo_flow.joblib

  # ou lendo de um pipe já existente:
  sudo tcpdump -i eth0 -w - -U -nn | python3 netanomaly_live.py --stdin --model modelo_flow.joblib

Requisitos: pip install scapy scikit-learn pandas numpy joblib
"""

import argparse
import subprocess
import sys
import time
import signal

import numpy as np
import pandas as pd
import joblib

# Reaproveita a engenharia de features do módulo de treino (mesma lógica -> mesmas colunas)
from netanomaly import build_flows, build_host_profiles


# ----------------------------------------------------------------------------
# Carregamento do modelo
# ----------------------------------------------------------------------------

def load_model(path):
    bundle = joblib.load(path)
    import sklearn
    if bundle.get("sklearn_version") != sklearn.__version__:
        print(f"[!] aviso: modelo treinado com scikit-learn "
              f"{bundle.get('sklearn_version')}, rodando {sklearn.__version__}. "
              f"Recomendado usar a mesma versão.", file=sys.stderr)
    print(f"[+] modelo '{bundle['kind']}' carregado "
          f"(threshold={bundle['threshold']:.4f}, "
          f"{len(bundle['feature_cols'])} features)", file=sys.stderr)
    return bundle


def classify(df, bundle):
    """Aplica scaler + IF congelados e marca anomalias pelo limiar salvo."""
    cols = bundle["feature_cols"]
    X = df[cols].fillna(0.0).replace([np.inf, -np.inf], 0.0).values
    Xs = bundle["scaler"].transform(X)          # transform, NUNCA fit_transform
    scores = -bundle["iso"].score_samples(Xs)
    df = df.copy()
    df["score"] = scores
    df["anomaly"] = (scores >= bundle["threshold"]).astype(int)
    return df


def explain(row_values, bundle):
    """Usa a árvore de decisão salva p/ dar uma razão curta ao alerta (opcional)."""
    tree = bundle.get("tree")
    if tree is None:
        return ""
    cols = bundle["feature_cols"]
    x = np.array([[row_values[c] for c in cols]], dtype=float)
    # percorre o caminho de decisão e junta as condições que levaram à folha
    path = tree.decision_path(x).indices
    feat = tree.tree_.feature
    thr = tree.tree_.threshold
    conds = []
    for node in path:
        f = feat[node]
        if f < 0:               # folha
            continue
        name = cols[f]
        if x[0, f] <= thr[node]:
            conds.append(f"{name}<={thr[node]:.1f}")
        else:
            conds.append(f"{name}>{thr[node]:.1f}")
    return " & ".join(conds[-3:])   # últimas condições, as mais específicas


# ----------------------------------------------------------------------------
# Fontes de pacotes (geram dicts no mesmo formato que netanomaly.read_pcap)
# ----------------------------------------------------------------------------

def _pkt_to_record(pkt):
    from scapy.all import IP, TCP, UDP
    if IP not in pkt:
        return None
    ip = pkt[IP]
    rec = {"ts": float(pkt.time), "src": ip.src, "dst": ip.dst,
           "proto": ip.proto, "length": len(pkt),
           "sport": None, "dport": None, "flags": ""}
    if TCP in pkt:
        rec["sport"] = int(pkt[TCP].sport); rec["dport"] = int(pkt[TCP].dport)
        rec["flags"] = str(pkt[TCP].flags)
    elif UDP in pkt:
        rec["sport"] = int(pkt[UDP].sport); rec["dport"] = int(pkt[UDP].dport)
    return rec


def packets_from_iface(iface):
    """Sobe `tcpdump -w - -U` e lê o stream pcap incrementalmente via scapy."""
    from scapy.all import PcapReader
    cmd = ["tcpdump", "-i", iface, "-w", "-", "-U", "-nn"]
    print(f"[+] capturando: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    reader = PcapReader(proc.stdout)
    try:
        for pkt in reader:
            rec = _pkt_to_record(pkt)
            if rec:
                yield rec
    finally:
        proc.terminate()


def packets_from_stdin():
    """Lê stream pcap do stdin (ex.: `tcpdump -w - -U | ...`)."""
    from scapy.all import PcapReader
    reader = PcapReader(sys.stdin.buffer)
    for pkt in reader:
        rec = _pkt_to_record(pkt)
        if rec:
            yield rec


def packets_from_pcap_replay(path, speed=0.0):
    """Reproduz um pcap como se fosse ao vivo (para teste offline).
    speed=0 processa o mais rápido possível; speed=1 respeita o tempo real."""
    from scapy.all import PcapReader
    reader = PcapReader(path)
    last = None
    for pkt in reader:
        rec = _pkt_to_record(pkt)
        if rec is None:
            continue
        if speed > 0 and last is not None:
            dt = (rec["ts"] - last) / speed
            if 0 < dt < 5:
                time.sleep(dt)
        last = rec["ts"]
        yield rec


# ----------------------------------------------------------------------------
# Loop principal: janela deslizante (tumbling window) por tempo de pacote
# ----------------------------------------------------------------------------

def run(source, bundle, window=10.0, view="flow", show_cols=None):
    builder = build_flows if view == "flow" else build_host_profiles
    id_cols = (["src", "dst", "portB"] if view == "flow" else ["src", "n_dst", "n_dports"])

    buf = []
    win_start = None
    n_win = 0

    def flush():
        nonlocal buf, n_win
        if len(buf) < 3:
            buf = []
            return
        df = builder(buf)
        if len(df) == 0:
            buf = []
            return
        df = classify(df, bundle)
        anoms = df[df["anomaly"] == 1].sort_values("score", ascending=False)
        n_win += 1
        stamp = time.strftime("%H:%M:%S")
        if len(anoms):
            print(f"\n[{stamp}] janela #{n_win}: "
                  f"{len(anoms)}/{len(df)} anomalia(s)")
            for _, row in anoms.iterrows():
                ident = " ".join(f"{c}={row[c]}" for c in id_cols if c in row)
                reason = explain(row, bundle)
                extra = f"  ({reason})" if reason else ""
                print(f"    ALERTA score={row['score']:.3f}  {ident}{extra}")
        else:
            print(f"[{stamp}] janela #{n_win}: {len(df)} fluxos, tudo normal",
                  flush=True)
        buf = []

    for rec in source:
        if win_start is None:
            win_start = rec["ts"]
        # fechou a janela? processa e recomeça
        if rec["ts"] - win_start >= window:
            flush()
            win_start = rec["ts"]
        buf.append(rec)
    flush()   # última janela parcial


def main():
    ap = argparse.ArgumentParser(description="Analisador de anomalias em tempo real.")
    ap.add_argument("--model", required=True, help="arquivo .joblib salvo pelo netanomaly.py")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="interface de rede (ex.: eth0) — requer root")
    src.add_argument("--stdin", action="store_true", help="lê stream pcap do stdin")
    src.add_argument("--pcap", help="reproduz um pcap (modo teste offline)")
    ap.add_argument("--view", choices=["flow", "host"], default="flow",
                    help="tipo de agregação — deve casar com o modelo carregado")
    ap.add_argument("--window", type=float, default=10.0,
                    help="tamanho da janela em segundos (padrão 10)")
    ap.add_argument("--replay-speed", type=float, default=0.0,
                    help="com --pcap: 0=máx velocidade, 1=tempo real")
    args = ap.parse_args()

    bundle = load_model(args.model)
    if bundle["kind"] != args.view:
        print(f"[!] o modelo é do tipo '{bundle['kind']}' mas --view={args.view}. "
              f"Ajustando para '{bundle['kind']}'.", file=sys.stderr)
        args.view = bundle["kind"]

    if args.iface:
        source = packets_from_iface(args.iface)
    elif args.stdin:
        source = packets_from_stdin()
    else:
        source = packets_from_pcap_replay(args.pcap, speed=args.replay_speed)

    # Ctrl+C limpo
    signal.signal(signal.SIGINT, lambda *_: (print("\n[+] encerrando."), sys.exit(0)))

    print(f"[+] janela={args.window}s, view={args.view}. Aguardando tráfego...\n",
          file=sys.stderr)
    run(source, bundle, window=args.window, view=args.view)


if __name__ == "__main__":
    main()
