# scripts/simulate_attack.py
"""
Simula fluxos de rede normais e de ataque para testar o sistema.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import random
import time
from datetime import datetime
from src.core.feature_extractor import NetworkFlow


def create_normal_flow() -> NetworkFlow:
    """Cria um fluxo normal (não ataque)."""
    return NetworkFlow(
        src_ip=f"192.168.1.{random.randint(1, 254)}",
        dst_ip=f"192.168.1.{random.randint(1, 254)}",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol='tcp',
        service='http',
        flag='SF',
        duration=random.uniform(0.1, 2.0),
        src_bytes=random.randint(100, 5000),
        dst_bytes=random.randint(1000, 10000),
        count=random.randint(1, 10),
        srv_count=random.randint(1, 10),
        same_srv_rate=random.uniform(0.5, 1.0),
        diff_srv_rate=random.uniform(0.0, 0.5)
    )


def create_dos_attack() -> NetworkFlow:
    """Cria um fluxo de ataque DoS (SYN flood)."""
    return NetworkFlow(
        src_ip=f"10.0.0.{random.randint(1, 10)}",
        dst_ip="192.168.1.1",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol='tcp',
        service='http',
        flag='REJ',  # Conexão rejeitada
        duration=random.uniform(0.01, 0.1),
        src_bytes=0,
        dst_bytes=0,
        count=random.randint(50, 200),
        srv_count=random.randint(50, 200),
        serror_rate=0.9,
        srv_serror_rate=0.9,
        same_srv_rate=0.1,
        diff_srv_rate=0.9
    )


def create_probe_attack() -> NetworkFlow:
    """Cria um fluxo de ataque Probe (scan)."""
    return NetworkFlow(
        src_ip=f"10.0.0.{random.randint(1, 10)}",
        dst_ip=f"192.168.1.{random.randint(1, 254)}",
        src_port=random.randint(1024, 65535),
        dst_port=random.choice([22, 23, 25, 80, 443, 3306, 5432]),
        protocol='tcp',
        service='other',
        flag='S0',  # SYN apenas
        duration=0.1,
        src_bytes=0,
        dst_bytes=0,
        count=1,
        srv_count=1,
        same_srv_rate=0.0,
        diff_srv_rate=1.0
    )


def create_r2l_attack() -> NetworkFlow:
    """Cria um fluxo de ataque R2L (Remote to Local)."""
    return NetworkFlow(
        src_ip=f"10.0.0.{random.randint(1, 10)}",
        dst_ip="192.168.1.1",
        src_port=random.randint(1024, 65535),
        dst_port=22,
        protocol='tcp',
        service='ssh',
        flag='SF',
        duration=30.0,
        src_bytes=5000,
        dst_bytes=1000,
        num_failed_logins=random.randint(5, 20),
        logged_in=0,
        count=random.randint(10, 50),
        srv_count=random.randint(10, 50)
    )


def create_u2r_attack() -> NetworkFlow:
    """Cria um fluxo de ataque U2R (User to Root)."""
    return NetworkFlow(
        src_ip=f"192.168.1.{random.randint(1, 254)}",
        dst_ip="192.168.1.1",
        src_port=random.randint(1024, 65535),
        dst_port=22,
        protocol='tcp',
        service='ssh',
        flag='SF',
        duration=60.0,
        src_bytes=10000,
        dst_bytes=2000,
        logged_in=1,
        root_shell=1,
        num_compromised=1,
        count=5,
        srv_count=5
    )


ATTACK_GENERATORS = {
    'dos': create_dos_attack,
    'probe': create_probe_attack,
    'r2l': create_r2l_attack,
    'u2r': create_u2r_attack,
    'normal': create_normal_flow
}


def simulate_flows(num_flows: int = 100, attack_rate: float = 0.2):
    """
    Simula uma sequência de fluxos.
    
    Args:
        num_flows: Número total de fluxos
        attack_rate: Proporção de ataques (0-1)
    """
    flows = []
    
    for i in range(num_flows):
        # Decidir se é ataque
        if random.random() < attack_rate:
            # Escolher tipo de ataque aleatório
            attack_type = random.choice(['dos', 'probe', 'r2l', 'u2r'])
            flow = ATTACK_GENERATORS[attack_type]()
            flow.is_attack = True
        else:
            flow = create_normal_flow()
            flow.is_attack = False
        
        flows.append(flow)
    
    return flows


if __name__ == "__main__":
    # Teste rápido
    print("🧪 Simulando fluxos para teste...")
    flows = simulate_flows(20, attack_rate=0.3)
    
    normal = sum(1 for f in flows if not f.is_attack)
    attack = sum(1 for f in flows if f.is_attack)
    
    print(f"✅ {normal} fluxos normais")
    print(f"🚨 {attack} fluxos de ataque")
    print("\nExemplo de fluxo normal:")
    print(flows[0])
    print("\nExemplo de fluxo de ataque:")
    for f in flows:
        if f.is_attack:
            print(f)
            break