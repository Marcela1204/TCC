# test_simple_fixed.py
"""
Versão simplificada - testa apenas a detecção sem o FeatureExtractor
"""

import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

@dataclass
class NetworkFlow:
    """Representa um fluxo de rede."""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    duration: float = 1.0
    src_bytes: int = 0
    dst_bytes: int = 0
    flag: str = "SF"
    service: str = "http"
    count: int = 1
    srv_count: int = 1
    serror_rate: float = 0.0
    same_srv_rate: float = 1.0
    diff_srv_rate: float = 0.0
    num_failed_logins: int = 0
    logged_in: int = 0
    root_shell: int = 0
    is_attack: bool = False


def create_normal_flow() -> NetworkFlow:
    """Cria fluxo normal."""
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


def create_attack_flow() -> NetworkFlow:
    """Cria fluxo de ataque."""
    return NetworkFlow(
        src_ip=f"10.0.0.{random.randint(1, 10)}",
        dst_ip="192.168.1.1",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol='tcp',
        service='http',
        flag='REJ',
        duration=random.uniform(0.01, 0.1),
        src_bytes=0,
        dst_bytes=0,
        count=random.randint(50, 200),
        srv_count=random.randint(50, 200),
        serror_rate=0.9,
        same_srv_rate=0.1,
        diff_srv_rate=0.9
    )


class SimpleDetector:
    """Detector baseado em regras."""
    
    def predict(self, flow: NetworkFlow) -> tuple:
        score = 0
        reasons = []
        
        if flow.flag == 'REJ' or flow.flag == 'RSTO':
            score += 2
            reasons.append("Conexão rejeitada")
        
        if flow.flag == 'S0':
            score += 1
            reasons.append("SYN sem ACK")
        
        if flow.num_failed_logins > 5:
            score += 2
            reasons.append(f"Muitas tentativas de login ({flow.num_failed_logins})")
        
        if flow.root_shell == 1:
            score += 3
            reasons.append("Root shell acessado!")
        
        if flow.duration < 0.1 and flow.src_bytes == 0:
            score += 1
            reasons.append("Conexão muito curta")
        
        if flow.count > 50:
            score += 1
            reasons.append(f"Muitas conexões ({flow.count})")
        
        is_attack = score >= 3
        confidence = min(score / 5, 0.95)
        
        return is_attack, confidence, reasons


def simulate_flows(num_flows: int = 100, attack_rate: float = 0.3) -> List[NetworkFlow]:
    """Simula fluxos."""
    flows = []
    for _ in range(num_flows):
        if random.random() < attack_rate:
            flow = create_attack_flow()
            flow.is_attack = True
        else:
            flow = create_normal_flow()
            flow.is_attack = False
        flows.append(flow)
    return flows


def main():
    print("="*60)
    print("🧪 TESTE DE DETECÇÃO (SEM FEATURE EXTRACTOR)")
    print("="*60)
    
    detector = SimpleDetector()
    flows = simulate_flows(50, attack_rate=0.3)
    
    normal = sum(1 for f in flows if not f.is_attack)
    attack = sum(1 for f in flows if f.is_attack)
    print(f"\n📊 {len(flows)} fluxos simulados ({normal} normais, {attack} ataques)")
    
    correct = 0
    for flow in flows:
        is_attack, confidence, reasons = detector.predict(flow)
        if is_attack == flow.is_attack:
            correct += 1
    
    print(f"\n✅ Acurácia: {correct/len(flows):.2%}")
    
    print("\n📝 Exemplos:")
    for i, flow in enumerate(flows[:5]):
        is_attack, confidence, reasons = detector.predict(flow)
        status = "🚨 ATAQUE" if is_attack else "✅ NORMAL"
        expected = "✓" if is_attack == flow.is_attack else "✗"
        print(f"  {i+1}. {status} {expected} | {flow.src_ip}->{flow.dst_ip} | Conf: {confidence:.2%}")
        if reasons:
            print(f"     Razões: {', '.join(reasons[:2])}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()