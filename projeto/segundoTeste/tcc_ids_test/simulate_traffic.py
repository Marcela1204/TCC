# simulate_traffic.py
"""
Simula tráfego de rede para testar o IDS em tempo real
"""

import requests
import time
import random
from datetime import datetime

API_URL = "http://192.168.15.5:5000"

def send_flow(is_attack=False):
    """Envia um fluxo simulado para o IDS"""
    
    if is_attack:
        # Fluxo de ataque
        flow = {
            "src_ip": f"10.0.0.{random.randint(1, 10)}",
            "dst_ip": "192.168.1.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "tcp",
            "service": "http",
            "flag": "REJ",
            "duration": random.uniform(0.01, 0.1),
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": random.randint(50, 200),
            "srv_count": random.randint(50, 200),
            "serror_rate": 0.9,
            "same_srv_rate": 0.1,
            "diff_srv_rate": 0.9,
            "num_failed_logins": 0,
            "logged_in": 0,
            "root_shell": 0
        }
    else:
        # Fluxo normal
        flow = {
            "src_ip": f"192.168.1.{random.randint(1, 254)}",
            "dst_ip": f"192.168.1.{random.randint(1, 254)}",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "tcp",
            "service": "http",
            "flag": "SF",
            "duration": random.uniform(0.1, 2.0),
            "src_bytes": random.randint(100, 5000),
            "dst_bytes": random.randint(1000, 10000),
            "count": random.randint(1, 10),
            "srv_count": random.randint(1, 10),
            "serror_rate": 0.0,
            "same_srv_rate": random.uniform(0.5, 1.0),
            "diff_srv_rate": random.uniform(0.0, 0.5),
            "num_failed_logins": 0,
            "logged_in": 1,
            "root_shell": 0
        }
    
    try:
        response = requests.post(f"{API_URL}/api/predict", json=flow)
        return response.json()
    except Exception as e:
        print(f"Erro: {e}")
        return None

def simulate_traffic(duration=60, rate=5, attack_rate=0.3):
    """
    Simula tráfego por um período
    
    Args:
        duration: Duração em segundos
        rate: Fluxos por segundo
        attack_rate: Proporção de ataques (0-1)
    """
    print(f"🚀 Iniciando simulação por {duration}s...")
    print(f"📊 Taxa: {rate} fluxos/s | Ataques: {attack_rate*100:.0f}%")
    print("-" * 50)
    
    start_time = time.time()
    flow_count = 0
    attack_count = 0
    
    while time.time() - start_time < duration:
        # Decidir se é ataque
        is_attack = random.random() < attack_rate
        
        # Enviar fluxo
        result = send_flow(is_attack)
        
        if result:
            flow_count += 1
            if result.get('prediction') == 1:
                attack_count += 1
            
            # Mostrar resultado
            status = "🚨 ATAQUE" if result.get('prediction') == 1 else "✅ NORMAL"
            confidence = result.get('confidence', 0)
            print(f"[{flow_count:3d}] {status} | Conf: {confidence:.2%} | {result.get('message', '')}")
        
        # Aguardar próximo fluxo
        time.sleep(1.0 / rate)
    
    print("-" * 50)
    print(f"📊 Resumo: {flow_count} fluxos, {attack_count} ataques ({attack_count/flow_count*100:.1f}%)")

if __name__ == "__main__":
    # Simular por 30 segundos, 3 fluxos/segundo, 20% de ataques
    simulate_traffic(duration=30, rate=3, attack_rate=0.2)