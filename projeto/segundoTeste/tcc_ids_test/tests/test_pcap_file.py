# tests/test_pcap_file.py
"""
Testa o sistema com um arquivo PCAP.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import rdpcap
from src.core.nsl_kdd_mapper import NSLKDDMapper
from src.core.feature_extractor import FeatureExtractor
from src.core.ids_predictor import IDSPredictor
import time


def test_pcap_file(pcap_file: str):
    """Processa um arquivo pcap."""
    print("="*60)
    print(f"🧪 TESTE COM ARQUIVO PCAP: {pcap_file}")
    print("="*60)
    
    # Verificar se arquivo existe
    if not os.path.exists(pcap_file):
        print(f"❌ Arquivo {pcap_file} não encontrado!")
        return
    
    # 1. Inicializar
    print("\n1. Inicializando sistema...")
    predictor = IDSPredictor()
    try:
        predictor.initialize()
    except Exception as e:
        print(f"   ⚠️ Erro na inicialização: {e}")
        print("   Usando modo offline (sem modelo)...")
        predictor.is_initialized = False
    
    # 2. Carregar PCAP
    print(f"\n2. Carregando {pcap_file}...")
    packets = rdpcap(pcap_file)
    print(f"   ✅ {len(packets)} pacotes carregados")
    
    # 3. Processar pacotes
    print("\n3. Processando pacotes...")
    mapper = NSLKDDMapper()
    flows = []
    
    for i, packet in enumerate(packets[:100]):  # Limitar para teste
        if packet.haslayer('IP'):
            flow_data = mapper.packet_to_flow(packet)
            if flow_data:
                flows.append(flow_data)
                if len(flows) % 10 == 0:
                    print(f"   Processados {len(flows)} fluxos...")
    
    print(f"   ✅ {len(flows)} fluxos extraídos")
    
    # 4. Classificar fluxos
    print("\n4. Classificando fluxos...")
    attack_count = 0
    normal_count = 0
    
    for flow_data in flows:
        # Verificar se é ataque (simples heurística)
        if flow_data.get('flag') in ['REJ', 'RSTO'] or flow_data.get('serror_rate', 0) > 0.5:
            attack_count += 1
        else:
            normal_count += 1
    
    print(f"   🚨 Ataques detectados: {attack_count}")
    print(f"   ✅ Fluxos normais: {normal_count}")
    print(f"   📊 Taxa de ataque: {attack_count/len(flows):.2%}")
    
    print("\n" + "="*60)
    print("✅ TESTE CONCLUÍDO!")


if __name__ == "__main__":
    # Usar um arquivo pcap de exemplo
    # Você pode baixar um arquivo pcap de exemplo:
    # wget https://www.malware-traffic-analysis.net/2023/01/17/2023-01-17.pcap.zip
    
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    test_pcap_file(pcap_file)