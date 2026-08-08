# tests/test_capture.py
"""
Testa a captura de pacotes usando Scapy.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import sniff, IP, TCP, UDP, ICMP
from src.core.nsl_kdd_mapper import NSLKDDMapper


def packet_callback(packet):
    """Callback para cada pacote capturado."""
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"📦 {ip.src} -> {ip.dst} | Proto: {ip.proto}")
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"   TCP {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}")
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"   UDP {udp.sport} -> {udp.dport}")
        elif packet.haslayer(ICMP):
            print(f"   ICMP type: {packet[ICMP].type}")


def test_capture():
    """Testa captura de pacotes."""
    print("="*60)
    print("🧪 TESTE DE CAPTURA DE PACOTES")
    print("="*60)
    
    print("\n📡 Capturando 10 pacotes...")
    print("   (Pressione Ctrl+C para parar)")
    
    try:
        # Capturar 10 pacotes
        sniff(
            count=10,
            prn=packet_callback,
            filter="ip",  # Filtra apenas IP
            timeout=30
        )
    except KeyboardInterrupt:
        print("\n⏹️ Captura interrompida")
    
    print("\n✅ TESTE CONCLUÍDO!")


if __name__ == "__main__":
    test_capture()