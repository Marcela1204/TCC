# capture_real.py
"""
Captura tráfego real da rede
"""

from scapy.all import sniff, IP, TCP, UDP
import requests
import time

API_URL = "http://192.168.15.5:5000"

def packet_callback(packet):
    """Processa cada pacote capturado"""
    if packet.haslayer(IP):
        ip = packet[IP]
        
        # Extrair informações
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = "tcp" if packet.haslayer(TCP) else "udp" if packet.haslayer(UDP) else "other"
        
        # Extrair portas
        src_port = 0
        dst_port = 0
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Criar fluxo
        flow = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "service": "http" if dst_port == 80 else "other",
            "flag": "SF",  # Simplificado
            "duration": 1.0,
            "src_bytes": len(packet),
            "dst_bytes": 0,
            "count": 1,
            "srv_count": 1,
            "serror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "num_failed_logins": 0,
            "logged_in": 1,
            "root_shell": 0
        }
        
        # Enviar para o IDS
        try:
            response = requests.post(f"{API_URL}/api/predict", json=flow, timeout=1)
            result = response.json()
            
            if result.get('prediction') == 1:
                print(f"🚨 ATAQUE: {src_ip} -> {dst_ip}:{dst_port}")
            else:
                print(f"✅ NORMAL: {src_ip} -> {dst_ip}:{dst_port}")
                
        except Exception as e:
            pass

def start_capture(interface="eth0", count=100):
    """Inicia captura de pacotes"""
    print(f"📡 Capturando na interface {interface}...")
    print("Pressione Ctrl+C para parar")
    
    try:
        sniff(iface=interface, prn=packet_callback, count=count, store=0)
    except KeyboardInterrupt:
        print("\n⏹️ Captura interrompida")

if __name__ == "__main__":
    # Listar interfaces disponíveis
    from scapy.all import get_if_list
    print("Interfaces disponíveis:")
    for iface in get_if_list():
        print(f"  - {iface}")
    
    # Escolher interface (ajuste conforme sua rede)
    interface = "eth0"  # ou "Wi-Fi", "Ethernet", etc.
    start_capture(interface, count=50)