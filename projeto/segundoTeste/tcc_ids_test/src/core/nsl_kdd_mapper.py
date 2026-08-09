# src/core/nsl_kdd_mapper.py
"""
Mapeia pacotes capturados para features NSL-KDD
"""

from typing import Dict, Optional, Tuple
from scapy.all import IP, TCP, UDP, ICMP, Raw
import time
from collections import defaultdict
import logging

from src.core.feature_extractor import NetworkFlow

logger = logging.getLogger(__name__)


class NSLKDDMapper:
    """
    Converte pacotes capturados para NetworkFlow no formato NSL-KDD.
    """
    
    def __init__(self):
        # Estado das conexões
        self.connections = {}
        
        # Mapeamento de serviços por porta
        self.service_map = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3',
            111: 'rpc', 135: 'netbios-ssn', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds',
            993: 'imaps', 995: 'pop3s', 3306: 'mysql',
            3389: 'ms-sql', 5432: 'postgresql', 6379: 'redis',
            8080: 'http-alt'
        }
        
        # Mapeamento de flags TCP
        self.flag_map = {
            'S': 'S0',      # SYN
            'SA': 'SF',     # SYN-ACK
            'A': 'S2',      # ACK
            'R': 'REJ',     # RST
            'RA': 'RSTO',   # RST-ACK
            'F': 'S1',      # FIN
            'FA': 'S3',     # FIN-ACK
            '': 'OTH'       # Outros
        }
    
    def get_service(self, dst_port: int, protocol: str) -> str:
        """Mapeia porta para serviço."""
        if protocol == 'icmp':
            return 'icmp'
        return self.service_map.get(dst_port, 'other')
    
    def get_flag(self, packet) -> str:
        """Extrai flag TCP."""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.flags
            
            if flags & 0x02:  # SYN
                if flags & 0x10:  # ACK
                    return 'SF'
                return 'S0'
            elif flags & 0x01:  # FIN
                return 'S1'
            elif flags & 0x04:  # RST
                if flags & 0x10:  # ACK
                    return 'RSTO'
                return 'REJ'
            elif flags & 0x10:  # ACK
                return 'S2'
            else:
                return 'OTH'
        return 'OTH'
    
    def packet_to_flow(self, packet) -> Optional[NetworkFlow]:
        """
        Converte um pacote para NetworkFlow.
        Retorna None se não for possível extrair um fluxo completo.
        """
        try:
            if not packet.haslayer(IP):
                return None
            
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            
            # Determinar protocolo
            if packet.haslayer(TCP):
                protocol = 'tcp'
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flag = self.get_flag(packet)
            elif packet.haslayer(UDP):
                protocol = 'udp'
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                flag = 'OTH'
            elif packet.haslayer(ICMP):
                protocol = 'icmp'
                sport = 0
                dport = 0
                flag = 'OTH'
            else:
                return None
            
            # Identificador único da conexão
            conn_key = (src_ip, dst_ip, sport, dport, protocol)
            
            # Atualizar conexão existente ou criar nova
            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'src_bytes': 0,
                    'dst_bytes': 0,
                    'packets': 0,
                    'flags': [],
                    'service': self.get_service(dport, protocol),
                    'protocol_type': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': sport,
                    'dst_port': dport,
                    'flag': flag
                }
            
            conn = self.connections[conn_key]
            conn['last_seen'] = time.time()
            conn['packets'] += 1
            
            # Calcular bytes
            src_bytes = len(packet) if packet.haslayer(Raw) else 0
            conn['src_bytes'] += src_bytes
            conn['dst_bytes'] += len(packet) - src_bytes
            conn['flags'].append(flag)
            conn['flag'] = flag  # Última flag
            
            # Se a conexão estiver completa, retornar o fluxo
            if conn['packets'] >= 5 or (time.time() - conn['first_seen']) > 60:
                return self._build_flow(conn_key, conn)
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")
            return None
    
    def _build_flow(self, conn_key: Tuple, conn: Dict) -> NetworkFlow:
        """Constrói NetworkFlow a partir de uma conexão."""
        duration = conn['last_seen'] - conn['first_seen']
        total_packets = conn['packets']
        
        # Calcular taxas de erro
        serror_count = sum(1 for f in conn['flags'] if f in ['REJ', 'RSTO'])
        rerror_count = sum(1 for f in conn['flags'] if f in ['RSTO'])
        
        # Remover conexão do estado
        del self.connections[conn_key]
        
        return NetworkFlow(
            src_ip=conn['src_ip'],
            dst_ip=conn['dst_ip'],
            src_port=conn['src_port'],
            dst_port=conn['dst_port'],
            protocol_type=conn['protocol_type'],
            duration=duration,
            src_bytes=conn['src_bytes'],
            dst_bytes=conn['dst_bytes'],
            flag=conn['flag'],
            service=conn['service'],
            count=total_packets,
            srv_count=total_packets,
            serror_rate=serror_count / total_packets if total_packets > 0 else 0,
            srv_serror_rate=serror_count / total_packets if total_packets > 0 else 0,
            rerror_rate=rerror_count / total_packets if total_packets > 0 else 0,
            srv_rerror_rate=rerror_count / total_packets if total_packets > 0 else 0,
            same_srv_rate=1.0,
            diff_srv_rate=0.0,
            dst_host_count=1,
            dst_host_srv_count=1,
            dst_host_same_srv_rate=1.0,
            dst_host_diff_srv_rate=0.0,
            dst_host_serror_rate=serror_count / total_packets if total_packets > 0 else 0
        )