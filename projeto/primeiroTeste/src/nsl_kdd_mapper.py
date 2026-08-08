# src/core/nsl_kdd_mapper.py
"""
Converte pacotes capturados em features no formato NSL-KDD.
Este é o coração do sistema - transforma tráfego real em dados que
o modelo Decision Tree entende.
"""

from typing import Dict, Optional, Tuple
from scapy.all import IP, TCP, UDP, ICMP, Raw
import time
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class NSLKDDMapper:
    """
    Mapeia pacotes/scapy para features no formato NSL-KDD.
    Mantém estado para calcular features baseadas em conexões.
    """
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        
        # Estado das conexões: {(src_ip, dst_ip, src_port, dst_port, proto): flow_data}
        self.connections: Dict[Tuple, Dict] = {}
        
        # Histórico por destino (para dst_host_* features)
        self.dst_history: Dict[str, list] = defaultdict(list)
        
        # Mapeamento de protocolos
        self.proto_map = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp'
        }
        
        # Mapeamento de flags TCP
        self.flag_map = {
            'S': 'S0',      # SYN
            'SA': 'SF',     # SYN-ACK (conexão normal)
            'A': 'S2',      # ACK
            'R': 'REJ',     # RST (conexão rejeitada)
            'RA': 'RSTO',   # RST-ACK
            'F': 'S1',      # FIN
            'FA': 'S3',     # FIN-ACK
            '': 'OTH'       # Outros
        }
        
        # Serviços comuns (baseado em portas)
        self.service_map = {
            20: 'ftp_data',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'domain',
            80: 'http',
            110: 'pop3',
            111: 'rpc',
            135: 'netbios-ssn',
            139: 'netbios-ssn',
            143: 'imap',
            443: 'https',
            445: 'microsoft-ds',
            993: 'imaps',
            995: 'pop3s',
            3306: 'mysql',
            3389: 'ms-sql',
            5432: 'postgresql',
            6379: 'redis',
            8080: 'http-alt',
        }
    
    def get_service(self, dst_port: int, protocol: str) -> str:
        """Mapeia porta para serviço (formato NSL-KDD)."""
        if protocol == 'icmp':
            return 'icmp'
        
        return self.service_map.get(dst_port, 'other')
    
    def get_flag(self, packet) -> str:
        """Extrai flag TCP no formato NSL-KDD."""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.flags
            
            # Mapear flags
            if flags & 0x02:  # SYN
                if flags & 0x10:  # ACK
                    return 'SF'  # SYN-ACK = conexão normal
                return 'S0'  # SYN
            elif flags & 0x01:  # FIN
                if flags & 0x10:  # ACK
                    return 'S1'  # FIN-ACK
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
    
    def packet_to_flow(self, packet) -> Optional[Dict]:
        """
        Converte um pacote capturado em um dicionário de features.
        Retorna None se o pacote não for IP.
        """
        if not packet.haslayer(IP):
            return None
        
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto
        
        # Mapear protocolo
        protocol = 'tcp' if proto == 6 else 'udp' if proto == 17 else 'icmp'
        
        # Portas
        src_port = 0
        dst_port = 0
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Identificador único da conexão
        conn_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        # Atualizar ou criar conexão
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'first_seen': time.time(),
                'last_seen': time.time(),
                'packets': [],
                'src_bytes': 0,
                'dst_bytes': 0,
                'duration': 0,
                'flags': [],
                'service': self.get_service(dst_port, protocol),
                'protocol_type': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'flag': 'SF',  # Default
                'count': 0,
                'srv_count': 0,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 0.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 0,
                'dst_host_srv_count': 0,
                'dst_host_same_srv_rate': 0.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0,
                'is_attack': False  # Será preenchido pelo modelo
            }
        
        # Atualizar conexão
        conn = self.connections[conn_key]
        conn['last_seen'] = time.time()
        
        # Calcular bytes
        src_bytes = len(packet) if packet.haslayer(Raw) else 0
        conn['src_bytes'] += src_bytes
        conn['dst_bytes'] += len(packet) - src_bytes
        
        # Flag
        flag = self.get_flag(packet)
        conn['flags'].append(flag)
        conn['flag'] = flag  # Última flag
        
        # Atualizar contagens
        conn['packets'].append(packet)
        
        # Se a conexão estiver completa, retornar as features
        if len(conn['packets']) >= 10 or (time.time() - conn['first_seen']) > 60:
            return self._build_nsl_kdd_features(conn_key, conn)
        
        # Se timeout, retornar mesmo incompleta
        if (time.time() - conn['first_seen']) > 120:
            return self._build_nsl_kdd_features(conn_key, conn)
        
        return None
    
    def _build_nsl_kdd_features(self, conn_key: Tuple, conn: Dict) -> Dict:
        """
        Constrói features no formato NSL-KDD a partir de uma conexão.
        """
        duration = conn['last_seen'] - conn['first_seen']
        total_packets = len(conn['packets'])
        
        # Flags de erro
        serror_count = sum(1 for f in conn['flags'] if f in ['REJ', 'RSTO'])
        rerror_count = sum(1 for f in conn['flags'] if f in ['RSTO'])
        
        # Features básicas
        features = {
            'duration': duration,
            'protocol_type': conn['protocol_type'],
            'service': conn['service'],
            'flag': conn['flag'],
            'src_bytes': conn['src_bytes'],
            'dst_bytes': conn['dst_bytes'],
            'land': 1 if conn['src_ip'] == conn['dst_ip'] else 0,
            'wrong_fragment': 0,  # Não temos como capturar isso facilmente
            'urgent': 0,
            'hot': 0,  # Não temos
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': total_packets,
            'srv_count': total_packets,  # Simplificado
            'serror_rate': serror_count / total_packets if total_packets > 0 else 0,
            'srv_serror_rate': serror_count / total_packets if total_packets > 0 else 0,
            'rerror_rate': rerror_count / total_packets if total_packets > 0 else 0,
            'srv_rerror_rate': rerror_count / total_packets if total_packets > 0 else 0,
            'same_srv_rate': 1.0,  # Simplificado
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': serror_count / total_packets if total_packets > 0 else 0,
            'dst_host_srv_serror_rate': serror_count / total_packets if total_packets > 0 else 0,
            'dst_host_rerror_rate': rerror_count / total_packets if total_packets > 0 else 0,
            'dst_host_srv_rerror_rate': rerror_count / total_packets if total_packets > 0 else 0,
            'is_attack': False  # Será preenchido depois
        }
        
        # Remover conexão do estado
        del self.connections[conn_key]
        
        return features