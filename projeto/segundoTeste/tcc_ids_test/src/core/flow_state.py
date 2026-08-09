# src/core/flow_state.py
"""
Gerencia o estado das conexões para calcular features temporais.
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import logging
from src.core.feature_extractor import NetworkFlow

logger = logging.getLogger(__name__)


class FlowStateManager:
    """
    Mantém estado das conexões para calcular features como:
    - count: conexões no mesmo host nos últimos 2s
    - srv_count: conexões na mesma porta
    - rates: taxas de erro
    - dst_host_*: estatísticas do host destino
    """
    
    def __init__(self, window_seconds: int = 2, max_history: int = 1000):
        self.window_seconds = window_seconds
        self.max_history = max_history
        
        # Histórico de conexões: { (src_ip, dst_ip): [conexões] }
        self.connections: Dict[Tuple[str, str], List[NetworkFlow]] = defaultdict(list)
        
        # Histórico por serviço
        self.service_connections: Dict[str, List[NetworkFlow]] = defaultdict(list)
        
        # Histórico por host destino
        self.dst_connections: Dict[str, List[NetworkFlow]] = defaultdict(list)
        
        logger.info(f"FlowStateManager inicializado (window={window_seconds}s)")
        
    def add_connection(self, flow: NetworkFlow):
        """Adiciona uma conexão ao histórico."""
        # Adicionar timestamp se não tiver
        if not hasattr(flow, 'timestamp'):
            flow.timestamp = datetime.now()
            
        # Remover conexões antigas
        self._cleanup()
        
        # Adicionar ao histórico geral
        key = (flow.src_ip, flow.dst_ip)
        self.connections[key].append(flow)
        
        # Adicionar ao histórico por serviço
        self.service_connections[flow.service].append(flow)
        
        # Adicionar ao histórico por destino
        self.dst_connections[flow.dst_ip].append(flow)
        
        # Limitar histórico
        if len(self.connections[key]) > self.max_history:
            self.connections[key] = self.connections[key][-self.max_history:]
    
    def _cleanup(self):
        """Remove conexões antigas."""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        for key in list(self.connections.keys()):
            self.connections[key] = [
                f for f in self.connections[key]
                if hasattr(f, 'timestamp') and f.timestamp > cutoff
            ]
            if not self.connections[key]:
                del self.connections[key]
    
    def compute_features(self, flow: NetworkFlow) -> NetworkFlow:
        """
        Computa features temporais para um fluxo.
        Atualiza o objeto flow com as features calculadas.
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Filtrar conexões recentes
        recent_connections = []
        for conn_list in self.connections.values():
            recent_connections.extend([
                f for f in conn_list 
                if hasattr(f, 'timestamp') and f.timestamp > cutoff
            ])
        
        # count: conexões para o mesmo host destino
        flow.count = sum(1 for f in recent_connections 
                        if f.dst_ip == flow.dst_ip)
        
        # srv_count: conexões para o mesmo serviço
        flow.srv_count = sum(1 for f in recent_connections 
                            if f.service == flow.service)
        
        # taxas de erro
        if flow.count > 0:
            total_to_host = [f for f in recent_connections if f.dst_ip == flow.dst_ip]
            flow.serror_rate = sum(1 for f in total_to_host if f.flag == 'REJ') / flow.count
            flow.rerror_rate = sum(1 for f in total_to_host if f.flag == 'RSTO') / flow.count
        else:
            flow.serror_rate = 0.0
            flow.rerror_rate = 0.0
        
        if flow.srv_count > 0:
            total_to_service = [f for f in recent_connections if f.service == flow.service]
            flow.srv_serror_rate = sum(1 for f in total_to_service if f.flag == 'REJ') / flow.srv_count
            flow.srv_rerror_rate = sum(1 for f in total_to_service if f.flag == 'RSTO') / flow.srv_count
        else:
            flow.srv_serror_rate = 0.0
            flow.srv_rerror_rate = 0.0
        
        # same_srv_rate: % de conexões para o mesmo serviço
        if flow.count > 0:
            total_to_host = [f for f in recent_connections if f.dst_ip == flow.dst_ip]
            same_srv = sum(1 for f in total_to_host if f.service == flow.service)
            flow.same_srv_rate = same_srv / flow.count if flow.count > 0 else 0.0
        else:
            flow.same_srv_rate = 0.0
        
        # diff_srv_rate: % de conexões para serviços diferentes
        flow.diff_srv_rate = 1.0 - flow.same_srv_rate
        
        # dst_host_* features
        dst_connections = self.dst_connections.get(flow.dst_ip, [])
        if dst_connections:
            flow.dst_host_count = len(dst_connections)
            flow.dst_host_srv_count = sum(1 for f in dst_connections if f.service == flow.service)
            
            if flow.dst_host_count > 0:
                flow.dst_host_same_srv_rate = flow.dst_host_srv_count / flow.dst_host_count
            else:
                flow.dst_host_same_srv_rate = 0.0
            
            # dst_host_serror_rate
            serrors = sum(1 for f in dst_connections if f.flag == 'REJ')
            flow.dst_host_serror_rate = serrors / flow.dst_host_count if flow.dst_host_count > 0 else 0.0
            
        return flow
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do estado."""
        return {
            'total_connections': sum(len(v) for v in self.connections.values()),
            'unique_connections': len(self.connections),
            'unique_services': len(self.service_connections),
            'unique_destinations': len(self.dst_connections)
        }