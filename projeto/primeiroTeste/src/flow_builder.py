# src/core/flow_builder.py
"""
Constrói objetos NetworkFlow completos a partir de dados capturados.
"""

from typing import Dict, Optional
from src.core.feature_extractor import NetworkFlow
import logging

logger = logging.getLogger(__name__)


class FlowBuilder:
    """
    Constrói NetworkFlow a partir de features NSL-KDD extraídas.
    """
    
    def build_flow(self, features: Dict) -> NetworkFlow:
        """
        Constrói um NetworkFlow a partir de um dicionário de features.
        """
        try:
            flow = NetworkFlow(
                # Identificação
                src_ip=features.get('src_ip', '0.0.0.0'),
                dst_ip=features.get('dst_ip', '0.0.0.0'),
                src_port=features.get('src_port', 0),
                dst_port=features.get('dst_port', 0),
                protocol=features.get('protocol_type', 'tcp'),
                
                # Métricas
                duration=features.get('duration', 0.0),
                src_bytes=features.get('src_bytes', 0),
                dst_bytes=features.get('dst_bytes', 0),
                flag=features.get('flag', 'SF'),
                service=features.get('service', 'other'),
                land=features.get('land', 0),
                wrong_fragment=features.get('wrong_fragment', 0),
                urgent=features.get('urgent', 0),
                
                # Autenticação
                hot=features.get('hot', 0),
                num_failed_logins=features.get('num_failed_logins', 0),
                logged_in=features.get('logged_in', 0),
                num_compromised=features.get('num_compromised', 0),
                root_shell=features.get('root_shell', 0),
                su_attempted=features.get('su_attempted', 0),
                num_root=features.get('num_root', 0),
                num_file_creations=features.get('num_file_creations', 0),
                num_shells=features.get('num_shells', 0),
                num_access_files=features.get('num_access_files', 0),
                num_outbound_cmds=features.get('num_outbound_cmds', 0),
                is_host_login=features.get('is_host_login', 0),
                is_guest_login=features.get('is_guest_login', 0),
                
                # Features baseadas em conexões
                count=features.get('count', 0),
                srv_count=features.get('srv_count', 0),
                serror_rate=features.get('serror_rate', 0.0),
                srv_serror_rate=features.get('srv_serror_rate', 0.0),
                rerror_rate=features.get('rerror_rate', 0.0),
                srv_rerror_rate=features.get('srv_rerror_rate', 0.0),
                same_srv_rate=features.get('same_srv_rate', 0.0),
                diff_srv_rate=features.get('diff_srv_rate', 0.0),
                srv_diff_host_rate=features.get('srv_diff_host_rate', 0.0),
                
                # Features do host de destino
                dst_host_count=features.get('dst_host_count', 0),
                dst_host_srv_count=features.get('dst_host_srv_count', 0),
                dst_host_same_srv_rate=features.get('dst_host_same_srv_rate', 0.0),
                dst_host_diff_srv_rate=features.get('dst_host_diff_srv_rate', 0.0),
                dst_host_same_src_port_rate=features.get('dst_host_same_src_port_rate', 0.0),
                dst_host_srv_diff_host_rate=features.get('dst_host_srv_diff_host_rate', 0.0),
                dst_host_serror_rate=features.get('dst_host_serror_rate', 0.0),
                dst_host_srv_serror_rate=features.get('dst_host_srv_serror_rate', 0.0),
                dst_host_rerror_rate=features.get('dst_host_rerror_rate', 0.0),
                dst_host_srv_rerror_rate=features.get('dst_host_srv_rerror_rate', 0.0)
            )
            
            return flow
            
        except Exception as e:
            logger.error(f"Erro ao construir fluxo: {e}")
            raise