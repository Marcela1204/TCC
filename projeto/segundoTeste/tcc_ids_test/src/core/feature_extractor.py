# src/core/feature_extractor.py
"""
Feature Extractor corrigido - versão estável para testes
"""

import pickle
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NetworkFlow:
    """Representa um fluxo de rede - VERSÃO CORRIGIDA"""
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
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    count: int = 1
    srv_count: int = 1
    serror_rate: float = 0.0
    srv_serror_rate: float = 0.0
    rerror_rate: float = 0.0
    srv_rerror_rate: float = 0.0
    same_srv_rate: float = 1.0
    diff_srv_rate: float = 0.0
    srv_diff_host_rate: float = 0.0
    dst_host_count: int = 1
    dst_host_srv_count: int = 1
    dst_host_same_srv_rate: float = 1.0
    dst_host_diff_srv_rate: float = 0.0
    dst_host_same_src_port_rate: float = 0.0
    dst_host_srv_diff_host_rate: float = 0.0
    dst_host_serror_rate: float = 0.0
    dst_host_srv_serror_rate: float = 0.0
    dst_host_rerror_rate: float = 0.0
    dst_host_srv_rerror_rate: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    is_attack: bool = False


class FeatureExtractor:
    """Extrator de features - VERSÃO CORRIGIDA"""
    
    # AGORA com 16 features (as que realmente existem no NetworkFlow)
    SELECTED_FEATURES = [
        'src_bytes',
        'dst_host_srv_count',
        'count',
        'dst_bytes',
        'hot',
        'dst_host_same_src_port_rate',
        'logged_in',
        'srv_count',
        'dst_host_same_srv_rate',
        'duration',
        'wrong_fragment',
        'dst_host_diff_srv_rate',
        'dst_host_count',
        'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate',
        'diff_srv_rate'
    ]
    
    # Features que NÃO estão no NetworkFlow (vamos ignorar)
    # - dst_host_srv_terror_rate (não existe)
    # - dst_host_terror_rate (não existe)
    
    CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
    
    def __init__(self, model_dir: str = './models'):
        self.model_dir = model_dir
        self.scaler = None
        self.label_encoders = {}
        self.is_initialized = False
        
    def flow_to_dict(self, flow: NetworkFlow) -> Dict:
        """Converte NetworkFlow para dicionário."""
        return {
            'duration': flow.duration,
            'protocol_type': flow.protocol,
            'service': flow.service,
            'flag': flow.flag,
            'src_bytes': flow.src_bytes,
            'dst_bytes': flow.dst_bytes,
            'land': flow.land,
            'wrong_fragment': flow.wrong_fragment,
            'urgent': flow.urgent,
            'hot': flow.hot,
            'num_failed_logins': flow.num_failed_logins,
            'logged_in': flow.logged_in,
            'num_compromised': flow.num_compromised,
            'root_shell': flow.root_shell,
            'su_attempted': flow.su_attempted,
            'num_root': flow.num_root,
            'num_file_creations': flow.num_file_creations,
            'num_shells': flow.num_shells,
            'num_access_files': flow.num_access_files,
            'num_outbound_cmds': flow.num_outbound_cmds,
            'is_host_login': flow.is_host_login,
            'is_guest_login': flow.is_guest_login,
            'count': flow.count,
            'srv_count': flow.srv_count,
            'serror_rate': flow.serror_rate,
            'srv_serror_rate': flow.srv_serror_rate,
            'rerror_rate': flow.rerror_rate,
            'srv_rerror_rate': flow.srv_rerror_rate,
            'same_srv_rate': flow.same_srv_rate,
            'diff_srv_rate': flow.diff_srv_rate,
            'srv_diff_host_rate': flow.srv_diff_host_rate,
            'dst_host_count': flow.dst_host_count,
            'dst_host_srv_count': flow.dst_host_srv_count,
            'dst_host_same_srv_rate': flow.dst_host_same_srv_rate,
            'dst_host_diff_srv_rate': flow.dst_host_diff_srv_rate,
            'dst_host_same_src_port_rate': flow.dst_host_same_src_port_rate,
            'dst_host_srv_diff_host_rate': flow.dst_host_srv_diff_host_rate,
            'dst_host_serror_rate': flow.dst_host_serror_rate,
            'dst_host_srv_serror_rate': flow.dst_host_srv_serror_rate,
            'dst_host_rerror_rate': flow.dst_host_rerror_rate,
            'dst_host_srv_rerror_rate': flow.dst_host_srv_rerror_rate
        }
    
    def load_artifacts(self):
        """Carrega ou cria artefatos."""
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Se não existir, cria fakes
        if not os.path.exists(f'{self.model_dir}/scaler.pkl'):
            logger.warning("Artefatos não encontrados. Criando fakes para teste...")
            self._create_fake_artifacts()
            return
        
        # Carregar scaler
        with open(f'{self.model_dir}/scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Carregar label encoders
        for col in self.CATEGORICAL_COLS:
            try:
                with open(f'{self.model_dir}/label_encoder_{col}.pkl', 'rb') as f:
                    self.label_encoders[col] = pickle.load(f)
            except:
                logger.warning(f"Encoder para {col} não encontrado, criando...")
                le = LabelEncoder()
                le.fit(['tcp', 'udp', 'icmp'] if col == 'protocol_type' 
                       else ['http', 'smtp', 'dns', 'ftp', 'other']
                       if col == 'service'
                       else ['SF', 'S0', 'REJ', 'RSTO', 'OTH'])
                self.label_encoders[col] = le
        
        self.is_initialized = True
        logger.info("Artefatos carregados com sucesso!")
    
    def _create_fake_artifacts(self):
        """Cria artefatos fakes com o número CORRETO de features."""
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        
        # Criar scaler com 16 features (NÃO 18!)
        self.scaler = StandardScaler()
        fake_data = np.random.randn(100, len(self.SELECTED_FEATURES))
        self.scaler.fit(fake_data)
        
        # Criar label encoders
        for col in self.CATEGORICAL_COLS:
            le = LabelEncoder()
            le.fit(['tcp', 'udp', 'icmp'] if col == 'protocol_type' 
                   else ['http', 'smtp', 'dns', 'ftp', 'other']
                   if col == 'service'
                   else ['SF', 'S0', 'REJ', 'RSTO', 'OTH'])
            self.label_encoders[col] = le
        
        # Salvar
        os.makedirs(self.model_dir, exist_ok=True)
        with open(f'{self.model_dir}/scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        
        for col, le in self.label_encoders.items():
            with open(f'{self.model_dir}/label_encoder_{col}.pkl', 'wb') as f:
                pickle.dump(le, f)
        
        self.is_initialized = True
        logger.info("Artefatos fakes criados para teste")
    
    def extract_features(self, flow: NetworkFlow) -> np.ndarray:
        """Extrai features padronizadas."""
        if not self.is_initialized:
            self.load_artifacts()
        
        flow_dict = self.flow_to_dict(flow)
        
        # Codificar categóricas
        for col in self.CATEGORICAL_COLS:
            col_name = col
            if col_name in self.label_encoders:
                try:
                    value = flow_dict.get(col_name, 'tcp')
                    flow_dict[col_name] = int(self.label_encoders[col_name].transform([value])[0])
                except:
                    flow_dict[col_name] = 0
        
        # Criar DataFrame
        df = pd.DataFrame([flow_dict])
        
        # IMPORTANTE: Selecionar APENAS as features que existem
        available_features = [f for f in self.SELECTED_FEATURES if f in df.columns]
        
        # Se alguma feature faltar, adicionar com valor padrão
        for f in self.SELECTED_FEATURES:
            if f not in df.columns:
                df[f] = 0
        
        # Selecionar na ordem correta
        df = df[self.SELECTED_FEATURES]
        
        # Verificar número de features
        if df.shape[1] != len(self.SELECTED_FEATURES):
            logger.error(f"Erro: esperava {len(self.SELECTED_FEATURES)} features, mas tem {df.shape[1]}")
            raise ValueError(f"Incompatibilidade de features: esperava {len(self.SELECTED_FEATURES)}, tem {df.shape[1]}")
        
        # Padronizar
        features_array = df.values.reshape(1, -1)
        
        try:
            scaled_features = self.scaler.transform(features_array)
        except Exception as e:
            logger.error(f"Erro no scaler: {e}")
            logger.error(f"Features shape: {features_array.shape}")
            logger.error(f"Scaler espera: {self.scaler.mean_.shape[0] if hasattr(self.scaler, 'mean_') else '?'}")
            raise
        
        return scaled_features[0]