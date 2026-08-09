# src/core/feature_extractor.py
"""
Feature Extractor - Versão Final
Compatível com os artefatos do MVP1 (18 features)
"""

import pickle
import json
import numpy as np
import pandas as pd
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NetworkFlow:
    """
    Representa um fluxo de rede no formato NSL-KDD.
    Contém todas as 41 features do NSL-KDD.
    """
    # Identificação
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    
    # Features básicas (1-9)
    duration: float = 0.0
    protocol_type: str = "tcp"
    service: str = "http"
    flag: str = "SF"
    src_bytes: int = 0
    dst_bytes: int = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    
    # Features de conteúdo (10-22)
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
    
    # Features baseadas em tempo (23-31)
    count: int = 0
    srv_count: int = 0
    serror_rate: float = 0.0
    srv_serror_rate: float = 0.0
    rerror_rate: float = 0.0
    srv_rerror_rate: float = 0.0
    same_srv_rate: float = 0.0
    diff_srv_rate: float = 0.0
    srv_diff_host_rate: float = 0.0
    
    # Features baseadas em host (32-41)
    dst_host_count: int = 0
    dst_host_srv_count: int = 0
    dst_host_same_srv_rate: float = 0.0
    dst_host_diff_srv_rate: float = 0.0
    dst_host_same_src_port_rate: float = 0.0
    dst_host_srv_diff_host_rate: float = 0.0
    dst_host_serror_rate: float = 0.0
    dst_host_srv_serror_rate: float = 0.0
    dst_host_rerror_rate: float = 0.0
    dst_host_srv_rerror_rate: float = 0.0
    
    # Metadados
    timestamp: datetime = field(default_factory=datetime.now)
    is_attack: bool = False
    confidence: float = 0.0


class FeatureExtractor:
    """
    Extrator de features compatível com o MVP1.
    Usa os artefatos salvos (scaler, encoders, features selecionadas).
    """
    
    def __init__(self, model_dir: str = './models'):
        self.model_dir = model_dir
        self.scaler = None
        self.label_encoders = {}
        self.selected_features = []
        self.is_initialized = False
        self.categorical_cols = ['protocol_type', 'service', 'flag']
        
    def load_artifacts(self) -> bool:
        """
        Carrega todos os artefatos salvos do MVP1.
        
        Returns:
            bool: True se carregou com sucesso
        """
        try:
            # 1. Carregar scaler
            with open(f'{self.model_dir}/scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
            logger.info(f"✅ Scaler carregado (features: {self.scaler.mean_.shape[0]})")
            
            # 2. Carregar label encoders
            for col in self.categorical_cols:
                try:
                    with open(f'{self.model_dir}/label_encoder_{col}.pkl', 'rb') as f:
                        self.label_encoders[col] = pickle.load(f)
                    logger.info(f"✅ Encoder carregado: {col}")
                except FileNotFoundError:
                    logger.warning(f"⚠️ Encoder {col} não encontrado, criando padrão...")
                    from sklearn.preprocessing import LabelEncoder
                    le = LabelEncoder()
                    le.fit(['tcp', 'udp', 'icmp'] if col == 'protocol_type' 
                           else ['http', 'smtp', 'dns', 'ftp', 'other']
                           if col == 'service'
                           else ['SF', 'S0', 'REJ', 'RSTO', 'OTH'])
                    self.label_encoders[col] = le
            
            # 3. Carregar features selecionadas
            try:
                with open(f'{self.model_dir}/selected_features.json', 'r') as f:
                    self.selected_features = json.load(f)
            except FileNotFoundError:
                # Fallback: usar as 18 features do MVP1
                self.selected_features = [
                    'src_bytes', 'dst_host_srv_count', 'count', 'dst_bytes',
                    'dst_host_srv_terror_rate', 'hot', 'dst_host_same_src_port_rate',
                    'logged_in', 'srv_count', 'dst_host_same_srv_rate',
                    'duration', 'wrong_fragment', 'dst_host_terror_rate',
                    'dst_host_diff_srv_rate', 'dst_host_count',
                    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                    'diff_srv_rate'
                ]
                logger.warning(f"⚠️ Usando features padrão: {len(self.selected_features)} features")
            
            self.is_initialized = True
            logger.info(f"🎯 FeatureExtractor inicializado com {len(self.selected_features)} features")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao carregar artefatos: {e}")
            return False
    
    def flow_to_dict(self, flow: NetworkFlow) -> Dict:
        """Converte NetworkFlow para dicionário de features."""
        return {
            'duration': flow.duration,
            'protocol_type': flow.protocol_type,
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
    
    def _encode_categorical(self, value: str, col_name: str) -> int:
        """Codifica um valor categórico usando o LabelEncoder salvo."""
        if col_name not in self.label_encoders:
            logger.warning(f"⚠️ Encoder para {col_name} não encontrado")
            return 0
        
        try:
            return int(self.label_encoders[col_name].transform([value])[0])
        except ValueError:
            # Valor desconhecido - usar o primeiro da lista
            logger.warning(f"⚠️ Valor desconhecido para {col_name}: {value}")
            return 0
    
    def extract_features(self, flow: NetworkFlow) -> Optional[np.ndarray]:
        """
        Extrai e padroniza as features de um fluxo.
        
        Args:
            flow: NetworkFlow com os dados
            
        Returns:
            np.ndarray: Features padronizadas (prontas para o modelo)
            None: Se houve erro
        """
        if not self.is_initialized:
            if not self.load_artifacts():
                return None
        
        try:
            # 1. Converter para dicionário
            flow_dict = self.flow_to_dict(flow)
            
            # 2. Codificar features categóricas
            for col in self.categorical_cols:
                flow_dict[col] = self._encode_categorical(flow_dict[col], col)
            
            # 3. Criar DataFrame
            df = pd.DataFrame([flow_dict])
            
            # 4. Selecionar apenas as features importantes
            available_features = [f for f in self.selected_features if f in df.columns]
            
            # Se alguma feature faltar, adicionar com valor 0
            for f in self.selected_features:
                if f not in df.columns:
                    df[f] = 0
                    logger.debug(f"Feature {f} não encontrada, usando 0")
            
            # Selecionar na ordem correta
            df = df[self.selected_features]
            
            # 5. Padronizar
            features_array = df.values.reshape(1, -1)
            
            # Verificar compatibilidade
            if features_array.shape[1] != self.scaler.mean_.shape[0]:
                logger.error(f"❌ Incompatibilidade: {features_array.shape[1]} features vs {self.scaler.mean_.shape[0]} esperadas")
                return None
            
            scaled_features = self.scaler.transform(features_array)
            
            return scaled_features[0]
            
        except Exception as e:
            logger.error(f"❌ Erro ao extrair features: {e}")
            return None