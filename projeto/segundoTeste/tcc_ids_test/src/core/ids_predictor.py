# src/core/ids_predictor.py
"""
IDS Predictor - Versão Final
Orquestra captura, extração, predição e exportação
"""

import pickle
import time
import threading
from typing import Optional, Dict, List, Tuple
from datetime import datetime
import logging

from src.core.feature_extractor import FeatureExtractor, NetworkFlow
from src.core.flow_state import FlowStateManager
from src.exporters.prometheus import PrometheusExporter
from src.alerts.alert_manager import AlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IDSPredictor:
    """
    Sistema completo de detecção de intrusões em tempo real.
    """
    
    def __init__(self, model_dir: str = './models'):
        self.model_dir = model_dir
        self.extractor = FeatureExtractor(model_dir)
        self.flow_state = FlowStateManager()
        self.alert_manager = AlertManager()
        self.model = None
        self.is_initialized = False
        
        # Métricas
        self.stats = {
            'total_flows': 0,
            'total_attacks': 0,
            'total_normal': 0,
            'avg_confidence': 0.0,
            'start_time': datetime.now()
        }
        
        # Exportadores
        self.prometheus = PrometheusExporter()
    
    def initialize(self) -> bool:
        """Inicializa todos os componentes."""
        logger.info("🚀 Inicializando IDS Predictor...")
        
        # 1. Carregar feature extractor
        if not self.extractor.load_artifacts():
            logger.error("❌ Falha ao carregar feature extractor")
            return False
        
        # 2. Carregar modelo Decision Tree
        try:
            with open(f'{self.model_dir}/decision_tree_model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"✅ Modelo carregado: {type(self.model).__name__}")
        except Exception as e:
            logger.error(f"❌ Falha ao carregar modelo: {e}")
            return False
        
        self.is_initialized = True
        logger.info("✅ IDS Predictor inicializado com sucesso!")
        return True
    
    def predict(self, flow: NetworkFlow) -> Tuple[int, float, Optional[str]]:
        """
        Prediz se um fluxo é ataque ou normal.
        
        Args:
            flow: NetworkFlow a ser classificado
            
        Returns:
            prediction: 0=normal, 1=ataque
            confidence: Confiança da predição (0-1)
            alert_message: Mensagem de alerta (se ataque)
        """
        if not self.is_initialized:
            logger.error("❌ IDS não inicializado")
            return 0, 0.0, None
        
        start_time = time.time()
        
        # 1. Extrair features
        features = self.extractor.extract_features(flow)
        if features is None:
            return 0, 0.0, None
        
        # 2. Predizer
        try:
            prediction = int(self.model.predict([features])[0])
            probabilities = self.model.predict_proba([features])[0]
            confidence = float(max(probabilities))
        except Exception as e:
            logger.error(f"❌ Erro na predição: {e}")
            return 0, 0.0, None
        
        # 3. Atualizar estatísticas
        self.stats['total_flows'] += 1
        if prediction == 1:
            self.stats['total_attacks'] += 1
        else:
            self.stats['total_normal'] += 1
        
        # Média móvel da confiança
        self.stats['avg_confidence'] = (
            self.stats['avg_confidence'] * (self.stats['total_flows'] - 1) + confidence
        ) / self.stats['total_flows']
        
        # 4. Gerar alerta se ataque
        alert_message = None
        if prediction == 1:
            alert_message = self.alert_manager.generate_alert(flow, confidence)
            self.alert_manager.send_alert(alert_message)
            logger.warning(f"🚨 ATAQUE DETECTADO! {alert_message}")
        
        # 5. Exportar métricas
        self.prometheus.record_prediction(prediction, confidence, time.time() - start_time)
        
        # 6. Atualizar estado do fluxo
        flow.is_attack = bool(prediction)
        flow.confidence = confidence
        self.flow_state.add_connection(flow)
        
        return prediction, confidence, alert_message
    
    def predict_batch(self, flows: List[NetworkFlow]) -> List[Dict]:
        """Prediz múltiplos fluxos em lote."""
        results = []
        for flow in flows:
            pred, conf, alert = self.predict(flow)
            results.append({
                'flow': flow,
                'prediction': pred,
                'confidence': conf,
                'alert': alert
            })
        return results
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do sistema."""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        return {
            'total_flows': self.stats['total_flows'],
            'total_attacks': self.stats['total_attacks'],
            'total_normal': self.stats['total_normal'],
            'attack_rate': self.stats['total_attacks'] / max(self.stats['total_flows'], 1),
            'avg_confidence': self.stats['avg_confidence'],
            'uptime_seconds': uptime,
            'is_initialized': self.is_initialized
        }