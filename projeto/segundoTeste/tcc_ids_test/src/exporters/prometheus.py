# src/exporters/prometheus.py
"""
Exportador de métricas para Prometheus - Versão Simplificada
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


class PrometheusExporter:
    """
    Exporta métricas do IDS para Prometheus.
    Versão simplificada que apenas loga as métricas.
    """
    
    def __init__(self, port: int = 8000):
        self.port = port
        self.metrics = {
            'total_predictions': 0,
            'total_attacks': 0,
            'total_normal': 0,
            'avg_confidence': 0.0,
            'total_latency': 0.0
        }
        logger.info(f"✅ PrometheusExporter inicializado (porta {port})")
    
    def record_prediction(self, prediction: int, confidence: float, latency: float):
        """
        Registra uma predição.
        
        Args:
            prediction: 0=normal, 1=ataque
            confidence: Confiança da predição
            latency: Tempo de processamento em segundos
        """
        self.metrics['total_predictions'] += 1
        
        if prediction == 1:
            self.metrics['total_attacks'] += 1
        else:
            self.metrics['total_normal'] += 1
        
        # Média móvel da confiança
        n = self.metrics['total_predictions']
        self.metrics['avg_confidence'] = (
            self.metrics['avg_confidence'] * (n - 1) + confidence
        ) / n
        
        self.metrics['total_latency'] += latency
        
        # Log em modo debug
        if n % 100 == 0:
            logger.debug(f"📊 Métricas: {self.get_metrics()}")
    
    def get_metrics(self) -> Dict:
        """Retorna as métricas atuais."""
        return {
            'total_predictions': self.metrics['total_predictions'],
            'total_attacks': self.metrics['total_attacks'],
            'total_normal': self.metrics['total_normal'],
            'attack_rate': self.metrics['total_attacks'] / max(self.metrics['total_predictions'], 1),
            'avg_confidence': self.metrics['avg_confidence'],
            'avg_latency': self.metrics['total_latency'] / max(self.metrics['total_predictions'], 1)
        }