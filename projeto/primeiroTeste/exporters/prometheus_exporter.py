# src/exporters/prometheus_exporter.py
"""
Exporta métricas para Prometheus.
"""

from prometheus_client import Counter, Gauge, Histogram, start_http_server
from typing import Dict
import logging

logger = logging.getLogger(__name__)


class PrometheusExporter:
    """
    Exporta métricas do IDS para Prometheus.
    """
    
    def __init__(self, port: int = 8000):
        self.port = port
        
        # Métricas
        self.packets_total = Counter('ids_packets_total', 'Total de pacotes processados')
        self.flows_total = Counter('ids_flows_total', 'Total de fluxos processados')
        self.alerts_total = Counter('ids_alerts_total', 'Total de alertas gerados')
        
        self.attacks_total = Counter(
            'ids_attacks_total',
            'Total de ataques detectados',
            ['attack_type']
        )
        
        self.prediction_latency = Histogram(
            'ids_prediction_latency_seconds',
            'Latência da predição em segundos',
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
        )
        
        self.flows_active = Gauge('ids_flows_active', 'Número de fluxos ativos')
        self.confidence_score = Gauge('ids_confidence_score', 'Confiança média das predições')
        
        self.start_server()
    
    def start_server(self):
        """Inicia o servidor HTTP do Prometheus."""
        start_http_server(self.port)
        logger.info(f"Prometheus exporter rodando na porta {self.port}")
    
    def record_packet(self):
        """Registra um pacote processado."""
        self.packets_total.inc()
    
    def record_flow(self):
        """Registra um fluxo processado."""
        self.flows_total.inc()
    
    def record_alert(self, attack_type: str = 'unknown'):
        """Registra um alerta."""
        self.alerts_total.inc()
        self.attacks_total.labels(attack_type=attack_type).inc()
    
    def record_latency(self, seconds: float):
        """Registra latência da predição."""
        self.prediction_latency.observe(seconds)
    
    def update_active_flows(self, count: int):
        """Atualiza número de fluxos ativos."""
        self.flows_active.set(count)
    
    def update_confidence(self, confidence: float):
        """Atualiza confiança média."""
        self.confidence_score.set(confidence)