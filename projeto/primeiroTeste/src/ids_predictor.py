# src/core/ids_predictor.py (atualizado)
"""
Orquestra tudo - captura, processamento, predição e exportação.
"""

import time
import threading
from typing import Optional
from src.core.feature_extractor import FeatureExtractor, NetworkFlow
from src.core.packet_capture import PacketCapture
from src.core.flow_state import FlowStateManager
from src.exporters.prometheus_exporter import PrometheusExporter
from src.exporters.influxdb_exporter import InfluxDBExporter
from src.alerts.alert_manager import AlertManager
import logging

logger = logging.getLogger(__name__)


class IDSPredictor:
    """
    Sistema completo de predição de intrusões em tempo real.
    """
    
    def __init__(self, model_dir: str = './models'):
        self.model_dir = model_dir
        self.feature_extractor = FeatureExtractor(model_dir)
        self.flow_state = FlowStateManager()
        self.packet_capture = PacketCapture(self._process_flow)
        self.model = None
        self.is_initialized = False
        
        # Exportadores
        self.prometheus = PrometheusExporter(port=8000)
        self.influxdb = InfluxDBExporter()
        
        # Alertas
        self.alert_manager = AlertManager()
        
        # Estatísticas
        self.total_packets = 0
        self.total_flows = 0
        self.total_alerts = 0
        
    def initialize(self):
        """Inicializa todos os componentes."""
        self.feature_extractor.load_artifacts()
        self.load_model()
        self.is_initialized = True
        logger.info("IDS Predictor inicializado!")
    
    def load_model(self):
        """Carrega modelo Decision Tree."""
        import pickle
        try:
            with open(f'{self.model_dir}/decision_tree_model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            logger.info("Modelo carregado!")
        except Exception as e:
            logger.error(f"Erro ao carregar modelo: {e}")
            raise
    
    def start_capture(self, interface: str = 'eth0', mode: str = 'real_time'):
        """
        Inicia captura de pacotes.
        
        Args:
            interface: Interface de rede
            mode: 'real_time', 'pcap_file', 'tcpdump'
        """
        if not self.is_initialized:
            raise RuntimeError("IDS Predictor não inicializado.")
        
        logger.info(f"Iniciando captura na interface {interface} (modo: {mode})")
        
        if mode == 'real_time':
            self.packet_capture.start_real_time(interface)
        elif mode == 'tcpdump':
            self.packet_capture.start_tcpdump_live(interface)
        else:
            raise ValueError(f"Modo não suportado: {mode}")
    
    def _process_flow(self, flow: NetworkFlow):
        """
        Processa um fluxo completo: extrai features, prediz e exporta.
        """
        start_time = time.time()
        
        # 1. Computar features temporais
        flow = self.flow_state.compute_features(flow)
        
        # 2. Extrair features padronizadas
        features = self.feature_extractor.extract_features(flow)
        
        # 3. Predizer
        prediction = self.model.predict([features])[0]
        
        # 4. Calcular confiança
        try:
            proba = self.model.predict_proba([features])[0]
            confidence = max(proba)
        except:
            confidence = 1.0
        
        # 5. Registrar métricas
        self.total_packets += 1
        self.total_flows += 1
        
        self.prometheus.record_packet()
        self.prometheus.record_flow()
        
        latency = time.time() - start_time
        self.prometheus.record_latency(latency)
        
        # 6. Gerar alerta se ataque
        if prediction == 1:
            self.total_alerts += 1
            self.prometheus.record_alert('dos' if flow.service == 'http' else 'unknown')
            
            alert = self.alert_manager.generate_alert(flow, confidence)
            logger.warning(f"🚨 ATAQUE DETECTADO! {alert}")
            
            # Enviar notificação
            self.alert_manager.notify(alert)
        
        # 7. Exportar para InfluxDB
        self.influxdb.export_flow(flow, prediction, confidence)
        
        # 8. Adicionar ao histórico
        self.flow_state.add_connection(flow)
        
        # 9. Atualizar métricas do Prometheus
        self.prometheus.update_active_flows(len(self.flow_state.connections))
        self.prometheus.update_confidence(confidence)
        
        return prediction, confidence