# src/alerts/alert_manager.py
"""
Gerenciador de Alertas - Versão Simplificada
"""

import logging
from datetime import datetime
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Gera e gerencia alertas de intrusão.
    """
    
    def __init__(self):
        self.alerts: List[Dict] = []
        self.max_alerts = 1000
        logger.info("✅ AlertManager inicializado")
    
    def generate_alert(self, flow, confidence: float) -> Dict:
        """
        Gera um alerta para um ataque detectado.
        
        Args:
            flow: NetworkFlow detectado como ataque
            confidence: Confiança da detecção
            
        Returns:
            Dict com os dados do alerta
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'ATTACK_DETECTED',
            'severity': 'HIGH' if confidence > 0.8 else 'MEDIUM',
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': flow.protocol_type,
            'service': flow.service,
            'confidence': confidence,
            'src_bytes': flow.src_bytes,
            'dst_bytes': flow.dst_bytes,
            'duration': flow.duration,
            'flag': flow.flag
        }
        
        # Armazenar alerta
        self.alerts.append(alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
        
        # Log do alerta
        logger.warning(
            f"🚨 ALERTA: {alert['src_ip']}:{alert['src_port']} -> "
            f"{alert['dst_ip']}:{alert['dst_port']} "
            f"(Serviço: {alert['service']}, Confiança: {confidence:.2%})"
        )
        
        return alert
    
    def send_alert(self, alert: Dict):
        """
        Envia um alerta (placeholder para integrações futuras).
        """
        # Aqui você pode adicionar integrações com:
        # - Discord
        # - Telegram
        # - Email
        # - Slack
        pass
    
    def get_alerts(self, limit: int = 10) -> List[Dict]:
        """Retorna os últimos alertas."""
        return self.alerts[-limit:]
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas de alertas."""
        return {
            'total_alerts': len(self.alerts),
            'high_severity': sum(1 for a in self.alerts if a.get('severity') == 'HIGH'),
            'medium_severity': sum(1 for a in self.alerts if a.get('severity') == 'MEDIUM')
        }