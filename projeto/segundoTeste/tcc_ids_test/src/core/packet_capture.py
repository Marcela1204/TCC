# src/core/packet_capture.py
"""
Captura de pacotes - Versão Simplificada
"""

import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Captura pacotes em tempo real (placeholder para testes).
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.is_capturing = False
        logger.info("✅ PacketCapture inicializado (modo simulação)")
    
    def start(self, interface: str = 'eth0'):
        """Inicia captura (simulação)."""
        self.is_capturing = True
        logger.info(f"📡 Captura iniciada na interface {interface} (modo simulação)")
        logger.warning("⚠️ Modo simulação - nenhum pacote real está sendo capturado")
        logger.info("💡 Para captura real, instale Scapy e configure a interface")
    
    def stop(self):
        """Para a captura."""
        self.is_capturing = False
        logger.info("⏹️ Captura parada")