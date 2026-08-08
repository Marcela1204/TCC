# src/core/packet_capture.py
"""
Captura de pacotes em múltiplos formatos:
- Tempo real (Scapy)
- Arquivos pcap
- NetFlow/sFlow (via nfdump)
"""

import subprocess
import threading
import time
import os
from typing import Optional, Callable
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
import logging
from src.core.nsl_kdd_mapper import NSLKDDMapper
from src.core.flow_builder import FlowBuilder

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Captura pacotes de múltiplas fontes e converte para formato NSL-KDD.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.is_capturing = False
        self.mapper = NSLKDDMapper()
        self.flow_builder = FlowBuilder()
        
        # Interface de rede padrão
        self.interface = 'eth0'  # Ajustar conforme necessário
        
        # Filtro BPF
        self.filter = 'ip'  # Captura apenas IPv4
        
    def start_real_time(self, interface: Optional[str] = None):
        """
        Inicia captura em tempo real usando Scapy.
        """
        if interface:
            self.interface = interface
        
        logger.info(f"Iniciando captura em tempo real na interface {self.interface}")
        self.is_capturing = True
        
        try:
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            logger.error(f"Erro na captura: {e}")
    
    def start_pcap_file(self, pcap_file: str):
        """
        Processa um arquivo pcap existente.
        """
        logger.info(f"Processando arquivo pcap: {pcap_file}")
        
        if not os.path.exists(pcap_file):
            logger.error(f"Arquivo não encontrado: {pcap_file}")
            return
        
        packets = rdpcap(pcap_file)
        logger.info(f"Lidos {len(packets)} pacotes do arquivo")
        
        for packet in packets:
            self._packet_callback(packet)
    
    def start_tcpdump_live(self, interface: str = 'eth0', duration: int = 60):
        """
        Inicia captura via tcpdump (mais rápido que Scapy para produção).
        """
        logger.info(f"Iniciando tcpdump na interface {interface}")
        
        cmd = f"tcpdump -i {interface} -nn -e -s 65535 -l"
        
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.is_capturing = True
            start_time = time.time()
            
            while self.is_capturing:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Processar linha do tcpdump
                self._process_tcpdump_line(line)
                
                # Limitar duração (se especificado)
                if duration and (time.time() - start_time) > duration:
                    break
                    
        except Exception as e:
            logger.error(f"Erro no tcpdump: {e}")
        finally:
            self.stop_capture()
    
    def _packet_callback(self, packet):
        """
        Callback chamado para cada pacote capturado.
        """
        try:
            # Verificar se é IP
            if not packet.haslayer(IP):
                return
            
            # Converter pacote para features NSL-KDD
            flow_data = self.mapper.packet_to_flow(packet)
            
            if flow_data:
                # Construir fluxo completo
                flow = self.flow_builder.build_flow(flow_data)
                
                if self.callback:
                    self.callback(flow)
                    
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")
    
    def _process_tcpdump_line(self, line: str):
        """
        Processa uma linha do tcpdump e converte para fluxo.
        """
        try:
            # Parse básico - melhorar conforme necessário
            parts = line.split()
            if len(parts) < 10:
                return
            
            # Extrair IPs e portas
            ip_parts = parts[-4].split('.')
            if len(ip_parts) < 4:
                return
            
            # Criar pacote Scapy para processamento
            # (Simplificado - em produção, use um parser melhor)
            pass
            
        except Exception as e:
            logger.error(f"Erro ao processar linha do tcpdump: {e}")
    
    def stop_capture(self):
        """Para a captura."""
        self.is_capturing = False
        logger.info("Captura parada")


class NetFlowCapture:
    """
    Captura fluxos NetFlow/sFlow via nfdump.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.is_running = False
        
    def start_netflow(self, collector_port: int = 2055, duration: int = 60):
        """
        Inicia captura NetFlow usando nfcapd.
        """
        logger.info(f"Iniciando coletor NetFlow na porta {collector_port}")
        
        # Criar diretório para armazenar fluxos
        flow_dir = '/tmp/netflow'
        os.makedirs(flow_dir, exist_ok=True)
        
        # nfcapd - porta 2055, escreve arquivos em /tmp/netflow
        cmd = f"nfcapd -p {collector_port} -l {flow_dir} -T all"
        
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.is_running = True
            
            # Processar arquivos de fluxo
            while self.is_running:
                time.sleep(5)
                self._process_netflow_files(flow_dir)
                
        except Exception as e:
            logger.error(f"Erro no NetFlow: {e}")
    
    def _process_netflow_files(self, flow_dir: str):
        """
        Processa arquivos NetFlow gerados pelo nfcapd.
        """
        import glob
        
        # Encontrar arquivos .bin
        flow_files = glob.glob(f"{flow_dir}/*.bin")
        
        for flow_file in flow_files:
            try:
                # Usar nfdump para ler o arquivo
                cmd = f"nfdump -r {flow_file} -o csv"
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if result.stdout:
                    self._parse_netflow_csv(result.stdout)
                
                # Remover arquivo processado
                os.remove(flow_file)
                
            except Exception as e:
                logger.error(f"Erro ao processar arquivo NetFlow: {e}")
    
    def _parse_netflow_csv(self, csv_data: str):
        """
        Converte CSV do nfdump para features NSL-KDD.
        """
        # Implementar parser conforme necessário
        pass