#!/usr/bin/env python3
"""
Extrator de features NSL-KDD a partir de captura tcpdump.

Converte o nível de pacote (tcpdump) para o nível de conexão (NSL-KDD),
emitindo as 16 features observáveis do conjunto ótimo identificado pelo
DecisionTree no TCC (Figura 4 de documentacao/final/main.pdf).

As duas features restantes do conjunto de 18 -- `hot` e `logged_in` --
NAO sao emitidas: ambas exigem inspecao de payload de aplicacao em texto
claro (no DARPA'98 vinham de analisadores de telnet/FTP). Sob TLS elas sao
inobservaveis, nao apenas difíceis. Retreine o modelo com estas 16 colunas.

Uso:
    # offline, sobre um pcap ja capturado
    ./extrator_nslkdd.py -r captura.pcap > conexoes.csv

    # tempo real, direto do tcpdump (emite cada conexao assim que ela fecha)
    sudo tcpdump -i eth0 -s 0 -nn -w - 'tcp or udp or icmp' \\
        | ./extrator_nslkdd.py --meta

Le pcap classico (o que o `tcpdump -w` gera) e pcapng (o formato dos
arquivos em datasets/CIC-IDS-2017/), detectando o formato pelo cabecalho.
Sem dependencias externas: parser de captura e decodificacao de cabecalhos
em Python puro.
"""

import argparse
import os
import struct
import sys
from collections import deque

# ---------------------------------------------------------------------------
# Vocabulario de servicos do KDD
# ---------------------------------------------------------------------------
# O KDD nomeia o servico a partir da porta do servidor, com um vocabulario
# fechado de 70 valores. Portas conhecidas viram o nome; portas altas nao
# atribuidas caem em 'private'; o resto em 'other'. Nao use a resolucao via
# /etc/services do tcpdump (rode-o com -nn): ela e inconsistente entre hosts
# e produz nomes fora deste vocabulario.
TCP_SERVICES = {
    7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 15: 'netstat',
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    37: 'time', 42: 'name', 43: 'whois', 53: 'domain', 57: 'mtp',
    66: 'sql_net', 70: 'gopher', 77: 'remote_job', 79: 'finger', 80: 'http',
    84: 'ctf', 87: 'link', 95: 'supdup', 101: 'hostnames', 102: 'iso_tsap',
    105: 'csnet_ns', 109: 'pop_2', 110: 'pop_3', 111: 'sunrpc', 113: 'auth',
    117: 'uucp_path', 119: 'nntp', 137: 'netbios_ns', 138: 'netbios_dgm',
    139: 'netbios_ssn', 143: 'imap4', 175: 'vmnet', 179: 'bgp', 194: 'IRC',
    210: 'Z39_50', 245: 'link', 389: 'ldap', 443: 'http_443', 433: 'nnsp',
    512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 520: 'efs',
    530: 'courier', 540: 'uucp', 543: 'klogin', 544: 'kshell',
    1521: 'sql_net', 2784: 'http_2784', 5190: 'aol', 6000: 'X11',
    8001: 'http_8001',
}

UDP_SERVICES = {
    7: 'echo', 9: 'discard', 13: 'daytime', 37: 'time', 42: 'name',
    53: 'domain_u', 69: 'tftp_u', 111: 'sunrpc', 123: 'ntp_u',
    137: 'netbios_ns', 138: 'netbios_dgm', 139: 'netbios_ssn',
}

# Pseudo-servicos ICMP do KDD, derivados do tipo da mensagem.
ICMP_SERVICES = {
    0: 'ecr_i',   # echo reply
    3: 'urp_i',   # destination unreachable
    5: 'red_i',   # redirect
    8: 'eco_i',   # echo request
    11: 'tim_i',  # time exceeded
    12: 'urh_i',  # parameter problem
}

# Estados de conexao que contam como erro de SYN / erro de reset.
SERROR_FLAGS = frozenset(('S0', 'S1', 'S2', 'S3'))
RERROR_FLAGS = frozenset(('REJ', 'RSTO', 'RSTR', 'RSTOS0'))

# Bits de flag TCP.
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

# As 16 features observaveis, na ordem de importancia da Figura 4 do TCC
# (as posicoes 6 `hot` e 8 `logged_in` foram removidas).
FEATURES = [
    'src_bytes',
    'dst_host_srv_count',
    'count',
    'dst_bytes',
    'dst_host_srv_rerror_rate',
    'dst_host_same_src_port_rate',
    'srv_count',
    'dst_host_same_srv_rate',
    'duration',
    'wrong_fragment',
    'dst_host_rerror_rate',
    'dst_host_diff_srv_rate',
    'dst_host_count',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate',
    'diff_srv_rate',
]

# Colunas de atribuicao. NAO sao entrada do modelo -- existem para que um
# alerta possa ser acionado contra um endereco concreto.
META = ['ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'protocol_type', 'service', 'flag']


def service_of(proto, server_port, icmp_type):
    """Nome de servico KDD para a conexao."""
    if proto == 1:
        return ICMP_SERVICES.get(icmp_type, 'other')
    table = TCP_SERVICES if proto == 6 else UDP_SERVICES
    name = table.get(server_port)
    if name is not None:
        return name
    return 'private' if server_port >= 1024 else 'other'


# ---------------------------------------------------------------------------
# Leitor pcap
# ---------------------------------------------------------------------------
def _read_exact(stream, n):
    """Le exatamente n bytes; None em EOF. Leituras em pipe voltam curtas."""
    chunks = []
    remaining = n
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


class PcapReader:
    """Parser de pcap classico, sobre arquivo ou pipe."""

    _MAGIC = {
        b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
        b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
        b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
        b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
    }

    def __init__(self, stream, header):
        self.stream = stream
        magic = header[:4]
        if magic not in self._MAGIC:
            raise ValueError('magic pcap desconhecido: %s' % magic.hex())
        self.endian, self.ts_div = self._MAGIC[magic]
        self.linktype = struct.unpack(self.endian + 'HHiIII', header[4:])[5]
        self._pkt_hdr = struct.Struct(self.endian + 'IIII')

    def __iter__(self):
        linktype = self.linktype
        unpack = self._pkt_hdr.unpack
        div = self.ts_div
        while True:
            header = _read_exact(self.stream, 16)
            if header is None:
                return
            ts_sec, ts_frac, incl_len, _orig_len = unpack(header)
            data = _read_exact(self.stream, incl_len)
            if data is None:
                return
            yield ts_sec + ts_frac / div, data, linktype


class PcapngReader:
    """Parser de pcapng.

    Necessario porque as capturas do CIC-IDS-2017 em datasets/ estao neste
    formato -- converter 40 GB com tshark antes de cada execucao seria
    desperdicio. O tcpdump -w continua gerando pcap classico.
    """

    SHB = 0x0A0D0D0A
    IDB = 0x00000001
    SPB = 0x00000003
    EPB = 0x00000006

    def __init__(self, stream, header):
        self.stream = stream
        # header traz os 24 bytes ja lidos: 8 do inicio do SHB + magic + ...
        # O magic e o valor 0x1A2B3C4D gravado na ordem da secao: em disco
        # sai como 4d3c2b1a numa secao little-endian.
        if header[8:12] == b'\x4d\x3c\x2b\x1a':
            self.endian = '<'
        elif header[8:12] == b'\x1a\x2b\x3c\x4d':
            self.endian = '>'
        else:
            raise ValueError('byte-order magic pcapng invalido')
        total_len = struct.unpack_from(self.endian + 'I', header, 4)[0]
        if total_len < 28:
            raise ValueError('SHB pcapng com tamanho invalido: %d' % total_len)
        # Consome o resto do SHB (opcoes + trailer de tamanho).
        if _read_exact(stream, total_len - 24) is None:
            raise ValueError('SHB pcapng truncado')
        # linktype e resolucao de timestamp por interface.
        self.interfaces = []
        self._blk = struct.Struct(self.endian + 'II')

    def _parse_idb(self, body):
        linktype = struct.unpack_from(self.endian + 'H', body, 0)[0]
        ts_div = 1_000_000  # padrao da especificacao: microssegundos
        # Percorre as opcoes procurando if_tsresol (codigo 9).
        pos = 8
        while pos + 4 <= len(body):
            code, length = struct.unpack_from(self.endian + 'HH', body, pos)
            pos += 4
            if code == 0:  # opt_endofopt
                break
            if code == 9 and length >= 1:
                raw = body[pos]
                ts_div = (2 ** (raw & 0x7F)) if (raw & 0x80) else (10 ** raw)
            pos += length + (-length % 4)  # opcoes alinhadas em 4 bytes
        self.interfaces.append((linktype, ts_div))

    def __iter__(self):
        while True:
            header = _read_exact(self.stream, 8)
            if header is None:
                return
            block_type, total_len = self._blk.unpack(header)
            if total_len < 12:
                return
            body = _read_exact(self.stream, total_len - 12)
            if body is None:
                return
            if _read_exact(self.stream, 4) is None:  # trailer de tamanho
                return

            if block_type == self.EPB:
                if len(body) < 20:
                    continue
                iface, ts_high, ts_low, caplen, _orig = struct.unpack_from(
                    self.endian + 'IIIII', body, 0)
                if iface >= len(self.interfaces):
                    continue
                linktype, ts_div = self.interfaces[iface]
                ts = ((ts_high << 32) | ts_low) / ts_div
                yield ts, body[20:20 + caplen], linktype
            elif block_type == self.IDB:
                if len(body) >= 8:
                    self._parse_idb(body)
            elif block_type == self.SPB:
                # Sem timestamp proprio: inutil para as janelas do KDD.
                continue
            elif block_type == self.SHB:
                # Nova secao: as interfaces sao redeclaradas a seguir.
                self.interfaces = []


def open_capture(stream):
    """Detecta pcap ou pcapng e devolve o leitor apropriado."""
    header = _read_exact(stream, 24)
    if header is None:
        raise ValueError('captura vazia ou truncada no cabecalho')
    if header[:4] == b'\x0a\x0d\x0d\x0a':
        return PcapngReader(stream, header)
    return PcapReader(stream, header)


# Offset do payload de rede e forma de obter o ethertype, por linktype.
def strip_link_layer(linktype, data):
    """Devolve o offset onde comeca o IPv4, ou None se nao for IPv4."""
    if linktype == 1:  # EN10MB
        if len(data) < 14:
            return None
        etype = struct.unpack_from('!H', data, 12)[0]
        offset = 14
        # Desempilha tags VLAN (802.1Q / 802.1ad).
        while etype in (0x8100, 0x88a8, 0x9100):
            if len(data) < offset + 4:
                return None
            etype = struct.unpack_from('!H', data, offset + 2)[0]
            offset += 4
        return offset if etype == 0x0800 else None
    if linktype == 113:  # LINUX_SLL
        if len(data) < 16:
            return None
        etype = struct.unpack_from('!H', data, 14)[0]
        return 16 if etype == 0x0800 else None
    if linktype == 276:  # LINUX_SLL2
        if len(data) < 20:
            return None
        etype = struct.unpack_from('!H', data, 0)[0]
        return 20 if etype == 0x0800 else None
    if linktype == 0:  # NULL / loopback
        if len(data) < 4:
            return None
        return 4
    if linktype in (12, 14, 101, 228):  # RAW / IPv4
        return 0
    raise ValueError('linktype %d nao suportado' % linktype)


def ip_checksum_ok(header):
    """Verifica o checksum do cabecalho IPv4."""
    if len(header) % 2:
        header += b'\x00'
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total & 0xFFFF) == 0


def ipv4_str(raw):
    return '%d.%d.%d.%d' % (raw[0], raw[1], raw[2], raw[3])


# ---------------------------------------------------------------------------
# Conexao
# ---------------------------------------------------------------------------
class Flow:
    """Estado acumulado de uma conexao (ou pseudo-conexao UDP/ICMP)."""

    __slots__ = ('proto', 'orig_ip', 'orig_port', 'resp_ip', 'resp_port',
                 'first_ts', 'last_ts', 'src_bytes', 'dst_bytes',
                 'wrong_fragment', 'urgent', 'icmp_type',
                 'syn_orig', 'synack_resp', 'fin_orig', 'fin_resp',
                 'rst_orig', 'rst_resp', 'resp_pkts', 'saw_syn')

    def __init__(self, proto, ts, orig_ip, orig_port, resp_ip, resp_port):
        self.proto = proto
        self.orig_ip = orig_ip
        self.orig_port = orig_port
        self.resp_ip = resp_ip
        self.resp_port = resp_port
        self.first_ts = ts
        self.last_ts = ts
        self.src_bytes = 0
        self.dst_bytes = 0
        self.wrong_fragment = 0
        self.urgent = 0
        self.icmp_type = 0
        self.syn_orig = False
        self.synack_resp = False
        self.fin_orig = False
        self.fin_resp = False
        self.rst_orig = False
        self.rst_resp = False
        self.resp_pkts = 0
        self.saw_syn = False

    @property
    def duration(self):
        # O KDD registra duracao em segundos inteiros.
        return int(self.last_ts - self.first_ts)

    @property
    def flag(self):
        """Estado da conexao no vocabulario do KDD (herdado do Bro)."""
        if self.proto != 6:
            # UDP/ICMP nao tem handshake: SF se houve resposta, S0 se nao.
            return 'SF' if self.resp_pkts else 'S0'
        if not self.saw_syn:
            return 'OTH'  # trafego capturado no meio da conexao
        if not self.synack_resp:
            # Tentativa de conexao sem SYN-ACK do responder.
            if self.rst_resp:
                return 'REJ'
            if self.rst_orig:
                return 'RSTOS0'
            if self.fin_orig:
                return 'SH'
            return 'S0'
        # Conexao estabelecida.
        if self.rst_orig:
            return 'RSTO'
        if self.rst_resp:
            return 'RSTR'
        if self.fin_orig and self.fin_resp:
            return 'SF'
        if self.fin_orig:
            return 'S2'
        if self.fin_resp:
            return 'S3'
        return 'S1'

    @property
    def closed(self):
        """Conexao terminou por sinalizacao (nao por timeout)."""
        if self.proto != 6:
            return False
        return self.rst_orig or self.rst_resp or (self.fin_orig and self.fin_resp)


class Record:
    """Resumo de conexao concluida, guardado nas janelas."""

    __slots__ = ('ts', 'dst_ip', 'service', 'flag', 'src_port')

    def __init__(self, ts, dst_ip, service, flag, src_port):
        self.ts = ts
        self.dst_ip = dst_ip
        self.service = service
        self.flag = flag
        self.src_port = src_port


# ---------------------------------------------------------------------------
# Extrator
# ---------------------------------------------------------------------------
class Extractor:
    """Monta conexoes a partir de pacotes e computa as janelas do KDD."""

    def __init__(self, tcp_timeout=60.0, udp_timeout=30.0,
                 time_window=2.0, conn_window=100, close_grace=5.0,
                 sweep_interval=1.0):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.time_window = time_window
        self.close_grace = close_grace
        self.sweep_interval = sweep_interval
        self.flows = {}
        # Depois de um RST ou do par de FINs ainda chegam ACKs finais e
        # retransmissoes. Sem esta carencia cada conexao gerava uma segunda
        # linha espuria -- flag OTH, 0 bytes, papeis invertidos -- que
        # dobrava a contagem e contaminava as janelas.
        self.closed_recent = {}
        self.last_sweep = 0.0
        # Janela temporal de 2s: features `count`, `srv_count`, `diff_srv_rate`.
        self.by_time = deque()
        # Janela das ultimas N conexoes: todas as features `dst_host_*`.
        self.by_conn = deque(maxlen=conn_window)
        # Primeiro fragmento de um datagrama carrega as portas; os seguintes
        # nao. Este mapa liga os fragmentos subsequentes a sua conexao.
        self.frag_owner = {}
        self.now = 0.0
        self.stats = {'packets': 0, 'non_ipv4': 0, 'connections': 0}

    # -- entrada de pacotes -------------------------------------------------
    def feed(self, ts, data, linktype):
        """Processa um pacote; devolve lista de conexoes expiradas."""
        self.stats['packets'] += 1
        if ts > self.now:
            self.now = ts

        offset = strip_link_layer(linktype, data)
        if offset is None:
            self.stats['non_ipv4'] += 1
            return self._expire()

        if len(data) < offset + 20:
            return self._expire()

        ihl = (data[offset] & 0x0F) * 4
        if ihl < 20 or len(data) < offset + ihl:
            return self._expire()

        total_len = struct.unpack_from('!H', data, offset + 2)[0]
        ip_id = struct.unpack_from('!H', data, offset + 4)[0]
        frag_field = struct.unpack_from('!H', data, offset + 6)[0]
        more_frags = bool(frag_field & 0x2000)
        frag_offset = (frag_field & 0x1FFF) * 8
        proto = data[offset + 9]
        src_ip = ipv4_str(data[offset + 12:offset + 16])
        dst_ip = ipv4_str(data[offset + 16:offset + 20])

        if proto not in (1, 6, 17):
            return self._expire()

        payload_at = offset + ihl
        # total_len vem do cabecalho, entao continua correto mesmo se o
        # snaplen truncou o pacote na captura.
        l4_len = max(0, total_len - ihl)

        # -- fragmentos que nao carregam cabecalho L4 ----------------------
        if frag_offset > 0:
            frag_key = (src_ip, dst_ip, proto, ip_id)
            owner = self.frag_owner.get(frag_key)
            if owner is not None:
                flow_key, from_orig = owner
                flow = self.flows.get(flow_key)
                if flow is not None:
                    flow.last_ts = max(flow.last_ts, ts)
                    if from_orig:
                        flow.src_bytes += l4_len
                    else:
                        flow.dst_bytes += l4_len
                        flow.resp_pkts += 1
                    if self._bad_fragment(data, offset, ihl, total_len,
                                          more_frags, frag_offset):
                        flow.wrong_fragment += 1
                    if not more_frags:
                        self.frag_owner.pop(frag_key, None)
            return self._expire()

        # -- cabecalho L4 presente ----------------------------------------
        src_port = dst_port = 0
        icmp_type = 0
        tcp_flags = 0

        if proto == 6:
            if len(data) < payload_at + 20:
                return self._expire()
            src_port, dst_port = struct.unpack_from('!HH', data, payload_at)
            doff = ((data[payload_at + 12] >> 4) & 0x0F) * 4
            if doff < 20:
                return self._expire()
            tcp_flags = data[payload_at + 13]
            l4_len = max(0, total_len - ihl - doff)
        elif proto == 17:
            if len(data) < payload_at + 8:
                return self._expire()
            src_port, dst_port = struct.unpack_from('!HH', data, payload_at)
            l4_len = max(0, total_len - ihl - 8)
        else:  # ICMP
            if len(data) < payload_at + 4:
                return self._expire()
            icmp_type = data[payload_at]
            l4_len = max(0, total_len - ihl - 8)

        flow_key = self._flow_key(proto, src_ip, src_port, dst_ip, dst_port)

        # Pacote residual de uma conexao ja emitida? Absorve, em vez de abrir
        # um fluxo novo. Um SYN puro encerra a carencia: e reuso legitimo da
        # tupla por uma conexao nova.
        grace_until = self.closed_recent.get(flow_key)
        if grace_until is not None:
            is_pure_syn = (proto == 6 and (tcp_flags & SYN)
                           and not (tcp_flags & ACK))
            if is_pure_syn or ts > grace_until:
                del self.closed_recent[flow_key]
            else:
                return self._expire()

        flow, from_orig = self._lookup(
            flow_key, ts, proto, src_ip, src_port, dst_ip, dst_port,
            icmp_type, tcp_flags)

        flow.last_ts = max(flow.last_ts, ts)
        if from_orig:
            flow.src_bytes += l4_len
        else:
            flow.dst_bytes += l4_len
            flow.resp_pkts += 1

        if more_frags:
            self.frag_owner[(src_ip, dst_ip, proto, ip_id)] = (flow_key, from_orig)
            if self._bad_fragment(data, offset, ihl, total_len,
                                  more_frags, frag_offset):
                flow.wrong_fragment += 1

        if proto == 6:
            self._apply_tcp_flags(flow, tcp_flags, from_orig)

        emitted = self._expire()
        if flow.closed:
            self.flows.pop(flow_key, None)
            self.closed_recent[flow_key] = ts + self.close_grace
            emitted.append(self._finalize(flow))
        return emitted

    def _bad_fragment(self, data, offset, ihl, total_len, more_frags, frag_offset):
        """Heuristica para o `wrong_fragment` do KDD.

        Conta fragmentos malformados: checksum de cabecalho invalido, ou
        fragmento intermediario cujo payload nao e multiplo de 8 (violacao
        do alinhamento exigido pela RFC 791).

        Cuidado: com checksum offload na placa, pacotes gerados localmente
        saem da captura com checksum invalido e inflariam esta contagem.
        Desligue com `ethtool -K eth0 tx off` ao capturar no proprio host,
        ou capture em um ponto de espelhamento.
        """
        if not ip_checksum_ok(data[offset:offset + ihl]):
            return True
        if more_frags and (total_len - ihl) % 8 != 0:
            return True
        return False

    @staticmethod
    def _flow_key(proto, src_ip, src_port, dst_ip, dst_port):
        """Chave canonica: os dois sentidos de uma conexao colidem nela."""
        if proto == 1:
            return (1, src_ip, dst_ip) if src_ip <= dst_ip else (1, dst_ip, src_ip)
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        return (proto, a, b) if a <= b else (proto, b, a)

    def _lookup(self, key, ts, proto, src_ip, src_port, dst_ip, dst_port,
                icmp_type, tcp_flags):
        """Encontra ou cria a conexao; resolve quem e o originador."""
        flow = self.flows.get(key)
        if flow is not None:
            timeout = self.tcp_timeout if proto == 6 else self.udp_timeout
            if ts - flow.last_ts > timeout:
                # Reuso da mesma tupla depois do timeout: conexao nova.
                self.flows.pop(key, None)
                flow = None

        if flow is None:
            # Um SYN puro identifica o originador sem ambiguidade. Sem isso,
            # assume-se que quem enviou o primeiro pacote visto originou.
            flow = Flow(proto, ts, src_ip, src_port, dst_ip, dst_port)
            if proto == 6 and (tcp_flags & SYN) and not (tcp_flags & ACK):
                flow.saw_syn = True
                flow.syn_orig = True
            if proto == 1:
                flow.icmp_type = icmp_type
            self.flows[key] = flow
            return flow, True

        # Um SYN puro chegando na direcao oposta corrige a orientacao
        # inferida a partir do primeiro pacote.
        if (proto == 6 and not flow.saw_syn and (tcp_flags & SYN)
                and not (tcp_flags & ACK) and src_ip == flow.resp_ip
                and src_port == flow.resp_port):
            flow.orig_ip, flow.resp_ip = flow.resp_ip, flow.orig_ip
            flow.orig_port, flow.resp_port = flow.resp_port, flow.orig_port
            flow.src_bytes, flow.dst_bytes = flow.dst_bytes, flow.src_bytes
            flow.saw_syn = True
            flow.syn_orig = True
            flow.resp_pkts = 0

        from_orig = (src_ip == flow.orig_ip and src_port == flow.orig_port)
        return flow, from_orig

    @staticmethod
    def _apply_tcp_flags(flow, flags, from_orig):
        if flags & SYN:
            if from_orig and not (flags & ACK):
                flow.syn_orig = True
                flow.saw_syn = True
            elif not from_orig and (flags & ACK):
                flow.synack_resp = True
        if flags & FIN:
            if from_orig:
                flow.fin_orig = True
            else:
                flow.fin_resp = True
        if flags & RST:
            if from_orig:
                flow.rst_orig = True
            else:
                flow.rst_resp = True
        if flags & URG:
            flow.urgent += 1

    def _expire(self):
        """Fecha conexoes inativas.

        Dirigido pelo relogio da captura, nao pelo relogio local, para que o
        resultado offline seja identico ao de tempo real. A varredura e
        limitada a uma por `sweep_interval` de tempo de captura: varrer todos
        os fluxos ativos a cada pacote e O(fluxos x pacotes) e dominava o
        tempo de execucao.
        """
        if self.now - self.last_sweep < self.sweep_interval:
            return []
        self.last_sweep = self.now

        emitted = []
        for key, flow in list(self.flows.items()):
            timeout = self.tcp_timeout if flow.proto == 6 else self.udp_timeout
            if self.now - flow.last_ts > timeout:
                del self.flows[key]
                emitted.append(self._finalize(flow))
        for key, until in list(self.closed_recent.items()):
            if self.now > until:
                del self.closed_recent[key]
        if len(self.frag_owner) > 65536:
            self.frag_owner.clear()
        return emitted

    def flush(self):
        """Fecha tudo que restou (fim da captura)."""
        emitted = [self._finalize(f) for f in self.flows.values()]
        self.flows.clear()
        return emitted

    # -- janelas e features -------------------------------------------------
    def _finalize(self, flow):
        """Calcula as 16 features de uma conexao concluida."""
        self.stats['connections'] += 1
        server_port = flow.resp_port
        service = service_of(flow.proto, server_port, flow.icmp_type)
        flag = flow.flag
        dst_ip = flow.resp_ip
        ts = flow.first_ts

        # Poda a janela temporal com base no inicio da conexao atual.
        cutoff = ts - self.time_window
        while self.by_time and self.by_time[0].ts < cutoff:
            self.by_time.popleft()

        # As janelas sao lidas ANTES de inserir a conexao atual: o KDD
        # define ambas como estritamente retrospectivas, e por isso `count`
        # e `dst_host_count` podem valer 0.
        same_host = [r for r in self.by_time if r.dst_ip == dst_ip]
        count = len(same_host)
        srv_count = sum(1 for r in self.by_time if r.service == service)
        diff_srv = sum(1 for r in same_host if r.service != service)
        diff_srv_rate = diff_srv / count if count else 0.0

        host_recs = [r for r in self.by_conn if r.dst_ip == dst_ip]
        srv_recs = [r for r in self.by_conn if r.service == service]
        host_srv = [r for r in host_recs if r.service == service]

        dst_host_count = len(host_recs)
        dst_host_srv_count = len(host_srv)

        if dst_host_count:
            dst_host_same_srv_rate = dst_host_srv_count / dst_host_count
            dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate
            dst_host_serror_rate = (
                sum(1 for r in host_recs if r.flag in SERROR_FLAGS)
                / dst_host_count)
            dst_host_rerror_rate = (
                sum(1 for r in host_recs if r.flag in RERROR_FLAGS)
                / dst_host_count)
        else:
            dst_host_same_srv_rate = 0.0
            dst_host_diff_srv_rate = 0.0
            dst_host_serror_rate = 0.0
            dst_host_rerror_rate = 0.0

        if dst_host_srv_count:
            dst_host_same_src_port_rate = (
                sum(1 for r in host_srv if r.src_port == flow.orig_port)
                / dst_host_srv_count)
            dst_host_srv_rerror_rate = (
                sum(1 for r in host_srv if r.flag in RERROR_FLAGS)
                / dst_host_srv_count)
        else:
            dst_host_same_src_port_rate = 0.0
            dst_host_srv_rerror_rate = 0.0

        # Definida sobre as conexoes ao mesmo SERVICO (qualquer host),
        # medindo a fracao que foi para um host diferente do atual. Este e
        # o unico ponto onde a definicao original do KDD e circular
        # ("entre as conexoes de dst_host_srv_count", que por construcao
        # sao todas ao mesmo host); adotou-se a leitura usada pelas
        # reimplementacoes, que produz valores nao-degenerados.
        if srv_recs:
            dst_host_srv_diff_host_rate = (
                sum(1 for r in srv_recs if r.dst_ip != dst_ip) / len(srv_recs))
        else:
            dst_host_srv_diff_host_rate = 0.0

        record = Record(ts, dst_ip, service, flag, flow.orig_port)
        self.by_time.append(record)
        self.by_conn.append(record)

        return {
            'ts': '%.6f' % ts,
            'src_ip': flow.orig_ip,
            'src_port': flow.orig_port,
            'dst_ip': dst_ip,
            'dst_port': server_port,
            'protocol_type': {1: 'icmp', 6: 'tcp', 17: 'udp'}[flow.proto],
            'service': service,
            'flag': flag,
            'duration': flow.duration,
            'src_bytes': flow.src_bytes,
            'dst_bytes': flow.dst_bytes,
            'wrong_fragment': flow.wrong_fragment,
            'count': count,
            'srv_count': srv_count,
            'diff_srv_rate': round(diff_srv_rate, 2),
            'dst_host_count': dst_host_count,
            'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': round(dst_host_same_srv_rate, 2),
            'dst_host_diff_srv_rate': round(dst_host_diff_srv_rate, 2),
            'dst_host_same_src_port_rate': round(dst_host_same_src_port_rate, 2),
            'dst_host_srv_diff_host_rate': round(dst_host_srv_diff_host_rate, 2),
            'dst_host_serror_rate': round(dst_host_serror_rate, 2),
            'dst_host_rerror_rate': round(dst_host_rerror_rate, 2),
            'dst_host_srv_rerror_rate': round(dst_host_srv_rerror_rate, 2),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Extrai features NSL-KDD de uma captura tcpdump.',
        epilog='Emite 16 das 18 features do TCC; `hot` e `logged_in` exigem '
               'DPI de payload em claro e sao omitidas.')
    parser.add_argument('-r', '--read', metavar='PCAP',
                        help='arquivo pcap de entrada (padrao: stdin)')
    parser.add_argument('-w', '--write', metavar='CSV',
                        help='arquivo CSV de saida (padrao: stdout)')
    parser.add_argument('--meta', action='store_true',
                        help='inclui colunas de atribuicao (ts, IPs, portas, '
                             'protocol_type, service, flag) antes das features')
    parser.add_argument('--no-header', action='store_true',
                        help='omite a linha de cabecalho do CSV')
    parser.add_argument('--tcp-timeout', type=float, default=60.0,
                        help='inatividade que encerra um fluxo TCP (s)')
    parser.add_argument('--udp-timeout', type=float, default=30.0,
                        help='inatividade que encerra um fluxo UDP/ICMP (s)')
    parser.add_argument('--conn-window', type=int, default=100,
                        help='tamanho da janela de conexoes das features '
                             'dst_host_* (padrao KDD: 100)')
    parser.add_argument('--close-grace', type=float, default=5.0,
                        help='carencia apos o fecho em que pacotes residuais '
                             'sao absorvidos em vez de abrir novo fluxo (s)')
    parser.add_argument('--sweep-interval', type=float, default=1.0,
                        help='intervalo minimo entre varreduras de expiracao (s)')
    parser.add_argument('--quiet', action='store_true',
                        help='nao imprime estatisticas no stderr ao terminar')
    args = parser.parse_args(argv)

    stream = None
    out = None
    try:
        if args.read:
            stream = open(args.read, 'rb')
        else:
            stream = sys.stdin.buffer
        out = open(args.write, 'w') if args.write else sys.stdout

        try:
            reader = open_capture(stream)
        except ValueError as exc:
            sys.stderr.write('erro: %s\n' % exc)
            return 2

        columns = (META + FEATURES) if args.meta else FEATURES
        if not args.no_header:
            out.write(','.join(columns) + '\n')

        extractor = Extractor(tcp_timeout=args.tcp_timeout,
                              udp_timeout=args.udp_timeout,
                              conn_window=args.conn_window,
                              close_grace=args.close_grace,
                              sweep_interval=args.sweep_interval)
        # Em pipe ao vivo cada conexao e escrita na hora: um IDS nao pode
        # esperar o buffer encher para alertar.
        live = args.read is None

        def emit(rows):
            for row in rows:
                out.write(','.join(str(row[c]) for c in columns) + '\n')
            if rows and live:
                out.flush()

        try:
            for ts, data, linktype in reader:
                emit(extractor.feed(ts, data, linktype))
            emit(extractor.flush())
            out.flush()
        except KeyboardInterrupt:
            # Ctrl-C encerra a captura: ainda emite os fluxos em aberto.
            try:
                emit(extractor.flush())
                out.flush()
            except (BrokenPipeError, ValueError):
                pass
        except BrokenPipeError:
            # Consumidor a jusante fechou o pipe (head, grep -m, etc.).
            # Silencia tambem o flush final do interpretador.
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 0

        if not args.quiet:
            stats = extractor.stats
            sys.stderr.write(
                'pacotes: %d | nao-IPv4 descartados: %d | conexoes: %d\n'
                % (stats['packets'], stats['non_ipv4'], stats['connections']))
        return 0
    finally:
        if stream is not None and args.read:
            stream.close()
        if out is not None and args.write:
            out.close()


if __name__ == '__main__':
    sys.exit(main())
