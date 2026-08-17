#!/usr/bin/env python3
"""
Rotula as conexoes do extrator_nslkdd.py com a verdade do CIC-IDS-2017.

Os CSV do CIC-IDS-2017 presentes em datasets/CIC-IDS-2017/CSV/ sao exportacoes
de pacotes do Wireshark e nao tem coluna de rotulo. A verdade usada aqui e o
cronograma oficial de ataques publicado pelo CIC/UNB: uma conexao e ataque
quando cai dentro da janela de tempo de um ataque E o par de enderecos bate
com o par atacante/vitima daquele ataque.

Rotular pelo cronograma, e nao por casamento com os fluxos do CICFlowMeter,
e deliberado: a literatura documenta construcao de fluxo incorreta e
timestamps incoerentes nos CSV oficiais, defeitos que seriam importados para
os rotulos. O cronograma e a definicao primaria do experimento.

NAT
O trafego foi capturado do lado interno do firewall, e o atacante Kali
aparece com duas identidades conforme o sentido da conexao: 172.16.0.1 nos
ataques de entrada (pos-NAT) e 205.174.165.73 nas conexoes iniciadas de
dentro para fora. As vitimas sempre aparecem com IP interno 192.168.10.x,
nunca com o IP publico 205.174.165.x listado no site do CIC.

Ambas as identidades sao necessarias: rotular so pelo IP publico do site
produz zero ataques, e rotular so pelo endereco pos-NAT perde botnet e
infiltracao inteiras, que sao justamente trafego de saida.

Uso:
    ./extrator_nslkdd.py -r datasets/CIC-IDS-2017/Tuesday-WorkingHours.pcap \\
        --meta -w tuesday.csv
    ./rotular_cicids.py -r tuesday.csv -w tuesday_rotulado.csv
"""

import argparse
import calendar
import csv
import sys
from collections import Counter

# Fuso do laboratorio do CIC/UNB (New Brunswick) em julho: ADT = UTC-3.
FUSO_PADRAO = -3

# O atacante Kali aparece com DUAS identidades na captura, conforme o sentido
# da conexao:
#   172.16.0.1      -- ataques de entrada, apos o NAT do firewall (patator,
#                      DoS, ataques web, port scan, DDoS);
#   205.174.165.73  -- conexoes iniciadas de dentro para fora, que nao passam
#                      pelo NAT de entrada: bot falando com o C&C na sexta e
#                      download do payload de infiltracao na quinta.
# Usar so a primeira deixa botnet e infiltracao inteiramente sem rotulo.
ATACANTE_NAT = '172.16.0.1'
ATACANTE_PUB = '205.174.165.73'
ATACANTE = [ATACANTE_NAT, ATACANTE_PUB]

SERVIDOR_WEB = '192.168.10.50'
SERVIDOR_UBUNTU12 = '192.168.10.51'
WIN_VISTA = '192.168.10.8'
MAC = '192.168.10.25'
CLIENTES = ['192.168.10.5', '192.168.10.8', '192.168.10.9', '192.168.10.12',
            '192.168.10.14', '192.168.10.15', '192.168.10.16', '192.168.10.17',
            '192.168.10.19', '192.168.10.25', '192.168.10.51']

# (data, inicio, fim, nome, atacantes, vitimas)
# Vitimas vazias = qualquer host. Horarios no fuso do dataset.
CRONOGRAMA = [
    # Segunda 03/07 e integralmente benigna: nenhuma entrada.
    ('2017-07-04', '09:20', '10:20', 'FTP-Patator', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-04', '14:00', '15:00', 'SSH-Patator', ATACANTE, [SERVIDOR_WEB]),

    ('2017-07-05', '09:47', '10:10', 'DoS-Slowloris', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-05', '10:14', '10:35', 'DoS-Slowhttptest', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-05', '10:43', '11:00', 'DoS-Hulk', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-05', '11:10', '11:23', 'DoS-GoldenEye', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-05', '15:12', '15:32', 'Heartbleed', ATACANTE, [SERVIDOR_UBUNTU12]),

    ('2017-07-06', '09:20', '10:00', 'Web-BruteForce', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-06', '10:15', '10:35', 'Web-XSS', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-06', '10:40', '10:42', 'Web-SQLInjection', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-06', '14:19', '14:35', 'Infiltration-Metasploit', ATACANTE, [WIN_VISTA]),
    ('2017-07-06', '14:53', '15:00', 'Infiltration-CoolDisk', ATACANTE, [MAC]),
    ('2017-07-06', '15:04', '15:45', 'Infiltration-Dropbox', ATACANTE, [WIN_VISTA]),
    # Apos a infiltracao, a propria vitima varre a rede interna.
    ('2017-07-06', '15:04', '15:45', 'Infiltration-PortScan', [WIN_VISTA], CLIENTES),

    ('2017-07-07', '10:02', '11:02', 'Botnet-ARES', ATACANTE,
     ['192.168.10.15', '192.168.10.9', '192.168.10.14', '192.168.10.5',
      '192.168.10.8']),
    ('2017-07-07', '13:55', '15:27', 'PortScan', ATACANTE, [SERVIDOR_WEB]),
    ('2017-07-07', '15:56', '16:16', 'DDoS-LOIT', ATACANTE, [SERVIDOR_WEB]),
]


def para_epoch(data, hora, fuso):
    """Converte data/hora do fuso do dataset para epoch UTC."""
    ano, mes, dia = (int(x) for x in data.split('-'))
    h, m = (int(x) for x in hora.split(':'))
    return calendar.timegm((ano, mes, dia, h - fuso, m, 0, 0, 0, 0))


def compilar(fuso, margem):
    """Pre-calcula as janelas em epoch, com margem opcional em segundos."""
    janelas = []
    for data, ini, fim, nome, atacantes, vitimas in CRONOGRAMA:
        janelas.append({
            'inicio': para_epoch(data, ini, fuso) - margem,
            'fim': para_epoch(data, fim, fuso) + margem,
            'nome': nome,
            'atacantes': set(atacantes),
            'vitimas': set(vitimas),
        })
    janelas.sort(key=lambda j: j['inicio'])
    return janelas


def rotular(ts, ip_a, ip_b, janelas):
    """Nome do ataque, ou None se benigno.

    O par de enderecos e comparado sem ordem: o extrator orienta a conexao
    pelo originador, mas sem SYN visivel (trafego capturado no meio) os
    papeis podem inverter.
    """
    for j in janelas:
        if not (j['inicio'] <= ts <= j['fim']):
            continue
        if ip_a in j['atacantes'] and (not j['vitimas'] or ip_b in j['vitimas']):
            return j['nome']
        if ip_b in j['atacantes'] and (not j['vitimas'] or ip_a in j['vitimas']):
            return j['nome']
    return None


def main(argv=None):
    p = argparse.ArgumentParser(
        description='Rotula conexoes do extrator com o cronograma do CIC-IDS-2017.')
    p.add_argument('-r', '--read', required=True,
                   help='CSV do extrator_nslkdd.py (precisa ter sido gerado com --meta)')
    p.add_argument('-w', '--write', required=True, help='CSV rotulado de saida')
    p.add_argument('--fuso', type=int, default=FUSO_PADRAO,
                   help='fuso do dataset em horas (padrao: -3, ADT)')
    p.add_argument('--margem', type=int, default=0,
                   help='segundos de folga nas bordas das janelas (padrao: 0, '
                        'janelas oficiais estritas)')
    args = p.parse_args(argv)

    janelas = compilar(args.fuso, args.margem)
    contagem = Counter()
    total = 0

    with open(args.read, newline='') as ent, open(args.write, 'w', newline='') as sai:
        leitor = csv.reader(ent)
        cabecalho = next(leitor)
        for obrig in ('ts', 'src_ip', 'dst_ip'):
            if obrig not in cabecalho:
                raise SystemExit(
                    'erro: coluna %s ausente. Gere a entrada com '
                    'extrator_nslkdd.py --meta' % obrig)
        i_ts = cabecalho.index('ts')
        i_src = cabecalho.index('src_ip')
        i_dst = cabecalho.index('dst_ip')

        escritor = csv.writer(sai)
        escritor.writerow(cabecalho + ['ataque', 'label'])
        for campos in leitor:
            if len(campos) < len(cabecalho):
                continue
            try:
                ts = float(campos[i_ts])
            except ValueError:
                continue
            nome = rotular(ts, campos[i_src], campos[i_dst], janelas)
            escritor.writerow(campos + [nome or 'benigno', 1 if nome else 0])
            contagem[nome or 'benigno'] += 1
            total += 1

    ataques = total - contagem['benigno']
    print('conexoes rotuladas: %d' % total)
    print('  benigno: %d (%.1f%%)'
          % (contagem['benigno'], 100.0 * contagem['benigno'] / max(total, 1)))
    print('  ataque : %d (%.1f%%)' % (ataques, 100.0 * ataques / max(total, 1)))
    for nome, n in contagem.most_common():
        if nome != 'benigno':
            print('    %-26s %7d' % (nome, n))
    if not ataques:
        print('\nAVISO: nenhum ataque rotulado. Verifique o fuso (--fuso) e se '
              'o pcap cobre as janelas do cronograma.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
