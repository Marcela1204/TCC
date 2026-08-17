#!/usr/bin/env python3
"""
Classifica em tempo real as conexoes emitidas pelo extrator_nslkdd.py.

Fecha o circuito do prototipo do TCC:

    sudo tcpdump -i wlan0 -s 0 -nn -w - 'tcp or udp or icmp' \\
        | ./extrator_nslkdd.py --meta \\
        | ./detectar.py -m modelo.joblib

Cada conexao e classificada assim que fecha, sem esperar o fim da captura.

AVISO METODOLOGICO
O modelo foi treinado na NSL-KDD, derivada do DARPA'98: uma LAN militar
simulada, sem TLS, sem QUIC, sem CDN, sem sincronizacao em nuvem. O trafego
de um notebook em 2026 nao se parece com aquilo. Espere taxa alta de falsos
positivos -- em especial QUIC (UDP/443, que cai em `private`) e conexoes
paralelas a CDNs, que produzem contagens de host altas parecidas com
varredura. Isso e uma limitacao da base, nao um defeito do codigo, e e
exatamente o tipo de resultado que o capitulo de validacao do TCC precisa
registrar. Use --calibrar para medir sua propria taxa de alerta em trafego
que voce sabe ser legitimo.
"""

import argparse
import csv
import os
import signal
import sys
import time
from collections import Counter

import numpy as np
import joblib


VERMELHO, AMARELO, VERDE, CINZA, LIMPA = (
    '\033[31m', '\033[33m', '\033[32m', '\033[90m', '\033[0m')


SEM_COR = ('', '', '', '', '')
COM_COR = (VERMELHO, AMARELO, VERDE, CINZA, LIMPA)


class Detector:
    def __init__(self, artefato, limiar=0.5, cor=True):
        self.modelo = artefato['modelo']
        self.features = artefato['features']
        self.limiar = limiar
        self.cor = cor
        self.contagem = Counter()
        self.servicos_alerta = Counter()
        self.origens_alerta = Counter()
        self.inicio = time.time()
        self.latencias = []

    def indices(self, cabecalho):
        """Mapeia as colunas do CSV pelos nomes, nao pela posicao.

        A ordem das features e o contrato entre treino e inferencia; resolver
        por nome evita que uma mudanca de layout no extrator produza
        silenciosamente predicoes sobre colunas trocadas.
        """
        faltando = [f for f in self.features if f not in cabecalho]
        if faltando:
            raise SystemExit(
                'erro: faltam colunas na entrada: %s\n'
                'Gere a entrada com extrator_nslkdd.py (de preferencia --meta).'
                % ', '.join(faltando))
        self.idx = [cabecalho.index(f) for f in self.features]
        self.meta_idx = {nome: cabecalho.index(nome)
                         for nome in ('ts', 'src_ip', 'src_port', 'dst_ip',
                                      'dst_port', 'protocol_type', 'service',
                                      'flag')
                         if nome in cabecalho}
        self.tem_meta = len(self.meta_idx) == 8

    def classificar(self, campos):
        vetor = np.array([[float(campos[i]) for i in self.idx]])
        t0 = time.perf_counter()
        prob = float(self.modelo.predict_proba(vetor)[0][1])
        self.latencias.append((time.perf_counter() - t0) * 1000)
        return prob, prob >= self.limiar

    def formatar(self, campos, prob, ataque):
        v, _a, _g, cz, z = COM_COR if self.cor else SEM_COR
        if not self.tem_meta:
            rotulo = '%sATAQUE%s' % (v, z) if ataque else '%snormal%s' % (cz, z)
            return '%s  %.2f' % (rotulo, prob)
        m = self.meta_idx
        relogio = time.strftime('%H:%M:%S',
                                time.localtime(float(campos[m['ts']])))
        rotulo = ('%sATAQUE%s' % (v, z) if ataque else '%snormal%s' % (cz, z))
        return ('%s%s%s  %s  %.2f  %s:%s -> %s:%s  %s/%s  %s'
                % (cz, relogio, z, rotulo, prob,
                   campos[m['src_ip']], campos[m['src_port']],
                   campos[m['dst_ip']], campos[m['dst_port']],
                   campos[m['protocol_type']], campos[m['service']],
                   campos[m['flag']]))

    def registrar(self, campos, ataque):
        self.contagem['total'] += 1
        self.contagem['ataque' if ataque else 'normal'] += 1
        if ataque and self.tem_meta:
            m = self.meta_idx
            self.servicos_alerta['%s/%s' % (campos[m['protocol_type']],
                                            campos[m['service']])] += 1
            self.origens_alerta[campos[m['src_ip']]] += 1

    def resumo(self, saida):
        total = self.contagem['total']
        decorrido = time.time() - self.inicio
        saida.write('\n--- resumo ---\n')
        if not total:
            saida.write('nenhuma conexao classificada\n')
            return
        taxa = 100.0 * self.contagem['ataque'] / total
        saida.write('conexoes: %d em %.1f s (%.1f/s)\n'
                    % (total, decorrido, total / max(decorrido, 1e-9)))
        saida.write('alertas : %d (%.1f%% do trafego)\n'
                    % (self.contagem['ataque'], taxa))
        if self.latencias:
            lat = sorted(self.latencias)
            p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))]
            saida.write('latencia de inferencia: mediana %.3f ms, p95 %.3f ms\n'
                        % (lat[len(lat) // 2], p95))
        if self.servicos_alerta:
            saida.write('servicos mais alertados: %s\n' % ', '.join(
                '%s (%d)' % (s, n)
                for s, n in self.servicos_alerta.most_common(5)))
        if self.origens_alerta:
            saida.write('origens mais alertadas: %s\n' % ', '.join(
                '%s (%d)' % (o, n)
                for o, n in self.origens_alerta.most_common(5)))
        if taxa > 20:
            saida.write(
                '\nATENCAO: %.0f%% do trafego foi classificado como ataque.\n'
                'Se esta captura e de navegacao comum, isso mede o desvio\n'
                'entre a NSL-KDD (DARPA 1998) e trafego real de 2026 -- nao\n'
                'uma invasao. Veja o aviso no topo de detectar.py.\n' % taxa)


def main(argv=None):
    p = argparse.ArgumentParser(
        description='Classifica conexoes do extrator_nslkdd.py em tempo real.')
    p.add_argument('-m', '--modelo', default='modelo.joblib',
                   help='artefato gerado por treinar_modelo.py')
    p.add_argument('-r', '--read', metavar='CSV',
                   help='CSV de entrada (padrao: stdin)')
    p.add_argument('-l', '--limiar', type=float, default=0.5,
                   help='probabilidade minima para alertar (padrao: 0.5)')
    p.add_argument('--todos', action='store_true',
                   help='imprime tambem as conexoes classificadas como normais')
    p.add_argument('--registrar', metavar='CSV',
                   help='grava toda a classificacao neste CSV')
    p.add_argument('--calibrar', action='store_true',
                   help='nao imprime linha a linha; so o resumo estatistico. '
                        'Use sobre trafego sabidamente legitimo para medir '
                        'a taxa de falsos positivos do modelo na sua rede')
    p.add_argument('--sem-cor', action='store_true', help='desliga ANSI')
    args = p.parse_args(argv)

    if not os.path.isfile(args.modelo):
        raise SystemExit('erro: modelo %s nao encontrado. Rode primeiro: '
                         './treinar_modelo.py' % args.modelo)

    artefato = joblib.load(args.modelo)
    cor = not args.sem_cor and sys.stdout.isatty()
    det = Detector(artefato, limiar=args.limiar, cor=cor)

    met = artefato.get('metricas', {}).get('kddtest', {})
    sys.stderr.write(
        'modelo: %s | %d features | acuracia KDDTest+ %.4f, recall %.4f\n'
        % (args.modelo, len(det.features), met.get('acuracia', float('nan')),
           met.get('recall', float('nan'))))

    entrada = open(args.read, newline='') if args.read else sys.stdin
    registro = None
    escritor = None

    # Ctrl-C deve fechar o pipeline com o resumo, nao com um traceback.
    interrompido = {'sim': False}

    def parar(_sig, _frame):
        interrompido['sim'] = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, parar)

    try:
        leitor = csv.reader(entrada)
        try:
            cabecalho = next(leitor)
        except StopIteration:
            raise SystemExit('erro: entrada vazia')
        det.indices(cabecalho)

        if args.registrar:
            registro = open(args.registrar, 'w', newline='')
            escritor = csv.writer(registro)
            escritor.writerow(cabecalho + ['prob_ataque', 'predicao'])

        for campos in leitor:
            if len(campos) < len(cabecalho):
                continue  # linha parcial: o produtor ainda esta escrevendo
            try:
                prob, ataque = det.classificar(campos)
            except (ValueError, IndexError):
                continue
            det.registrar(campos, ataque)
            if escritor:
                escritor.writerow(
                    campos + ['%.4f' % prob, 'ataque' if ataque else 'normal'])
                registro.flush()
            if not args.calibrar and (ataque or args.todos):
                print(det.formatar(campos, prob, ataque), flush=True)
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    finally:
        if registro:
            registro.close()
        if args.read and entrada is not sys.stdin:
            entrada.close()

    det.resumo(sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
