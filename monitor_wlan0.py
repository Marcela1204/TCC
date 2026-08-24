#!/usr/bin/env python3
"""
IDS ao vivo: escuta uma interface (padrao wlan0), reconstroi conexoes e
classifica cada uma com o Decision Tree treinado por treinar_dt.py,
alertando quando um ataque e detectado.

Monta e supervisiona o pipeline inteiro em um unico comando:

    tcpdump -i wlan0 -w -  ->  extrator_nslkdd.py --meta  ->  este script

Uso:
    sudo ./monitor_wlan0.py                          # wlan0, modelo_dt.joblib
    sudo ./monitor_wlan0.py -i eth0 --limiar 0.8
    sudo ./monitor_wlan0.py --backend tshark
    sudo ./monitor_wlan0.py --todos --registrar sessao.csv
    ./monitor_wlan0.py --pcap captura.pcap           # sem captura ao vivo

A captura exige root (CAP_NET_RAW). Sem privilegio, o script reexecuta
apenas o tcpdump/tshark sob sudo -- a classificacao continua no usuario
comum.

AVISO METODOLOGICO
A NSL-KDD deriva do DARPA'98: uma LAN militar simulada, sem TLS, sem QUIC,
sem CDN, sem sincronizacao em nuvem. O trafego de um notebook em 2026 nao
se parece com aquilo. Espere taxa alta de falsos positivos -- em especial
QUIC (UDP/443, que cai em `private`) e conexoes paralelas a CDNs, que
produzem contagens por host parecidas com varredura. Isso e limitacao da
base, nao defeito do codigo, e e exatamente o que o capitulo de validacao
precisa registrar. Rode --calibrar sobre trafego sabidamente legitimo para
medir sua propria taxa de alerta antes de confiar em qualquer alarme.
"""

import argparse
import csv
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter, defaultdict

import numpy as np
import joblib


AQUI = os.path.dirname(os.path.abspath(__file__))
EXTRATOR = os.path.join(AQUI, 'extrator_nslkdd.py')

VERMELHO, AMARELO, VERDE, CINZA, NEGRITO, LIMPA = (
    '\033[31m', '\033[33m', '\033[32m', '\033[90m', '\033[1m', '\033[0m')

# Filtro BPF: o extrator so modela IPv4/TCP/UDP/ICMP, entao nem vale a pena
# copiar o resto para o espaco de usuario.
FILTRO = 'ip and (tcp or udp or icmp)'

# Descricao curta de cada familia, para o alerta dizer o que esta em jogo.
FAMILIAS = {
    'dos': 'negacao de servico (inundacao/exaustao)',
    'probe': 'varredura/reconhecimento',
    'r2l': 'acesso remoto nao autorizado',
    'u2r': 'escalada de privilegio',
    'ataque': 'anomalia (modelo binario)',
}


def sem_cor(ativo):
    return ('', '', '', '', '', '') if not ativo else (
        VERMELHO, AMARELO, VERDE, CINZA, NEGRITO, LIMPA)


def precisa_sudo(args):
    """Decide se a captura precisa de sudo.

    O tshark captura pelo dumpcap, que em distribuicoes derivadas do Debian
    vem com cap_net_raw e grupo `wireshark`. Se o usuario esta nesse grupo,
    exigir sudo seria pedir senha a toa -- e rodar um IDS inteiro como root
    quando so a captura precisa de privilegio.
    """
    if os.geteuid() == 0 or args.sem_sudo:
        return False
    if args.backend == 'tshark':
        dumpcap = shutil.which('dumpcap')
        if dumpcap and os.access(dumpcap, os.X_OK):
            return False
    return True


def comando_captura(args):
    """Monta o comando de captura, ja com sudo se necessario."""
    if args.backend == 'tcpdump':
        if not shutil.which('tcpdump'):
            raise SystemExit('erro: tcpdump nao encontrado no PATH')
        # -U: entrega pacote a pacote, sem esperar o buffer encher. Sem isso
        # o alerta chega minutos depois do ataque.
        cmd = ['tcpdump', '-i', args.interface, '-s', '0', '-nn', '-U',
               '-w', '-']
        if args.promiscuo is False:
            cmd.append('-p')
        cmd.append(args.filtro)
    else:
        if not shutil.which('tshark'):
            raise SystemExit('erro: tshark nao encontrado no PATH')
        cmd = ['tshark', '-i', args.interface, '-s', '0', '-q', '-w', '-',
               '-f', args.filtro]
        if args.promiscuo is False:
            cmd.append('-p')
    if precisa_sudo(args):
        cmd = ['sudo'] + cmd
    return cmd


def verificar_interface(nome):
    caminho = '/sys/class/net/%s' % nome
    if not os.path.exists(caminho):
        disponiveis = sorted(os.listdir('/sys/class/net'))
        raise SystemExit('erro: interface %s nao existe. Disponiveis: %s'
                         % (nome, ', '.join(disponiveis)))
    try:
        with open(os.path.join(caminho, 'operstate')) as fh:
            estado = fh.read().strip()
        if estado not in ('up', 'unknown'):
            sys.stderr.write('aviso: %s esta "%s" -- pode nao haver trafego\n'
                             % (nome, estado))
    except OSError:
        pass


class Monitor:
    def __init__(self, artefato, args):
        self.modelo = artefato['modelo']
        self.features = artefato['features']
        multi = artefato.get('multiclasse')
        self.modelo_cat = multi['modelo'] if multi and not args.sem_familia \
            else None
        self.limiar = args.limiar
        self.todos = args.todos
        self.calibrar = args.calibrar
        self.janela = args.agrupar
        self.cor = args.cor
        self.contagem = Counter()
        self.por_familia = Counter()
        self.origens = Counter()
        self.servicos = Counter()
        self.latencias = []
        self.ultimo_alerta = {}
        self.suprimidos = defaultdict(int)
        self.inicio = time.time()

    def indices(self, cabecalho):
        """Resolve as colunas por nome, nunca por posicao.

        A ordem das features e o contrato entre treino e inferencia; casar
        por nome evita que uma mudanca de layout no extrator produza
        silenciosamente predicoes sobre colunas trocadas.
        """
        faltando = [f for f in self.features if f not in cabecalho]
        if faltando:
            raise SystemExit('erro: faltam colunas na entrada: %s'
                             % ', '.join(faltando))
        self.idx = [cabecalho.index(f) for f in self.features]
        self.meta = {n: cabecalho.index(n) for n in
                     ('ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                      'protocol_type', 'service', 'flag') if n in cabecalho}
        self.tem_meta = len(self.meta) == 8

    def classificar(self, campos):
        vetor = np.array([[float(campos[i]) for i in self.idx]])
        t0 = time.perf_counter()
        prob = float(self.modelo.predict_proba(vetor)[0][1])
        familia = None
        if prob >= self.limiar and self.modelo_cat is not None:
            familia = str(self.modelo_cat.predict(vetor)[0])
            if familia == 'normal':
                # O binario acusou e o multiclasse nao soube dizer qual: o
                # alerta continua valendo, so nao ha familia atribuida.
                familia = 'ataque'
        self.latencias.append((time.perf_counter() - t0) * 1000)
        return prob, prob >= self.limiar, familia

    def chave(self, campos):
        if not self.tem_meta:
            return None
        m = self.meta
        return (campos[m['src_ip']], campos[m['dst_ip']],
                campos[m['protocol_type']], campos[m['service']])

    def deve_imprimir(self, campos, agora):
        """Agrupa alertas repetidos do mesmo par origem/destino/servico.

        Uma varredura gera centenas de conexoes por segundo; sem isso o
        terminal vira ruido e o operador perde o evento seguinte.
        """
        if self.janela <= 0:
            return True
        k = self.chave(campos)
        if k is None:
            return True
        anterior = self.ultimo_alerta.get(k)
        if anterior is not None and agora - anterior < self.janela:
            self.suprimidos[k] += 1
            return False
        self.ultimo_alerta[k] = agora
        return True

    def formatar(self, campos, prob, ataque, familia, repetidos=0):
        v, a, g, cz, n, z = sem_cor(self.cor)
        if not self.tem_meta:
            rotulo = '%s%sATAQUE%s' % (n, v, z) if ataque else \
                '%snormal%s' % (cz, z)
            return '%s  %.2f' % (rotulo, prob)
        m = self.meta
        relogio = time.strftime('%H:%M:%S',
                                time.localtime(float(campos[m['ts']])))
        if ataque:
            fam = familia or 'ataque'
            rotulo = '%s%s[ALERTA %s]%s' % (n, v, fam.upper(), z)
            desc = FAMILIAS.get(fam, '')
        else:
            rotulo = '%snormal%s' % (cz, z)
            desc = ''
        linha = ('%s%s%s %s %.2f  %s:%s %s->%s %s:%s  %s/%s %s'
                 % (cz, relogio, z, rotulo, prob,
                    campos[m['src_ip']], campos[m['src_port']],
                    cz, z,
                    campos[m['dst_ip']], campos[m['dst_port']],
                    campos[m['protocol_type']], campos[m['service']],
                    campos[m['flag']]))
        if desc:
            linha += '  %s%s%s' % (cz, desc, z)
        if repetidos:
            linha += '  %s(+%d agrupados)%s' % (a, repetidos, z)
        return linha

    def registrar(self, campos, ataque, familia):
        self.contagem['total'] += 1
        if not ataque:
            self.contagem['normal'] += 1
            return
        self.contagem['ataque'] += 1
        self.por_familia[familia or 'ataque'] += 1
        if self.tem_meta:
            m = self.meta
            self.origens[campos[m['src_ip']]] += 1
            self.servicos['%s/%s' % (campos[m['protocol_type']],
                                     campos[m['service']])] += 1

    def resumo(self, saida):
        total = self.contagem['total']
        decorrido = time.time() - self.inicio
        saida.write('\n--- resumo da sessao ---\n')
        if not total:
            saida.write('nenhuma conexao classificada '
                        '(a interface viu trafego IPv4?)\n')
            return
        taxa = 100.0 * self.contagem['ataque'] / total
        saida.write('conexoes: %d em %.1f s (%.1f/s)\n'
                    % (total, decorrido, total / max(decorrido, 1e-9)))
        saida.write('alertas : %d (%.1f%% do trafego)\n'
                    % (self.contagem['ataque'], taxa))
        if self.por_familia:
            saida.write('por familia: %s\n' % ', '.join(
                '%s %d' % (f, n) for f, n in self.por_familia.most_common()))
        if self.origens:
            saida.write('origens mais alertadas: %s\n' % ', '.join(
                '%s (%d)' % (o, n) for o, n in self.origens.most_common(5)))
        if self.servicos:
            saida.write('servicos mais alertados: %s\n' % ', '.join(
                '%s (%d)' % (s, n) for s, n in self.servicos.most_common(5)))
        if self.latencias:
            lat = sorted(self.latencias)
            saida.write('latencia de inferencia: mediana %.3f ms, p95 %.3f ms\n'
                        % (lat[len(lat) // 2],
                           lat[min(len(lat) - 1, int(0.95 * len(lat)))]))
        if self.suprimidos:
            saida.write('alertas agrupados (repeticoes suprimidas): %d\n'
                        % sum(self.suprimidos.values()))
        if taxa > 20:
            saida.write(
                '\nATENCAO: %.0f%% do trafego foi classificado como ataque.\n'
                'Se esta e uma captura de navegacao comum, isso mede o desvio\n'
                'entre a NSL-KDD (DARPA 1998) e o trafego real -- nao uma\n'
                'invasao. Veja o aviso no topo de monitor_wlan0.py.\n' % taxa)


def main(argv=None):
    p = argparse.ArgumentParser(
        description='IDS ao vivo: captura, extrai features NSL-KDD e '
                    'classifica com o Random Forest.')
    p.add_argument('-i', '--interface', default='wlan0',
                   help='interface a escutar (padrao: wlan0)')
    p.add_argument('-m', '--modelo', default=os.path.join(AQUI,
                                                          'modelo_dt.joblib'),
                   help='artefato gerado por treinar_dt.py')
    p.add_argument('--pcap', metavar='ARQUIVO',
                   help='le um pcap em vez de capturar ao vivo')
    p.add_argument('--backend', choices=('tcpdump', 'tshark'),
                   default='tcpdump', help='ferramenta de captura')
    p.add_argument('-l', '--limiar', type=float, default=0.5,
                   help='probabilidade minima para alertar (padrao: 0.5)')
    p.add_argument('-f', '--filtro', default=FILTRO,
                   help='filtro BPF (padrao: %s)' % FILTRO)
    p.add_argument('--agrupar', type=float, default=10.0,
                   help='segundos de supressao de alertas repetidos do mesmo '
                        'par origem/destino/servico (0 desliga)')
    p.add_argument('--todos', action='store_true',
                   help='imprime tambem as conexoes classificadas como normais')
    p.add_argument('--calibrar', action='store_true',
                   help='so o resumo estatistico, sem linha a linha. Use '
                        'sobre trafego sabidamente legitimo para medir a taxa '
                        'de falsos positivos na sua rede')
    p.add_argument('--registrar', metavar='CSV',
                   help='grava toda a classificacao neste CSV')
    p.add_argument('--sem-familia', action='store_true',
                   help='nao usa o modelo multiclasse (so normal/ataque)')
    p.add_argument('--sem-promiscuo', dest='promiscuo', action='store_false',
                   help='nao coloca a interface em modo promiscuo')
    p.add_argument('--sem-sudo', action='store_true',
                   help='nao prefixa a captura com sudo')
    p.add_argument('--sem-cor', dest='cor', action='store_false',
                   help='desliga ANSI')
    p.add_argument('--tcp-timeout', type=float, default=60.0,
                   help='inatividade que encerra um fluxo TCP (s)')
    p.add_argument('--udp-timeout', type=float, default=30.0,
                   help='inatividade que encerra um fluxo UDP/ICMP (s)')
    p.set_defaults(promiscuo=True, cor=True)
    args = p.parse_args(argv)
    args.cor = args.cor and sys.stdout.isatty()

    if not os.path.isfile(args.modelo):
        raise SystemExit('erro: modelo %s nao encontrado. Rode primeiro: '
                         './treinar_dt.py' % args.modelo)
    if not os.path.isfile(EXTRATOR):
        raise SystemExit('erro: extrator_nslkdd.py nao encontrado em %s' % AQUI)

    artefato = joblib.load(args.modelo)
    mon = Monitor(artefato, args)

    met = artefato.get('metricas', {}).get('kddtest', {})
    treino = artefato.get('treino', {})
    v, a, g, cz, n, z = sem_cor(args.cor)
    # Detalhe do modelo: profundidade/folhas para a arvore, numero de
    # estimadores se um dia o artefato vier de um ensemble.
    if treino.get('n_estimators'):
        detalhe = '%s arvores' % treino['n_estimators']
    elif treino.get('profundidade_final'):
        detalhe = ('profundidade %s, %s folhas'
                   % (treino['profundidade_final'], treino.get('n_folhas', '?')))
    else:
        detalhe = 'parametros nao registrados'
    sys.stderr.write(
        '%smodelo%s %s (%s, %s) | %d features | KDDTest+: acuracia '
        '%.4f, recall %.4f\n'
        % (n, z, os.path.basename(args.modelo),
           treino.get('algoritmo', '?'), detalhe,
           len(mon.features), met.get('acuracia', float('nan')),
           met.get('recall', float('nan'))))
    if mon.modelo_cat is not None:
        sys.stderr.write('familias reconhecidas: %s\n'
                         % ', '.join(artefato['multiclasse']['classes']))

    # --- monta o pipeline ---------------------------------------------------
    cmd_extrator = [sys.executable, EXTRATOR, '--meta', '--quiet',
                    '--tcp-timeout', str(args.tcp_timeout),
                    '--udp-timeout', str(args.udp_timeout)]
    captura = None

    if args.pcap:
        if not os.path.isfile(args.pcap):
            raise SystemExit('erro: %s nao encontrado' % args.pcap)
        cmd_extrator += ['--read', args.pcap]
        sys.stderr.write('lendo %s (sem captura ao vivo)\n\n' % args.pcap)
        extrator = subprocess.Popen(cmd_extrator, stdout=subprocess.PIPE,
                                    text=True, bufsize=1)
    else:
        verificar_interface(args.interface)
        cmd = comando_captura(args)
        sys.stderr.write('%scaptura%s %s\n' % (n, z, ' '.join(cmd)))
        sys.stderr.write('escutando %s%s%s, limiar %.2f -- Ctrl-C encerra\n\n'
                         % (n, args.interface, z, args.limiar))
        captura = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        extrator = subprocess.Popen(cmd_extrator, stdin=captura.stdout,
                                    stdout=subprocess.PIPE, text=True,
                                    bufsize=1)
        # O pai nao le do tcpdump; deixar o descritor aberto aqui impediria
        # o tcpdump de receber SIGPIPE se o extrator morrer.
        captura.stdout.close()

    registro = escritor = None
    # Ctrl-C deve fechar o pipeline com o resumo, nao com um traceback.
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(
        KeyboardInterrupt))

    try:
        leitor = csv.reader(extrator.stdout)
        try:
            cabecalho = next(leitor)
        except StopIteration:
            raise SystemExit('erro: o extrator nao produziu saida. A captura '
                             'falhou? Rode o comando acima manualmente.')
        mon.indices(cabecalho)

        if args.registrar:
            registro = open(args.registrar, 'w', newline='')
            escritor = csv.writer(registro)
            escritor.writerow(cabecalho + ['prob_ataque', 'predicao',
                                           'familia'])

        for campos in leitor:
            if len(campos) < len(cabecalho):
                continue  # linha parcial: o produtor ainda esta escrevendo
            try:
                prob, ataque, familia = mon.classificar(campos)
            except (ValueError, IndexError):
                continue
            mon.registrar(campos, ataque, familia)
            if escritor:
                escritor.writerow(campos + ['%.4f' % prob,
                                            'ataque' if ataque else 'normal',
                                            familia or ''])
                registro.flush()
            if args.calibrar:
                continue
            if ataque:
                agora = time.time()
                if mon.deve_imprimir(campos, agora):
                    k = mon.chave(campos)
                    reps = mon.suprimidos.pop(k, 0) if k else 0
                    print(mon.formatar(campos, prob, True, familia, reps),
                          flush=True)
            elif args.todos:
                print(mon.formatar(campos, prob, False, None), flush=True)
    except KeyboardInterrupt:
        sys.stderr.write('\nencerrando captura...\n')
    except BrokenPipeError:
        pass
    finally:
        for proc in (captura, extrator):
            if proc is None:
                continue
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if registro:
            registro.close()

    if captura is not None and captura.returncode not in (0, None,
                                                          -signal.SIGTERM):
        sys.stderr.write('aviso: a captura terminou com codigo %d '
                         '(permissao? interface?)\n' % captura.returncode)
    mon.resumo(sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
