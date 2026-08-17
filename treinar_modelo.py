#!/usr/bin/env python3
"""
Treina o DecisionTree do TCC sobre a NSL-KDD, restrito as 16 features que o
extrator_nslkdd.py consegue observar em trafego real.

O conjunto otimo identificado na Figura 4 do TCC tem 18 features. Duas delas
-- `hot` e `logged_in` -- vem de analise de payload de aplicacao em texto
claro e sao inobservaveis sob TLS. Este script treina com as 16 restantes e
reporta o custo dessa remocao.

Avalia em dois regimes, porque eles medem coisas diferentes:

  * particao interna da KDDTrain+ (70/30), comparavel a Tabela II do TCC;
  * KDDTest+ oficial, que contem tipos de ataque ausentes do treino e mede
    generalizacao para o desconhecido.

A diferenca entre os dois numeros e um resultado, nao um defeito.

Uso:
    ./treinar_modelo.py                      # treina e salva modelo.joblib
    ./treinar_modelo.py --comparar-18        # mede o custo de perder hot/logged_in
"""

import argparse
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.tree import DecisionTreeClassifier
import joblib

# Layout da NSL-KDD: 41 atributos + label + difficulty, sem cabecalho.
COLUNAS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty',
]

# As 16 observaveis, na ordem de importancia da Figura 4 do TCC.
# Esta ordem e o contrato com o extrator: mudou aqui, muda la.
FEATURES_16 = [
    'src_bytes', 'dst_host_srv_count', 'count', 'dst_bytes',
    'dst_host_srv_rerror_rate', 'dst_host_same_src_port_rate', 'srv_count',
    'dst_host_same_srv_rate', 'duration', 'wrong_fragment',
    'dst_host_rerror_rate', 'dst_host_diff_srv_rate', 'dst_host_count',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'diff_srv_rate',
]

# Conjunto original de 18, so para medir o custo de remover as duas.
FEATURES_18 = FEATURES_16 + ['hot', 'logged_in']

CACHE_KAGGLE = os.path.expanduser(
    '~/.cache/kagglehub/datasets/hassan06/nslkdd/versions/1')


def localizar_base(diretorio=None):
    """Encontra os arquivos da NSL-KDD; baixa via kagglehub se preciso."""
    candidatos = [diretorio] if diretorio else []
    candidatos += [CACHE_KAGGLE, 'datasets/NSL-KDD', '.']
    for base in candidatos:
        if base and os.path.isfile(os.path.join(base, 'KDDTrain+.txt')):
            return base
    try:
        import kagglehub
        return kagglehub.dataset_download('hassan06/nslkdd')
    except ImportError:
        raise SystemExit(
            'erro: KDDTrain+.txt nao encontrado. Passe --dados CAMINHO ou '
            'instale kagglehub (pip install kagglehub) para baixar.')


def carregar(base, arquivo):
    df = pd.read_csv(os.path.join(base, arquivo), header=None, names=COLUNAS)
    return df.drop(columns=['difficulty'])


def carregar_cicids(caminhos):
    """Le CSV rotulados por rotular_cicids.py e monta X, y.

    Mesmas 16 features da NSL-KDD, extraidas de pcap real pelo
    extrator_nslkdd.py -- e por isso o modelo resultante continua compativel
    com detectar.py sem nenhuma alteracao.
    """
    partes = []
    for caminho in caminhos:
        df = pd.read_csv(caminho)
        faltando = [c for c in FEATURES_16 + ['label'] if c not in df.columns]
        if faltando:
            raise SystemExit('erro: %s nao tem as colunas %s. Gere com '
                             'extrator_nslkdd.py --meta | rotular_cicids.py'
                             % (caminho, ', '.join(faltando)))
        df['_dia'] = os.path.basename(caminho).replace('.csv', '')
        partes.append(df)
    return pd.concat(partes, ignore_index=True)


def preparar(df, features):
    """Separa X e y. Alvo binario: 0 = normal, 1 = qualquer ataque.

    Nenhuma das 16 features e categorica -- sao todas contagens, bytes,
    duracao ou taxas. Logo nao ha LabelEncoder no caminho, e como o modelo
    e uma arvore tambem nao ha normalizacao. O unico artefato que precisa
    sobreviver ate a inferencia e a ORDEM das colunas.
    """
    X = df[features].astype('float64').to_numpy()
    y = (df['label'] != 'normal').astype('int8').to_numpy()
    return X, y


def avaliar(modelo, X, y, nome):
    inicio = time.perf_counter()
    pred = modelo.predict(X)
    tempo = time.perf_counter() - inicio
    m = {
        'conjunto': nome,
        'n': len(y),
        'acuracia': accuracy_score(y, pred),
        'precisao': precision_score(y, pred, zero_division=0),
        'recall': recall_score(y, pred, zero_division=0),
        'f1': f1_score(y, pred, zero_division=0),
        'tempo_teste_s': tempo,
    }
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    m.update({'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)})
    return m, pred


def linha_metrica(m):
    return ('%-22s %7d  %.4f    %.4f   %.4f   %.4f  %8.4f'
            % (m['conjunto'], m['n'], m['acuracia'], m['precisao'],
               m['recall'], m['f1'], m['tempo_teste_s']))


def treinar(X, y, semente=42):
    modelo = DecisionTreeClassifier(random_state=semente)
    inicio = time.perf_counter()
    modelo.fit(X, y)
    return modelo, time.perf_counter() - inicio


def recall_por_ataque(df, pred, coluna='ataque'):
    """Recall discriminado por tipo de ataque.

    A acuracia agregada esconde o que interessa operacionalmente: um modelo
    pode ir muito bem em DoS volumetrico, que domina a contagem, e nao ver
    infiltracao nenhuma.
    """
    linhas = []
    for nome, grupo in df.groupby(coluna):
        if nome == 'benigno':
            continue
        idx = grupo.index
        detectados = int(pred[idx].sum())
        linhas.append((nome, len(idx), detectados, detectados / len(idx)))
    return sorted(linhas, key=lambda r: r[3])


def treinar_cicids(args):
    """Treina sobre conexoes reais do CIC-IDS-2017 rotuladas pelo cronograma."""
    df = carregar_cicids(args.cicids)
    X = df[FEATURES_16].astype('float64').to_numpy()
    y = df['label'].astype('int8').to_numpy()

    n_ataque = int(y.sum())
    print('conexoes: %d (%d benigno, %d ataque -- %.2f%% ataque)'
          % (len(y), len(y) - n_ataque, n_ataque, 100.0 * n_ataque / len(y)))
    print('dias: %s\n' % ', '.join(sorted(df['_dia'].unique())))

    # Regime 1: particao aleatoria. Otimista -- os mesmos ataques aparecem
    # no treino e no teste.
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.30, random_state=args.semente, stratify=y)
    modelo_ale, _ = treinar(X_tr, y_tr, args.semente)
    m_ale, _ = avaliar(modelo_ale, X_te, y_te, 'particao aleatoria 30%')

    print('%-24s %7s  %-9s %-8s %-8s %-7s %8s'
          % ('regime', 'n', 'acuracia', 'precisao', 'recall', 'f1', 'teste(s)'))
    print('-' * 80)
    print(linha_metrica(m_ale))

    # Regime 2: um dia inteiro fora do treino. Os ataques do dia retido nao
    # aparecem no treino, o que mede generalizacao para ataque novo -- e o
    # analogo honesto da KDDTest+.
    dias = sorted(df['_dia'].unique())
    m_dia = None
    if len(dias) > 1:
        dia_teste = args.teste_dia or dias[-1]
        if dia_teste not in dias:
            raise SystemExit('erro: dia "%s" nao esta em %s'
                             % (dia_teste, ', '.join(dias)))
        treino_mask = (df['_dia'] != dia_teste).to_numpy()
        modelo_dia, _ = treinar(X[treino_mask], y[treino_mask], args.semente)
        m_dia, pred_dia = avaliar(modelo_dia, X[~treino_mask], y[~treino_mask],
                                  'retendo %s' % dia_teste)
        print(linha_metrica(m_dia))

    # Modelo final: toda a base disponivel.
    modelo, t_fit = treinar(X, y, args.semente)
    print('\ntempo de treino (base completa): %.4f s' % t_fit)

    print('\nmatriz de confusao, particao aleatoria:')
    print('              benigno  ataque')
    print('  benigno   %8d %8d' % (m_ale['tn'], m_ale['fp']))
    print('  ataque    %8d %8d' % (m_ale['fn'], m_ale['tp']))
    print('  taxa de falso positivo: %.2f%%'
          % (100.0 * m_ale['fp'] / max(m_ale['fp'] + m_ale['tn'], 1)))

    if 'ataque' in df.columns:
        pred_todos = modelo_ale.predict(X)
        print('\nrecall por tipo de ataque (modelo da particao aleatoria):')
        for nome, n, det, taxa in recall_por_ataque(df, pred_todos):
            print('  %-26s %7d  detectados %7d  recall %.4f'
                  % (nome, n, det, taxa))

    artefato = {
        'modelo': modelo,
        'features': FEATURES_16,
        'classes': {0: 'normal', 1: 'ataque'},
        'metricas': {'particao_aleatoria': m_ale,
                     'dia_retido': m_dia,
                     # detectar.py exibe esta chave ao iniciar
                     'kddtest': m_dia or m_ale},
        'treino': {
            'base': 'CIC-IDS-2017 (pcap -> extrator_nslkdd -> rotular_cicids)',
            'arquivos': [os.path.basename(c) for c in args.cicids],
            'n_registros': len(y),
            'n_ataque': n_ataque,
            'semente': args.semente,
            'tempo_treino_s': t_fit,
        },
        'sklearn': __import__('sklearn').__version__,
    }
    joblib.dump(artefato, args.saida)
    print('\nmodelo salvo em %s (%.1f KB)'
          % (args.saida, os.path.getsize(args.saida) / 1024))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description='Treina o DecisionTree do TCC nas 16 features observaveis.')
    p.add_argument('--cicids', nargs='+', metavar='CSV',
                   help='treina sobre CSV rotulados por rotular_cicids.py '
                        'em vez da NSL-KDD')
    p.add_argument('--teste-dia', metavar='DIA',
                   help='dia a reter do treino no modo --cicids '
                        '(padrao: o ultimo em ordem alfabetica)')
    p.add_argument('--dados', help='diretorio com KDDTrain+.txt e KDDTest+.txt')
    p.add_argument('-o', '--saida', default='modelo.joblib',
                   help='arquivo de saida do modelo (padrao: modelo.joblib)')
    p.add_argument('--semente', type=int, default=42,
                   help='random_state, como na Tabela II do TCC')
    p.add_argument('--comparar-18', action='store_true',
                   help='treina tambem com hot/logged_in para medir a perda')
    p.add_argument('--cv', type=int, default=0,
                   help='dobras de validacao cruzada (0 desliga)')
    args = p.parse_args(argv)

    if args.cicids:
        return treinar_cicids(args)

    base = localizar_base(args.dados)
    print('base NSL-KDD: %s\n' % base)

    treino_df = carregar(base, 'KDDTrain+.txt')
    teste_df = carregar(base, 'KDDTest+.txt')

    n_normal = int((treino_df['label'] == 'normal').sum())
    print('KDDTrain+: %d registros (%d normal, %d ataque)'
          % (len(treino_df), n_normal, len(treino_df) - n_normal))
    n_normal_t = int((teste_df['label'] == 'normal').sum())
    print('KDDTest+ : %d registros (%d normal, %d ataque)\n'
          % (len(teste_df), n_normal_t, len(teste_df) - n_normal_t))

    X, y = preparar(treino_df, FEATURES_16)
    X_teste, y_teste = preparar(teste_df, FEATURES_16)

    # Particao interna: reproduz o regime da Tabela II do TCC.
    X_tr, X_val, y_tr, y_val = train_test_split(
        X, y, test_size=0.30, random_state=args.semente, stratify=y)

    modelo_val, t_fit = treinar(X_tr, y_tr, args.semente)
    m_val, _ = avaliar(modelo_val, X_val, y_val, 'particao interna 30%')

    # Modelo final: treinado em toda a KDDTrain+, avaliado na KDDTest+.
    modelo, t_fit_full = treinar(X, y, args.semente)
    m_teste, pred_teste = avaliar(modelo, X_teste, y_teste, 'KDDTest+ oficial')

    print('%-22s %7s  %-9s %-8s %-8s %-7s %8s'
          % ('conjunto', 'n', 'acuracia', 'precisao', 'recall', 'f1', 'teste(s)'))
    print('-' * 78)
    print(linha_metrica(m_val))
    print(linha_metrica(m_teste))
    print('\ntempo de treino: %.4f s (particao) / %.4f s (base completa)'
          % (t_fit, t_fit_full))

    print('\nmatriz de confusao na KDDTest+ (linha=real, coluna=predito):')
    print('              normal   ataque')
    print('  normal    %8d %8d' % (m_teste['tn'], m_teste['fp']))
    print('  ataque    %8d %8d' % (m_teste['fn'], m_teste['tp']))
    print('\n' + classification_report(y_teste, pred_teste,
                                       target_names=['normal', 'ataque'],
                                       digits=4, zero_division=0))

    if args.cv:
        escores = cross_val_score(
            DecisionTreeClassifier(random_state=args.semente), X, y,
            cv=args.cv, scoring='accuracy', n_jobs=-1)
        print('validacao cruzada (%d dobras): %.4f +/- %.4f\n'
              % (args.cv, escores.mean(), escores.std()))

    if args.comparar_18:
        X18, y18 = preparar(treino_df, FEATURES_18)
        X18_te, y18_te = preparar(teste_df, FEATURES_18)
        X18_tr, X18_val, y18_tr, y18_val = train_test_split(
            X18, y18, test_size=0.30, random_state=args.semente, stratify=y18)
        m18_val, _ = avaliar(*[treinar(X18_tr, y18_tr, args.semente)[0]],
                             X18_val, y18_val, '18 feats, interna')
        m18_te, _ = avaliar(treinar(X18, y18, args.semente)[0],
                            X18_te, y18_te, '18 feats, KDDTest+')
        print('custo de remover hot e logged_in:')
        print(linha_metrica(m18_val))
        print(linha_metrica(m18_te))
        print('  delta acuracia interna : %+.4f'
              % (m_val['acuracia'] - m18_val['acuracia']))
        print('  delta acuracia KDDTest+: %+.4f\n'
              % (m_teste['acuracia'] - m18_te['acuracia']))

    artefato = {
        'modelo': modelo,
        'features': FEATURES_16,   # a ordem e o contrato com o extrator
        'classes': {0: 'normal', 1: 'ataque'},
        'metricas': {'particao_interna': m_val, 'kddtest': m_teste},
        'treino': {
            'base': 'NSL-KDD KDDTrain+.txt',
            'n_registros': len(treino_df),
            'semente': args.semente,
            'tempo_treino_s': t_fit_full,
        },
        'sklearn': __import__('sklearn').__version__,
    }
    joblib.dump(artefato, args.saida)
    print('modelo salvo em %s (%.1f KB)'
          % (args.saida, os.path.getsize(args.saida) / 1024))
    return 0


if __name__ == '__main__':
    sys.exit(main())
