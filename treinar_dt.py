#!/usr/bin/env python3
"""
Treina o Decision Tree do TCC sobre a NSL-KDD (base do Kaggle:
hassan06/nslkdd), restrito as 16 features que o extrator_nslkdd.py consegue
observar em trafego real de rede.

Por que 16 e nao 41: o modelo so serve para deteccao ao vivo se todas as
suas entradas puderem ser calculadas a partir do que passa na interface.
As features de payload da NSL-KDD (`hot`, `logged_in`, `num_root`, ...)
exigem inspecao de conteudo em texto claro, que TLS elimina. A lista de 16
e o contrato com o extrator -- a ordem importa e nao pode mudar de um lado
sem mudar do outro.

Diferenca para treinar_modelo.py: aquele produz apenas o classificador
binario. Este acrescenta o que a deteccao ao vivo precisa -- modelo de
familia de ataque, recall por tipo na KDDTest+, importancia das features e
latencia de inferencia unitaria -- no mesmo artefato.

Treina dois modelos sobre o mesmo vetor de entrada:

  * binario      normal x ataque          -> dispara o alerta
  * multiclasse  normal/dos/probe/r2l/u2r -> diz QUAL familia de ataque

Avalia em dois regimes, porque medem coisas diferentes:

  * particao interna da KDDTrain+ (70/30), otimista: os mesmos tipos de
    ataque aparecem no treino e no teste;
  * KDDTest+ oficial, que contem 17 tipos de ataque ausentes do treino e
    portanto mede generalizacao para o desconhecido.

A diferenca entre os dois numeros e um resultado do TCC, nao um defeito.

Uso:
    ./treinar_dt.py                        # treina e salva modelo_dt.joblib
    ./treinar_dt.py --profundidade 12 --balanceado
    ./treinar_dt.py --comparar             # custo/beneficio contra o RF
    ./treinar_dt.py --cv 5
"""

import argparse
import os
import sys
import time

from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.tree import DecisionTreeClassifier
import joblib

# Reaproveita o layout da base e o localizador de arquivos ja usados pelo
# resto do prototipo, para que treino e inferencia nao divirjam.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from treinar_modelo import (FEATURES_16, carregar,  # noqa: E402
                            localizar_base)


# Mapa oficial da NSL-KDD/DARPA de rotulo -> familia de ataque.
# Cobre os 22 tipos da KDDTrain+ e os 37 da KDDTest+ (os 17 tipos novos que
# so aparecem no teste estao marcados com *).
CATEGORIAS = {
    # DoS
    'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos',
    'smurf': 'dos', 'teardrop': 'dos',
    'apache2': 'dos', 'mailbomb': 'dos', 'processtable': 'dos',      # *
    'udpstorm': 'dos',                                               # *
    # Probe
    'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe',
    'satan': 'probe',
    'mscan': 'probe', 'saint': 'probe',                              # *
    # R2L
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l',
    'multihop': 'r2l', 'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l',
    'warezmaster': 'r2l',
    'httptunnel': 'r2l', 'named': 'r2l', 'sendmail': 'r2l',          # *
    'snmpgetattack': 'r2l', 'snmpguess': 'r2l', 'worm': 'r2l',       # *
    'xlock': 'r2l', 'xsnoop': 'r2l',                                 # *
    # U2R
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r',
    'rootkit': 'u2r',
    'ps': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r',                 # *
}

ORDEM_CATEGORIAS = ['normal', 'dos', 'probe', 'r2l', 'u2r']


def categorizar(serie):
    """Rotulo bruto -> familia. Rotulo desconhecido vira 'desconhecido'.

    A alternativa comum (`else: return 'u2r'`) despeja todo tipo novo na
    classe mais rara e corrompe silenciosamente as metricas por familia --
    especialmente na KDDTest+, onde 17 tipos nao existem no treino.
    """
    cat = serie.map(lambda r: 'normal' if r == 'normal'
                    else CATEGORIAS.get(r, 'desconhecido'))
    faltando = sorted(set(serie[cat == 'desconhecido']))
    if faltando:
        sys.stderr.write('aviso: rotulos fora do mapa de categorias: %s\n'
                         % ', '.join(faltando))
    return cat


def preparar(df, features):
    """Separa X, y binario e y por familia.

    Nenhuma das 16 features e categorica -- sao contagens, bytes, duracao e
    taxas. Nao ha LabelEncoder no caminho e, por ser uma arvore, tambem nao
    ha normalizacao: o unico artefato que precisa sobreviver ate a
    inferencia e a ORDEM das colunas.
    """
    X = df[features].astype('float64').to_numpy()
    y = (df['label'] != 'normal').astype('int8').to_numpy()
    y_cat = categorizar(df['label']).to_numpy()
    return X, y, y_cat


def construir(args):
    return DecisionTreeClassifier(
        criterion=args.criterio,
        max_depth=args.profundidade,
        min_samples_leaf=args.min_folha,
        class_weight='balanced' if args.balanceado else None,
        random_state=args.semente)


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


def recall_por_tipo(df, pred):
    """Recall discriminado por tipo de ataque.

    A acuracia agregada esconde o que interessa operacionalmente: um modelo
    pode ir muito bem em DoS volumetrico, que domina a contagem, e nao ver
    nenhuma escalada de privilegio.
    """
    linhas = []
    rotulos = df['label'].to_numpy()
    for tipo in sorted(set(rotulos)):
        if tipo == 'normal':
            continue
        mascara = rotulos == tipo
        n = int(mascara.sum())
        det = int(pred[mascara].sum())
        linhas.append((tipo, CATEGORIAS.get(tipo, '?'), n, det, det / n))
    return sorted(linhas, key=lambda r: r[4])


def latencia_inferencia(modelo, X, amostras=2000):
    """Mede o custo de classificar UMA conexao, que e o regime ao vivo.

    Predizer em lote diz pouco sobre um IDS que recebe uma conexao por vez;
    o numero que importa para o capitulo de viabilidade e este.
    """
    n = min(amostras, len(X))
    tempos = []
    for i in range(n):
        vetor = X[i:i + 1]
        t0 = time.perf_counter()
        modelo.predict_proba(vetor)
        tempos.append((time.perf_counter() - t0) * 1000)
    tempos.sort()
    return {
        'n': n,
        'mediana_ms': tempos[n // 2],
        'p95_ms': tempos[min(n - 1, int(0.95 * n))],
        'media_ms': sum(tempos) / n,
    }


def main(argv=None):
    p = argparse.ArgumentParser(
        description='Treina o Decision Tree na NSL-KDD com as 16 features '
                    'observaveis em trafego real.')
    p.add_argument('--dados', help='diretorio com KDDTrain+.txt e KDDTest+.txt '
                                   '(padrao: cache do kagglehub)')
    p.add_argument('-o', '--saida', default='modelo_dt.joblib',
                   help='arquivo de saida (padrao: modelo_dt.joblib)')
    p.add_argument('--criterio', choices=('gini', 'entropy', 'log_loss'),
                   default='gini', help='criterio de divisao (padrao: gini)')
    p.add_argument('--profundidade', type=int, default=None,
                   help='max_depth (padrao: sem limite)')
    p.add_argument('--min-folha', type=int, default=1,
                   help='min_samples_leaf; acima de 1 poda a arvore e suaviza '
                        'as probabilidades (padrao: 1)')
    p.add_argument('--balanceado', action='store_true',
                   help='class_weight=balanced; melhora recall de r2l/u2r '
                        'ao custo de falsos positivos')
    p.add_argument('--semente', type=int, default=42,
                   help='random_state, como na Tabela II do TCC')
    p.add_argument('--cv', type=int, default=0,
                   help='dobras de validacao cruzada na KDDTrain+ (0 desliga)')
    p.add_argument('--comparar', action='store_true',
                   help='treina tambem um Random Forest para medir o que a '
                        'arvore unica deixa na mesa')
    p.add_argument('--sem-multiclasse', action='store_true',
                   help='nao treina o modelo de familia de ataque')
    args = p.parse_args(argv)

    base = localizar_base(args.dados)
    print('base NSL-KDD: %s\n' % base)

    treino_df = carregar(base, 'KDDTrain+.txt')
    teste_df = carregar(base, 'KDDTest+.txt')

    n_normal = int((treino_df['label'] == 'normal').sum())
    print('KDDTrain+: %d registros (%d normal, %d ataque, %d tipos)'
          % (len(treino_df), n_normal, len(treino_df) - n_normal,
             treino_df['label'].nunique() - 1))
    n_normal_t = int((teste_df['label'] == 'normal').sum())
    novos = set(teste_df['label']) - set(treino_df['label'])
    print('KDDTest+ : %d registros (%d normal, %d ataque, %d tipos, '
          '%d deles inexistentes no treino)\n'
          % (len(teste_df), n_normal_t, len(teste_df) - n_normal_t,
             teste_df['label'].nunique() - 1, len(novos)))

    X, y, y_cat = preparar(treino_df, FEATURES_16)
    X_teste, y_teste, y_cat_teste = preparar(teste_df, FEATURES_16)

    print('distribuicao por familia na KDDTrain+:')
    for cat in ORDEM_CATEGORIAS:
        n = int((y_cat == cat).sum())
        print('  %-8s %7d  (%5.2f%%)' % (cat, n, 100.0 * n / len(y_cat)))
    print()

    # Regime 1: particao interna, comparavel a Tabela II do TCC.
    X_tr, X_val, y_tr, y_val = train_test_split(
        X, y, test_size=0.30, random_state=args.semente, stratify=y)
    modelo_val = construir(args)
    t0 = time.perf_counter()
    modelo_val.fit(X_tr, y_tr)
    t_fit = time.perf_counter() - t0
    m_val, _ = avaliar(modelo_val, X_val, y_val, 'particao interna 30%')

    # Regime 2: modelo final, treinado em toda a KDDTrain+ e avaliado na
    # KDDTest+ oficial.
    modelo = construir(args)
    t0 = time.perf_counter()
    modelo.fit(X, y)
    t_fit_full = time.perf_counter() - t0
    m_teste, pred_teste = avaliar(modelo, X_teste, y_teste, 'KDDTest+ oficial')

    print('%-22s %7s  %-9s %-8s %-8s %-7s %8s'
          % ('conjunto', 'n', 'acuracia', 'precisao', 'recall', 'f1',
             'teste(s)'))
    print('-' * 78)
    print(linha_metrica(m_val))
    print(linha_metrica(m_teste))
    print('\ntempo de treino: %.4f s (particao) / %.4f s (base completa)'
          % (t_fit, t_fit_full))
    print('arvore final: profundidade %d, %d folhas, %d nos'
          % (modelo.get_depth(), modelo.get_n_leaves(),
             modelo.tree_.node_count))

    print('\nmatriz de confusao na KDDTest+ (linha=real, coluna=predito):')
    print('              normal   ataque')
    print('  normal    %8d %8d' % (m_teste['tn'], m_teste['fp']))
    print('  ataque    %8d %8d' % (m_teste['fn'], m_teste['tp']))
    print('  taxa de falso positivo: %.2f%%'
          % (100.0 * m_teste['fp'] / max(m_teste['fp'] + m_teste['tn'], 1)))
    print('\n' + classification_report(y_teste, pred_teste,
                                       target_names=['normal', 'ataque'],
                                       digits=4, zero_division=0))

    print('recall por tipo de ataque na KDDTest+ (pior primeiro):')
    for tipo, fam, n, det, taxa in recall_por_tipo(teste_df, pred_teste):
        marca = ' [novo]' if tipo in novos else ''
        print('  %-18s %-6s %6d  detectados %6d  recall %.4f%s'
              % (tipo, fam, n, det, taxa, marca))

    imp = sorted(zip(FEATURES_16, modelo.feature_importances_),
                 key=lambda r: r[1], reverse=True)
    print('\nimportancia das features (Decision Tree, base completa):')
    for i, (nome, valor) in enumerate(imp, 1):
        print('  %2d. %-30s %.4f' % (i, nome, valor))

    lat = latencia_inferencia(modelo, X_teste)
    print('\nlatencia de inferencia por conexao (n=%d): mediana %.3f ms, '
          'p95 %.3f ms' % (lat['n'], lat['mediana_ms'], lat['p95_ms']))

    # Modelo multiclasse: mesmo vetor de entrada, alvo por familia.
    artefato_multi = None
    if not args.sem_multiclasse:
        modelo_cat = construir(args)
        t0 = time.perf_counter()
        modelo_cat.fit(X, y_cat)
        t_fit_cat = time.perf_counter() - t0
        pred_cat = modelo_cat.predict(X_teste)
        presentes = [c for c in ORDEM_CATEGORIAS
                     if c in set(y_cat_teste) or c in set(pred_cat)]
        print('\n' + '=' * 78)
        print('MODELO MULTICLASSE (familia de ataque) -- KDDTest+')
        print('=' * 78)
        print(classification_report(y_cat_teste, pred_cat, labels=presentes,
                                    digits=4, zero_division=0))
        cm = confusion_matrix(y_cat_teste, pred_cat, labels=presentes)
        print('matriz de confusao (linha=real, coluna=predito):')
        print('           ' + ''.join('%9s' % c for c in presentes))
        for nome, linha in zip(presentes, cm):
            print('  %-8s ' % nome + ''.join('%9d' % v for v in linha))
        artefato_multi = {
            'modelo': modelo_cat,
            'classes': list(modelo_cat.classes_),
            'acuracia_kddtest': accuracy_score(y_cat_teste, pred_cat),
            'tempo_treino_s': t_fit_cat,
        }

    if args.cv:
        escores = cross_val_score(construir(args), X, y, cv=args.cv,
                                  scoring='f1', n_jobs=-1)
        print('\nvalidacao cruzada (%d dobras, f1): %.4f +/- %.4f'
              % (args.cv, escores.mean(), escores.std()))

    if args.comparar:
        # O RF entra so como referencia: mede quanto de generalizacao a
        # arvore unica troca por interpretabilidade e latencia.
        from sklearn.ensemble import RandomForestClassifier
        rf = RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                    class_weight='balanced'
                                    if args.balanceado else None,
                                    random_state=args.semente)
        t0 = time.perf_counter()
        rf.fit(X, y)
        t_rf = time.perf_counter() - t0
        rf.n_jobs = 1   # predicao unitaria: threads so atrapalham
        m_rf, _ = avaliar(rf, X_teste, y_teste, 'RandomForest KDDTest+')
        lat_rf = latencia_inferencia(rf, X_teste, amostras=500)
        print('\ncomparacao com o ensemble (100 arvores):')
        print(linha_metrica(m_teste))
        print(linha_metrica(m_rf))
        print('  delta acuracia: %+.4f | delta f1: %+.4f'
              % (m_teste['acuracia'] - m_rf['acuracia'],
                 m_teste['f1'] - m_rf['f1']))
        print('  treino: %.2f s (arvore) vs %.2f s (floresta)'
              % (t_fit_full, t_rf))
        print('  latencia por conexao: %.3f ms (arvore) vs %.3f ms (floresta)'
              % (lat['mediana_ms'], lat_rf['mediana_ms']))

    artefato = {
        'modelo': modelo,
        'features': FEATURES_16,   # a ordem e o contrato com o extrator
        'classes': {0: 'normal', 1: 'ataque'},
        'multiclasse': artefato_multi,
        'metricas': {'particao_interna': m_val, 'kddtest': m_teste,
                     'latencia': lat},
        'importancias': imp,
        'treino': {
            'base': 'NSL-KDD KDDTrain+.txt (kaggle: hassan06/nslkdd)',
            'algoritmo': 'DecisionTreeClassifier',
            'criterion': args.criterio,
            'max_depth': args.profundidade,
            'min_samples_leaf': args.min_folha,
            'class_weight': 'balanced' if args.balanceado else None,
            'profundidade_final': modelo.get_depth(),
            'n_folhas': int(modelo.get_n_leaves()),
            'n_registros': len(treino_df),
            'semente': args.semente,
            'tempo_treino_s': t_fit_full,
        },
        'sklearn': __import__('sklearn').__version__,
    }
    joblib.dump(artefato, args.saida, compress=3)
    print('\nmodelo salvo em %s (%.1f KB)'
          % (args.saida, os.path.getsize(args.saida) / 1024))
    print('detecte ao vivo com:  ./monitor_wlan0.py -m %s' % args.saida)
    return 0


if __name__ == '__main__':
    sys.exit(main())
