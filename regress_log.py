import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.datasets import make_classification # Para gerar um dataset de exemplo

# --- 1. Geração de um dataset de exemplo (SUBSTITUA A PARTIR DAQUI COM SEU PRÓPRIO DATASET) ---
# Se você já tem seu CSV/Excel, pode pular esta seção de make_classification e ir direto para pd.read_csv

# Gerar um dataset de classificação binária de exemplo
# X_exemplo, y_exemplo = make_classification(
#     n_samples=1000,      # Número de amostras
#     n_features=20,       # Número total de features
#     n_informative=10,    # Número de features informativas
#     n_redundant=5,       # Número de features redundantes
#     n_classes=2,         # Duas classes para classificação binária
#     random_state=42      # Para reprodutibilidade
# )

# Converter para DataFrame do pandas para simular a importação do seu dataset
# As colunas 'feature_0', 'feature_1', etc., representam suas features de entrada
# A coluna 'target' representa sua variável dependente (o que você quer prever)
# df_seu_dataset = pd.DataFrame(X_exemplo, columns=[f'feature_{i}' for i in range(X_exemplo.shape[1])])
# df_seu_dataset['target'] = y_exemplo

# print("Prévia do seu dataset de exemplo:")
# print(df_seu_dataset.head())
# print("\n")

# --- COMO IMPORTAR SEU PRÓPRIO DATASET ---
# DESCOMENTE e MODIFIQUE a linha abaixo para carregar seu arquivo CSV ou Excel.
# Certifique-se de que o arquivo esteja no mesmo diretório do seu script Python,
# ou forneça o caminho completo para o arquivo.

# Para CSV:
df_seu_dataset = pd.read_csv('./datasets/CIC-IDS-2017/CSV/fryday.csv')

# Para Excel:
# df_seu_dataset = pd.read_excel('seu_arquivo.xlsx')

# Certifique-se de que as colunas que você usará como features e target estejam no seu DataFrame.
# Por exemplo, se seu CSV tem colunas 'Idade', 'Renda', 'Histórico_Crédito', 'Comprou_Produto',
# você as usaria na próxima etapa.

# --- 2. Preparação dos dados ---

# Defina suas features (X) e sua variável alvo (y)
# Substitua 'target' pelo nome da coluna que você quer prever no seu dataset
# Substitua as colunas de exemplo abaixo pelas colunas de features do seu dataset.
# Exemplo: features = ['Idade', 'Renda', 'Histórico_Crédito']
# Exemplo: target_column = 'Comprou_Produto'

target_column = 'Length'
features = [col for col in df_seu_dataset.columns if col != target_column]

X = df_seu_dataset[features]
y = df_seu_dataset[target_column]

print(f"Features (X) shape: {X.shape}")
print(f"Target (y) shape: {y.shape}")
print("\n")

# Dividir os dados em conjuntos de treinamento e teste
# 80% para treinamento, 20% para teste
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"X_train shape: {X_train.shape}")
print(f"X_test shape: {X_test.shape}")
print("\n")

# --- 3. Implementação da Regressão Logística ---

# Inicializar o modelo de Regressão Logística
# 'solver' e 'max_iter' são parâmetros comuns. 'liblinear' é bom para datasets pequenos.
model = LogisticRegression(solver='liblinear', max_iter=100, random_state=42)

# Treinar o modelo com os dados de treinamento
print("Treinando o modelo de Regressão Logística...")
model.fit(X_train, y_train)
print("Modelo treinado com sucesso!\n")

# --- 4. Fazer previsões ---

# Fazer previsões no conjunto de teste
y_pred = model.predict(X_test)

# Se você precisar das probabilidades, use predict_proba
y_pred_proba = model.predict_proba(X_test)
print("Primeiras 5 previsões (classes):", y_pred[:5])
print("Primeiras 5 probabilidades (para classe 0 e 1):", y_pred_proba[:5])
print("\n")

# --- 5. Avaliar o modelo ---

# Calcular a acurácia do modelo
accuracy = accuracy_score(y_test, y_pred)
print(f"Acurácia do modelo: {accuracy:.4f}\n")

# Exibir um relatório de classificação detalhado
print("Relatório de Classificação:")
print(classification_report(y_test, y_pred))

# Acessar os coeficientes do modelo (importante para entender a contribuição de cada feature)
print("Coeficientes do modelo:")
for i, feature in enumerate(features):
    print(f"  {feature}: {model.coef_[0][i]:.4f}")
print(f"Intercepto: {model.intercept_[0]:.4f}")
