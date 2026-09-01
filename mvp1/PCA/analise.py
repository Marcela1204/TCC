#!/bin/env python
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import hashlib
import sys

# carregar dados
# df = pd.read_csv("../datasets/CIC-IDS-2017/CSV/fryday.csv")
df = pd.read_csv(sys.argv[1])


df["Source_Hash"] = df["Source"].apply(lambda x: int(hashlib.md5(str(x).encode()).hexdigest(),16))
df["Destination_Hash"] = df["Destination"].apply(lambda x: int(hashlib.md5(str(x).encode()).hexdigest(),16))
df["Protocol_Hash"] = df["Protocol"].apply(lambda x: int(hashlib.md5(str(x).encode()).hexdigest(),16))


df = df.drop(columns=["Source", "Destination", "Protocol"])

# remover coluna target se existir
X = df.drop(columns=["Info"])

# padronizar
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

print(sys.argv[1])
print(pca.explained_variance_ratio_)


import matplotlib.pyplot as plt

# plt.scatter(X_pca[:,0], X_pca[:,1])
# plt.xlabel("PC1")
# plt.ylabel("PC2")
# plt.title("PCA Projection")
# plt.show()
#
pca = PCA()
pca.fit(X_scaled)

import numpy as np
var_cum = np.cumsum(pca.explained_variance_ratio_)

# plt.plot(var_cum)
# plt.xlabel("Número de componentes")
# plt.ylabel("Variância acumulada")
# plt.show()
#
loadings = pd.DataFrame(
    pca.components_.T,
    columns=[f'PC{i+1}' for i in range(len(X.columns))],
    index=X.columns
)
print(loadings)

x = np.arange(len(loadings.index))
width = 0.12

for i, col in enumerate(loadings.columns):
    plt.bar(x + i * width, loadings[col], width, label=col)

plt.xticks(x + width * (len(loadings.columns) / 2), loadings.index, rotation=30)
plt.legend()
plt.title("Loadings PCA")
plt.tight_layout()

plt.show()
