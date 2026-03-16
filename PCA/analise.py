#!/bin/env python
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

# carregar dados
df = pd.read_csv("../datasets/CIC-IDS-2017/CSV/fryday.csv")


df["Source_Hash"] = df["Source"].apply(hash)
df["Destination_Hash"] = df["Destination"].apply(hash)
df["Protocol_Hash"] = df["Protocol"].apply(hash)


df = df.drop(columns=["Source", "Destination", "Protocol"])

# remover coluna target se existir
X = df.drop(columns=["Info"])

# padronizar
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)


print(pca.explained_variance_ratio_)


import matplotlib.pyplot as plt

plt.scatter(X_pca[:,0], X_pca[:,1])
plt.xlabel("PC1")
plt.ylabel("PC2")
plt.title("PCA Projection")
plt.show()
#
pca = PCA()
pca.fit(X_scaled)

import numpy as np
var_cum = np.cumsum(pca.explained_variance_ratio_)

plt.plot(var_cum)
plt.xlabel("Número de componentes")
plt.ylabel("Variância acumulada")
plt.show()
#
loadings = pd.DataFrame(
    pca.components_.T,
    columns=[f'PC{i+1}' for i in range(len(X.columns))],
    index=X.columns
)
print(loadings)
