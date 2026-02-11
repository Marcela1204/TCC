import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN

df = pd.read_csv("./datasets/CIC-IDS-2017/CSV/fryday.csv")

# Codificar protocolo
df["Protocol"] = df["Protocol"].astype("category").cat.codes

# Selecionar features
X = df[["Time", "Length", "Protocol"]].values

# Normalização (obrigatório)
scaler = StandardScaler()
x = scaler.fit_transform(X)
print("Iniciando treinamento")

kmeans = KMeans(n_clusters=3, random_state=42)
labels = kmeans.fit_predict(x)

df["Cluster"] = labels

print("Vizualização")

plt.scatter(x[:, 0], x[:, 1], c=labels, s=10)
plt.xlabel("Time")
plt.ylabel("Length")
plt.title("Separação de padrões de tráfego")
plt.show()
input("enter para continuar")
print("ok")

dbscan = DBSCAN(eps=0.5, min_samples=10)
labels = dbscan.fit_predict(x)

df["Cluster"] = labels

