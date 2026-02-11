import pandas as pd
import matplotlib.pyplot as plt
from sklearn.inspection import DecisionBoundaryDisplay
from sklearn.svm import SVC

# carregar dataset
df = pd.read_csv("./datasets/CIC-IDS-2017/CSV/fryday.csv")

# escolher DUAS features (obrigatório pra plotar a fronteira)
X = df[["Time", "Lenght"]].values
y = df["Label"].values

svm = SVC(kernel="linear", C=1)
svm.fit(X, y)

DecisionBoundaryDisplay.from_estimator(
    svm,
    X,
    response_method="predict",
    alpha=0.8,
    cmap="Pastel1",
    xlabel="Time",
    ylabel="Lenght",
)

plt.scatter(X[:, 0], X[:, 1],
            c=y,
            s=20,
            edgecolors="k")
plt.show()

