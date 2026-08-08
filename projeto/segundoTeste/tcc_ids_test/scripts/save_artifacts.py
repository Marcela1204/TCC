# scripts/save_artifacts.py
"""
Script para salvar os artefatos do MVP1.
Execute isso no seu notebook do MVP1.
"""

import pickle
import json
import os
from sklearn.preprocessing import StandardScaler


def save_artifacts(X_train, y_train, model, categorical_encoders, selected_features):
    """
    Salva todos os artefatos necessários.
    
    Args:
        X_train: Dados de treino (pós padronização)
        y_train: Labels de treino
        model: Modelo treinado (Decision Tree)
        categorical_encoders: Dict com LabelEncoders
        selected_features: Lista das top features
    """
    model_dir = './models'
    os.makedirs(model_dir, exist_ok=True)
    
    # 1. Salvar modelo
    with open(f'{model_dir}/decision_tree_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    
    # 2. Salvar scaler
    scaler = StandardScaler()
    scaler.fit(X_train)
    with open(f'{model_dir}/scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    # 3. Salvar label encoders
    for name, encoder in categorical_encoders.items():
        with open(f'{model_dir}/label_encoder_{name}.pkl', 'wb') as f:
            pickle.dump(encoder, f)
    
    # 4. Salvar features selecionadas
    with open(f'{model_dir}/selected_features.json', 'w') as f:
        json.dump(selected_features, f)
    
    print(f"✅ Artefatos salvos em {model_dir}")
    print(f"   - Modelo: decision_tree_model.pkl")
    print(f"   - Scaler: scaler.pkl")
    print(f"   - Encoders: label_encoder_*.pkl")
    print(f"   - Features: selected_features.json")