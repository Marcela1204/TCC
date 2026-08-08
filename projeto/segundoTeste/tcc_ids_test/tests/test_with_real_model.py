# tests/test_with_real_model.py
"""
Teste do pipeline completo com o modelo real.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pickle
import numpy as np
from src.core.feature_extractor import FeatureExtractor, NetworkFlow
from scripts.simulate_attack import simulate_flows


class RealModelPredictor:
    """Predictor que usa o modelo real treinado."""
    
    def __init__(self, model_dir: str = './models'):
        self.model_dir = model_dir
        self.model = None
        self.extractor = FeatureExtractor(model_dir)
        
    def load_artifacts(self):
        """Carrega modelo e extrator."""
        # Carregar extrator
        self.extractor.load_artifacts()
        
        # Carregar modelo
        model_path = f'{self.model_dir}/decision_tree_model.pkl'
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"✅ Modelo carregado de {model_path}")
        else:
            print("⚠️ Modelo não encontrado. Use o detector simples.")
            return False
        
        return True
    
    def predict(self, flow: NetworkFlow) -> tuple:
        """Prediz usando o modelo real."""
        if self.model is None:
            # Fallback para detector simples
            from test_simple import SimpleDetector
            detector = SimpleDetector()
            return detector.predict(flow)
        
        # Extrair features
        features = self.extractor.extract_features(flow)
        
        # Predizer
        prediction = self.model.predict([features])[0]
        
        # Confiança
        try:
            proba = self.model.predict_proba([features])[0]
            confidence = max(proba)
        except:
            confidence = 0.9
        
        return prediction == 1, confidence, []


def test_with_real_model():
    """Testa com modelo real."""
    print("="*60)
    print("🧪 TESTE COM MODELO REAL")
    print("="*60)
    
    # Verificar se os artefatos existem
    if not os.path.exists('./models/decision_tree_model.pkl'):
        print("\n⚠️ Modelo não encontrado!")
        print("   Execute primeiro o script save_artifacts.py")
        print("   ou coloque os artefatos na pasta ./models")
        print("\n   Para teste rápido, execute test_simple.py")
        return
    
    # 1. Inicializar predictor
    print("\n1. Inicializando predictor...")
    predictor = RealModelPredictor()
    if not predictor.load_artifacts():
        print("   ❌ Falha ao carregar modelo")
        return
    print("   ✅ Predictor pronto!")
    
    # 2. Simular fluxos
    print("\n2. Simulando fluxos...")
    flows = simulate_flows(num_flows=100, attack_rate=0.3)
    print(f"   ✅ {len(flows)} fluxos simulados")
    
    # 3. Processar fluxos
    print("\n3. Processando fluxos...")
    correct = 0
    total = 0
    predictions = []
    
    for flow in flows:
        try:
            is_attack, confidence, reasons = predictor.predict(flow)
            total += 1
            
            expected = flow.is_attack
            if is_attack == expected:
                correct += 1
            
            predictions.append({
                'flow': flow,
                'predicted': is_attack,
                'expected': expected,
                'confidence': confidence
            })
        except Exception as e:
            print(f"   ❌ Erro: {e}")
    
    # 4. Resultados
    print("\n4. Resultados:")
    accuracy = correct/total if total > 0 else 0
    print(f"   Total processados: {total}")
    print(f"   Corretos: {correct}")
    print(f"   Acurácia: {accuracy:.2%}")
    
    # Matriz de confusão manual
    tp = sum(1 for p in predictions if p['predicted'] and p['expected'])
    fp = sum(1 for p in predictions if p['predicted'] and not p['expected'])
    tn = sum(1 for p in predictions if not p['predicted'] and not p['expected'])
    fn = sum(1 for p in predictions if not p['predicted'] and p['expected'])
    
    print("\n5. Matriz de Confusão:")
    print(f"   VP: {tp}  |  FP: {fp}")
    print(f"   FN: {fn}  |  VN: {tn}")
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n   Precisão: {precision:.2%}")
    print(f"   Recall: {recall:.2%}")
    print(f"   F1-Score: {f1:.2%}")
    
    # 6. Exemplos
    print("\n6. Exemplos de classificação:")
    for i, p in enumerate(predictions[:10]):
        status = "🚨 ATAQUE" if p['predicted'] else "✅ NORMAL"
        expected = " (✓)" if p['predicted'] == p['expected'] else " (✗)"
        flow = p['flow']
        print(f"   {i+1}. {status} {expected} | Conf: {p['confidence']:.2%}")
        print(f"      {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} ({flow.service})")
    
    print("\n" + "="*60)
    print("✅ TESTE CONCLUÍDO!")
    print("="*60)


if __name__ == "__main__":
    test_with_real_model()