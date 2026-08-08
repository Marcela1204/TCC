# tests/test_simple.py
"""
Teste mais simples possível para validar o pipeline.
Não precisa de modelo treinado - usa regras simples.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import random
from src.core.feature_extractor import FeatureExtractor, NetworkFlow
from scripts.simulate_attack import simulate_flows


class SimpleDetector:
    """Detector baseado em regras para teste."""
    
    def predict(self, flow: NetworkFlow) -> tuple:
        """Regras simples para classificar ataques."""
        score = 0
        reasons = []
        
        # 1. Muitas conexões rejeitadas
        if flow.flag == 'REJ':
            score += 2
            reasons.append("Conexão rejeitada (RST)")
        
        # 2. SYN sem ACK
        if flow.flag == 'S0':
            score += 1
            reasons.append("SYN sem ACK - possível scan")
        
        # 3. Muitas tentativas de login
        if flow.num_failed_logins > 5:
            score += 2
            reasons.append(f"Muitas tentativas de login ({flow.num_failed_logins})")
        
        # 4. Root shell
        if flow.root_shell == 1:
            score += 3
            reasons.append("Root shell acessado!")
        
        # 5. Conexão muito curta (DoS)
        if flow.duration < 0.1 and flow.src_bytes == 0:
            score += 1
            reasons.append("Conexão muito curta - possível DoS")
        
        # 6. Muitas conexões para o mesmo destino
        if flow.count > 50:
            score += 1
            reasons.append(f"Muitas conexões para o destino ({flow.count})")
        
        # Decisão
        is_attack = score >= 3
        confidence = min(score / 5, 0.95)
        
        return is_attack, confidence, reasons


def test_pipeline():
    """Testa o pipeline completo com o detector simples."""
    print("="*60)
    print("🧪 TESTE DO PIPELINE COM DETECTOR SIMPLES")
    print("="*60)
    
    # 1. Inicializar extrator
    print("\n1. Inicializando FeatureExtractor...")
    extractor = FeatureExtractor()
    extractor.load_artifacts()
    print("   ✅ FeatureExtractor pronto!")
    
    # 2. Criar detector simples
    detector = SimpleDetector()
    print("   ✅ Detector simples pronto!")
    
    # 3. Simular fluxos
    print("\n2. Simulando fluxos...")
    flows = simulate_flows(num_flows=50, attack_rate=0.3)
    print(f"   ✅ {len(flows)} fluxos simulados")
    
    # 4. Processar fluxos
    print("\n3. Processando fluxos...")
    results = []
    correct = 0
    total = 0
    
    for flow in flows:
        # Extrair features (verifica se o extrator funciona)
        try:
            features = extractor.extract_features(flow)
            total += 1
        except Exception as e:
            print(f"   ❌ Erro na extração: {e}")
            continue
        
        # Classificar
        is_attack, confidence, reasons = detector.predict(flow)
        
        # Comparar com ground truth
        expected = flow.is_attack
        if is_attack == expected:
            correct += 1
        
        results.append({
            'flow': flow,
            'predicted': is_attack,
            'expected': expected,
            'confidence': confidence,
            'reasons': reasons
        })
    
    # 5. Resultados
    print("\n4. Resultados:")
    print(f"   Total processados: {total}")
    print(f"   Corretos: {correct}")
    print(f"   Acurácia: {correct/total:.2%}")
    
    # Mostrar alguns exemplos
    print("\n5. Exemplos de classificação:")
    for i, result in enumerate(results[:5]):
        status = "🚨 ATAQUE" if result['predicted'] else "✅ NORMAL"
        expected = " (✓)" if result['predicted'] == result['expected'] else " (✗)"
        print(f"   {i+1}. {status} {expected} | Conf: {result['confidence']:.2%}")
        print(f"      Razões: {', '.join(result['reasons'])}")
    
    print("\n" + "="*60)
    print("✅ TESTE CONCLUÍDO!")
    print("="*60)


if __name__ == "__main__":
    test_pipeline()