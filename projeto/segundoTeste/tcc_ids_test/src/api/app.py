# src/api/app.py
import os
import sys

# Adiciona a pasta raiz do projeto (tcc_ids_test) ao sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.core.ids_predictor import IDSPredictor

"""
API REST e Dashboard para o IDS
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import json
from datetime import datetime
import logging

from src.core.ids_predictor import IDSPredictor
from src.core.packet_capture import PacketCapture

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Inicializar IDS
ids = IDSPredictor()
ids.initialize()

# Inicializar captura
capture = PacketCapture(callback=ids.predict)

# Estado do sistema
system_state = {
    'is_running': False,
    'alerts': [],
    'predictions': []
}


@app.route('/')
def index():
    """Dashboard principal."""
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Retorna status do sistema."""
    stats = ids.get_stats()
    return jsonify({
        'status': 'running' if system_state['is_running'] else 'stopped',
        'stats': stats,
        'alerts_count': len(system_state['alerts']),
        'recent_alerts': system_state['alerts'][-10:]
    })


@app.route('/api/start', methods=['POST'])
def start_capture():
    """Inicia captura de pacotes."""
    if not system_state['is_running']:
        interface = request.json.get('interface', 'eth0')
        system_state['is_running'] = True
        
        # Iniciar em thread separada
        threading.Thread(
            target=capture.start,
            args=(interface,),
            daemon=True
        ).start()
        
        logger.info(f"✅ Captura iniciada na interface {interface}")
        return jsonify({'status': 'started', 'interface': interface})
    
    return jsonify({'status': 'already_running'})


@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Para captura de pacotes."""
    if system_state['is_running']:
        capture.stop()
        system_state['is_running'] = False
        logger.info("⏹️ Captura parada")
        return jsonify({'status': 'stopped'})
    
    return jsonify({'status': 'already_stopped'})


@app.route('/api/alerts')
def get_alerts():
    """Retorna alertas."""
    return jsonify(system_state['alerts'])


@app.route('/api/stats')
def get_stats():
    """Retorna estatísticas detalhadas."""
    return jsonify(ids.get_stats())


@socketio.on('connect')
def handle_connect():
    """Cliente conectado."""
    logger.info("🔗 Cliente conectado")
    emit('status', system_state)


@socketio.on('disconnect')
def handle_disconnect():
    """Cliente desconectado."""
    logger.info("🔌 Cliente desconectado")


def send_alert(alert_data):
    """Envia alerta via WebSocket."""
    socketio.emit('new_alert', alert_data)
    system_state['alerts'].append(alert_data)


# Adicione este código no app.py, antes do if __name__ == '__main__':

@app.route('/api/predict', methods=['POST'])
def predict_flow():
    """Endpoint para predizer um fluxo"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Criar um NetworkFlow a partir dos dados
        from src.core.feature_extractor import NetworkFlow
        flow = NetworkFlow(
            src_ip=data.get('src_ip', '0.0.0.0'),
            dst_ip=data.get('dst_ip', '0.0.0.0'),
            src_port=data.get('src_port', 0),
            dst_port=data.get('dst_port', 0),
            protocol_type=data.get('protocol', 'tcp'),
            duration=data.get('duration', 1.0),
            src_bytes=data.get('src_bytes', 0),
            dst_bytes=data.get('dst_bytes', 0),
            flag=data.get('flag', 'SF'),
            service=data.get('service', 'http'),
            count=data.get('count', 1),
            srv_count=data.get('srv_count', 1),
            serror_rate=data.get('serror_rate', 0.0),
            srv_serror_rate=data.get('srv_serror_rate', 0.0),
            rerror_rate=data.get('rerror_rate', 0.0),
            srv_rerror_rate=data.get('srv_rerror_rate', 0.0),
            same_srv_rate=data.get('same_srv_rate', 1.0),
            diff_srv_rate=data.get('diff_srv_rate', 0.0),
            dst_host_count=data.get('dst_host_count', 1),
            dst_host_srv_count=data.get('dst_host_srv_count', 1),
            dst_host_same_srv_rate=data.get('dst_host_same_srv_rate', 1.0),
            dst_host_diff_srv_rate=data.get('dst_host_diff_srv_rate', 0.0),
            dst_host_serror_rate=data.get('dst_host_serror_rate', 0.0),
            num_failed_logins=data.get('num_failed_logins', 0),
            logged_in=data.get('logged_in', 1),
            root_shell=data.get('root_shell', 0)
        )
        
        # Predizer
        prediction, confidence, alert = ids.predict(flow)
        
        return jsonify({
            'prediction': prediction,
            'confidence': confidence,
            'alert': alert,
            'message': '🚨 ATAQUE DETECTADO!' if prediction == 1 else '✅ Tráfego normal'
        })
        
    except Exception as e:
        logger.error(f"Erro na predição: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)