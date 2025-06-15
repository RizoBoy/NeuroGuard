from scapy.all import sniff, IP, TCP, UDP
import time
import yaml
import subprocess

import torch
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

from libs import CNN
from libs import KMeans
from libs import LSTM
from libs import RandomForest

class TrafficCapture:
    def __init__(self, interface="eth0", packet_limit=100):
        self.interface = interface
        self.packet_limit = packet_limit
        self.captured_packets = []
        self.running = False

    def packet_callback(self, packet):
        if IP in packet:
            data = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'proto': packet[IP].proto,
                'len': len(packet),
                'src_port': packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
                'dst_port': packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
            }
            self.captured_packets.append(data)

    def start_capture(self):
        print(f"[INFO] Начинаем захват трафика на интерфейсе {self.interface}")
        self.running = True
        sniff(iface=self.interface, prn=self.packet_callback, store=False, count=self.packet_limit)
        print(f"[INFO] Захват завершен. Количество пакетов: {len(self.captured_packets)}")
        return self.captured_packets

    def stop_capture(self):
        print("[INFO] Захват трафика остановлен.")
        self.running = False

    def get_packets(self):
        """Возвращает все захваченные пакеты в виде списка словарей"""
        return self.captured_packets

class Preprocessor:
    def __init__(self, filters=None):
        self.filters = filters or {}

    def packet_passes_filter(self, packet):
        for key, allowed_values in self.filters.items():
            if packet.get(key) not in allowed_values:
                return False
        return True

    def process_packet(self, packet):
        if not self.packet_passes_filter(packet):
            return None

        features = {
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'proto': packet['proto'],
            'len': packet['len'],
            'src_port': packet['src_port'],
            'dst_port': packet['dst_port'],
            'timestamp': packet['timestamp']
        }
        return features

    def process_batch(self, packets):
        processed = []
        for pkt in packets:
            result = self.process_packet(pkt)
            if result:
                processed.append(result)
        return processed

class DummyNN(torch.nn.Module):
    def __init__(self):
        super(DummyNN, self).__init__()
        self.fc = torch.nn.Linear(1, 1)
    def forward(self, x):
        return torch.sigmoid(self.fc(x))

class TrafficAnalyzer:
    def __init__(self, cnn_model=None, lstm_model=None, rf_model=None, kmeans_model=None):
        self.cnn_model = cnn_model
        self.lstm_model = lstm_model
        self.rf_model = rf_model
        self.kmeans_model = kmeans_model

    def analyze_packet(self, packet_features, sequence_features=None):
        results = {}
        if self.cnn_model:
            results['cnn'] = predict_cnn(self.cnn_model, packet_features)
        if self.lstm_model and sequence_features is not None:
            results['lstm'] = predict_lstm(self.lstm_model, sequence_features)
        else:
            results['lstm'] = None
        if self.rf_model:
            results['rf_class'] = self.rf_model.predict(packet_features)
            results['rf_prob'] = self.rf_model.predict_proba(packet_features)
        if self.kmeans_model:
            results['kmeans_cluster'] = self.kmeans_model.predict([packet_features])[0]

        return results


import smtplib
import requests

class Notifier:
    def __init__(self, email_config=None, telegram_config=None):
        self.email_config = email_config or {}
        self.telegram_config = telegram_config or {}

    def send_email(self, subject, body):
        try:
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            message = f"Subject: {subject}\n\n{body}"
            server.sendmail(self.email_config['username'], self.email_config['recipient'], message)
            server.quit()
            print("[INFO] Email-уведомление отправлено.")
        except Exception as e:
            print(f"[ERROR] Не удалось отправить email: {e}")

    def send_telegram(self, message):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_config['token']}/sendMessage"
            data = {"chat_id": self.telegram_config['chat_id'], "text": message}
            response = requests.post(url, data=data)
            if response.status_code == 200:
                print("[INFO] Telegram-уведомление отправлено.")
            else:
                print(f"[ERROR] Telegram ошибка: {response.text}")
        except Exception as e:
            print(f"[ERROR] Не удалось отправить сообщение в Telegram: {e}")

    def notify(self, subject, message):
        if self.email_config:
            self.send_email(subject, message)
        if self.telegram_config:
            self.send_telegram(message)


import pandas as pd
import json
import datetime

class Logger:
    def __init__(self, log_file="network_log.csv", json_file="network_log.json"):
        self.log_file = log_file
        self.json_file = json_file
        self.events = []

    def log_event(self, event_data):
        timestamp = datetime.datetime.now().isoformat()
        event_data['timestamp'] = timestamp
        self.events.append(event_data)
        print(f"[INFO] Событие записано: {event_data}")

        try:
            df = pd.DataFrame([event_data])
            with open(self.log_file, 'a', encoding='utf-8', newline='') as f:
                df.to_csv(f, header=f.tell() == 0, index=False)
        except Exception as e:
            print(f"[ERROR] Ошибка записи в CSV: {e}")

        try:
            with open(self.json_file, 'a', encoding='utf-8') as f:
                json.dump(event_data, f)
                f.write("\n")
        except Exception as e:
            print(f"[ERROR] Ошибка записи в JSON: {e}")

    def generate_report(self):
        try:
            df = pd.read_csv(self.log_file)
            print("[INFO] Отчет по событиям:")
            print(df.groupby("rf_class").size().rename("Количество событий"))
        except Exception as e:
            print(f"[ERROR] Не удалось сгенерировать отчет: {e}")


import time

class TrafficMonitorApp:
    def __init__(self, capture, preprocessor, analyzer, notifier, logger):
        self.capture = capture
        self.preprocessor = preprocessor
        self.analyzer = analyzer
        self.notifier = notifier
        self.logger = logger
        self.running = False

    def run(self):
        self.running = True
        print("[INFO] Система запущена.")

        while self.running:
            packets = self.capture.get_packets()

            for packet in packets:
                processed = self.preprocessor.process_packet(packet)
                if not processed:
                    continue

                sequence = [processed for _ in range(5)] 

                results = self.analyzer.analyze_packet(
                    packet_features=list(processed.values())[1:], 
                    sequence_features=sequence
                )

                alert_triggered = (
                    (results.get('rf_class', 0) == 1) or
                    (results.get('cnn', 0) > 0.7) or
                    (results.get('isolation', 1) == -1)
                )

                if alert_triggered:
                    message = f"Аномалия обнаружена! IP: {processed['src_ip']} -> {processed['dst_ip']}"
                    self.notifier.notify("Аномалия в трафике", message)

                log_data = {**processed, **results}
                self.logger.log_event(log_data)

            time.sleep(5)

    def stop(self):
        self.running = False
        print("[INFO] Система остановлена.")

def load_config(path: str = "config.yaml") -> dict:
    with open(path, 'r') as file:
        return yaml.safe_load(file)

def main():
    import torch
    import numpy as np
    import pyfiglet

    print(pyfiglet.figlet_format("NeuroGuard"))

    config = load_config()
    models = config.get("models", {})
    nf = config.get("network_filters", {})
    notif = config.get("notifications", {})

    subprocess.run(f'bash .\ddoswarningbandwidth.sh {notif.get("discord_webhook")} {nf.get("net_adapter")} {nf.get("minimum_traffic_speed")} {nf.get("minimum_packets")}', shell=True)

    capture = TrafficCapture(interface="eth0", packet_limit=1000)

    filters = {'proto': [6], 'dst_port': nf.get('ports')}
    preprocessor = Preprocessor(filters=filters)

    if models.get("cnn"):
        cnn_model = CNN.init_cnn_model(features_count=10)
        cnn_model.load_state_dict(torch.load("cnn_model.pth", map_location=torch.device('cpu')))
        cnn_model.eval()

    if models.get("lstm"):
        lstm_model = LSTM.__init__(input_size=10)
        lstm_model.load_state_dict(torch.load("lstm_model.pth", map_location=torch.device('cpu')))
        lstm_model.eval
    
    X_train = np.random.rand(100, 10)
    y_train = np.random.randint(0, 2, 100)

    if models.get("random_forest"):
        rf_model = TrafficRandomForest()
        rf_model.train(X_train, y_train)

    if models.get("k_means"):
        kmeans_model = TrafficKMeans(n_clusters=2)
        kmeans_model.fit(X_train)

    analyzer = TrafficAnalyzer(
        cnn_model=cnn_model,
        lstm_model=lstm_model,
        rf_model=rf_model,
        kmeans_model=kmeans_model
    )

    email_conf = {
        'smtp_server': notif.get("email_smtp_server"),
        'smtp_port': notif.get("email_smtp_port"),
        'username': notif.get("email_username"),
        'password': notif.get("email_password"),
        'recipient': notif.get("email_recipient")
    }

    telegram_conf = {
        'token': notif.get("email_smttelegram_tokenp_server"),
        'chat_id': notif.get("telegrams_to_send")
    }

    notifier = Notifier(email_config=email_conf, telegram_config=telegram_conf)

    logger = Logger(log_file="network_log.csv", json_file="network_log.json")

    app = TrafficMonitorApp(
        capture=capture,
        preprocessor=preprocessor,
        analyzer=analyzer,
        notifier=notifier,
        logger=logger
    )

    try:
        app.run()
    except KeyboardInterrupt:
        app.stop()
        print("[INFO] Мониторинг остановлен пользователем.")

if __name__ == "__main__":
    main()