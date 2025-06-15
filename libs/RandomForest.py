from sklearn.ensemble import RandomForestClassifier
import numpy as np

class TrafficRandomForest:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)

    def train(self, X_train, y_train):
        self.model.fit(X_train, y_train)

    def predict(self, packet_features):
        if isinstance(packet_features, list):
            packet_features = np.array(packet_features).reshape(1, -1)
        return int(self.model.predict(packet_features)[0])

    def predict_proba(self, packet_features):
        if isinstance(packet_features, list):
            packet_features = np.array(packet_features).reshape(1, -1)
        return self.model.predict_proba(packet_features)[0][1]  # Вероятность класса "атака"
