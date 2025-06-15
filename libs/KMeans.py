from sklearn.cluster import KMeans

class TrafficKMeans:
    def __init__(self, n_clusters=2):
        self.model = KMeans(n_clusters=n_clusters, random_state=42)

    def fit(self, X):
        self.model.fit(X)

    def predict(self, packet_features):
        if isinstance(packet_features, list):
            packet_features = np.array(packet_features).reshape(1, -1)
        return int(self.model.predict(packet_features)[0])
