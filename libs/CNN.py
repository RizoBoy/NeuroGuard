import torch
import torch.nn as nn
import torch.nn.functional as F

class TrafficCNN(nn.Module):
    def __init__(self, input_channels=1, features_count=10):
        super(TrafficCNN, self).__init__()
        self.conv1 = nn.Conv1d(input_channels, 16, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(16, 32, kernel_size=3, padding=1)
        self.pool = nn.MaxPool1d(2)
        self.fc1 = nn.Linear(32 * (features_count // 4), 64) 
        self.fc2 = nn.Linear(64, 1) 

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = self.pool(x)
        x = F.relu(self.conv2(x))
        x = self.pool(x)
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        x = torch.sigmoid(self.fc2(x))
        return x

def init_cnn_model(features_count=10, device="cpu"):
    model = TrafficCNN(input_channels=1, features_count=features_count)
    model.to(device)
    model.eval() 
    return model

def predict_cnn(model, packet_features, device="cpu"):
    """
    packet_features: np.array или список признаков (features_count,)
    """
    if isinstance(packet_features, list):
        packet_features = torch.tensor(packet_features, dtype=torch.float32).unsqueeze(0).unsqueeze(0).to(device)
    elif isinstance(packet_features, np.ndarray):
        packet_features = torch.tensor(packet_features, dtype=torch.float32).unsqueeze(0).unsqueeze(0).to(device)
    else:
        raise ValueError("Неподдерживаемый формат входных данных")

    with torch.no_grad():
        output = model(packet_features).item()
    return output 
