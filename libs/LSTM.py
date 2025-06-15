import torch
import torch.nn as nn

class TrafficLSTM(nn.Module):
    def __init__(self, input_size=10, hidden_size=32, num_layers=1, output_size=1):
        super(TrafficLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]  # Берём последний временной шаг
        out = self.fc(out)
        return self.sigmoid(out)
    
def predict_lstm(model, sequence_features, device="cpu"):
    if isinstance(sequence_features, list):
        sequence_features = torch.tensor(sequence_features, dtype=torch.float32).unsqueeze(0).to(device)
    elif isinstance(sequence_features, np.ndarray):
        sequence_features = torch.tensor(sequence_features, dtype=torch.float32).unsqueeze(0).to(device)
    else:
        raise ValueError("Неподдерживаемый формат входных данных")

    with torch.no_grad():
        output = model(sequence_features).item()
    return output
