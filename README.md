# NeuroGuard

Инструмент по обнаружению уязвимостей в сети приложения

![image](https://github.com/user-attachments/assets/52cead56-d4ef-457b-9d3f-ef2f11f43e9e)

# Установка

1. Склонируйте репозитории

```
git clone https://github.com/RizoBoy/NeuroGuard
cd NeuroGuard
```

2. Скачайте установщик пакетов PIP

```
Следуйте инструкции на сайте https://pip.pypa.io/en/stable/installation/
```

3. Установите библиотеки

```
pip install scapy torch scikit-learn requests pandas pyfiglet pyyaml subprocess
```

4. Настройте `config.yaml`

```yaml
models:
  lstm: true            # Useful for specific attacks
  cnn: false            # Useful for specific attacks less resource intensive
  random_forest: true   # Useful for UDP-Flood 
  k_means: false        # Useful for DNS-Amplification

network_filters:
  net_adapter: "eth0"
  ports: [22, 80, 443]
  protocol: "Both"  # TCP, UDP, Both
  minimum_traffic_speed: 100.0  # Mbps
  minimum_packets: 50

notifications:
  discord_webhook: "https://discord.com/api/webhooks/1037300794409627698"
  telegram_token: "123456789:ABCDefGHIJKLMNOPQrstuvwxYZ" #Example
  telegrams_to_send:
    - "@channel1"
    - "@user2"
  email_smtp_server: ""
  email_smtp_port: 587
  email_username: ""
  email_password: ""
  email_recipient: ""
  emails_to_send:
    - "admin@example.com"
    - "security@example.org"
```

5. Запустите программу командой `py app.py` или `python3 app.py`

```
Для завершения работы нажмите комбинацию Ctrl+C
```

# Проверка работы программы

1. Установите в конфигах минимальную требуемую скорость трафика на 1 мбит/с или минимальное кол-во пакетов на 1.
2. Установите любой способ отправки уведомлении (Discord, Telegram, Email).
3. Как только запустите программу к вам сразу должно прийти уведомление со статистикой.

Пример статистики:
![image](https://github.com/user-attachments/assets/e19676ed-b347-4535-945b-030268647462)

