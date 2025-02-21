from scapy.all import *

# IP-адрес и порт сервера
dst_ip = "https://google-gruyere.appspot.com/442892396391752271607384688243822732139/"
dst_port = 80

# Создаем TCP-соединение
ip_layer = IP(dst=dst_ip)
tcp_layer = TCP(dport=dst_port, flags="S")
packet = ip_layer / tcp_layer

# Отправляем пакет и получаем ответ
response = sr1(packet, timeout=2)

if response:
    print("Ответ получен:")
    response.show()
else:
    print("Нет ответа.")