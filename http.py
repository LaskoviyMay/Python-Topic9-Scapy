from scapy.all import *
import random
import sys

# Получаем аргументы командной строки
dest = sys.argv[1]

try:
    if sys.argv[2]:
        getStr = sys.argv[2]
except IndexError:
    getStr = 'GET / HTTP/1.1\r\nHost:' + dest + '\r\nAccept-Encoding: gzip, deflate\r\n\r\n'

try:
    if sys.argv[3]:
        max_requests = int(sys.argv[3])
except IndexError:
    max_requests = 10

counter = 0

while counter < max_requests:
    # SEND SYN
    syn = IP(dst=dest) / TCP(sport=random.randint(1025, 65500), dport=80, flags='S')
    
    # GET SYN-ACK
    syn_ack = sr1(syn, timeout=2)
    if syn_ack is None:
        print("No SYN-ACK received. Exiting.")
        sys.exit(1)
    
    # Send ACK
    out_ack = send(IP(dst=dest) / TCP(dport=80, sport=syn_ack[TCP].sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A'))
    
    # Send the HTTP GET
    http_response = sr1(IP(dst=dest) / TCP(dport=80, sport=syn_ack[TCP].sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='PA') / getStr, timeout=2)
    
    if http_response:
        print("HTTP Response received:")
        http_response.show()
    else:
        print("No HTTP response received.")
    
    counter += 1