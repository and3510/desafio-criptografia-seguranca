"""Emissor UDP broadcast: envia uma frase do frases.txt por minuto, em loop."""
import argparse
import socket
import time

p = argparse.ArgumentParser()
p.add_argument("--broadcast", default="192.168.1.255", help="endereço de broadcast da rede")
p.add_argument("--porta", type=int, default=80)
p.add_argument("--intervalo", type=float, default=60, help="segundos entre frases")
args = p.parse_args()

with open("frases.txt", encoding="utf-8") as f:
    frases = [l.strip() for l in f if l.strip() and not l.startswith("#")]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print(f"Enviando para {args.broadcast}:{args.porta}. Ctrl+C para parar.")
try:
    while True:
        for frase in frases:
            try:
                sock.sendto(frase.encode("utf-8"), (args.broadcast, args.porta))
                print("enviada:", frase)
            except OSError as e:
                print("erro ao enviar (confira o endereço de broadcast e a rede):", e)
            time.sleep(args.intervalo)
except KeyboardInterrupt:
    pass