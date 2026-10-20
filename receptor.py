"""Receptor UDP: mostra as frases recebidas e salva em capturas.csv."""
import argparse
import csv
import socket
from datetime import datetime

p = argparse.ArgumentParser()
p.add_argument("--porta", type=int, default=80)
args = p.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind(("", args.porta))
except PermissionError:
    raise SystemExit(f"Sem permissão para usar a porta {args.porta}. Rode como administrador/sudo.")
except OSError as e:
    raise SystemExit(f"Não consegui abrir a porta {args.porta} (já está em uso?): {e}")

print(f"Escutando na porta {args.porta}. Ctrl+C para parar.")
with open("capturas.csv", "a", newline="", encoding="utf-8") as f:
    arquivo = csv.writer(f)
    try:
        while True:
            dados, (ip, _) = sock.recvfrom(65535)
            frase = dados.decode("utf-8", errors="replace").strip()
            hora = datetime.now().strftime("%H:%M:%S")
            print(f"[{hora}] {ip} -> {frase}")
            arquivo.writerow([hora, ip, frase])
            f.flush()
    except KeyboardInterrupt:
        pass