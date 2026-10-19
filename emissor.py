#!/usr/bin/env python3
"""
Emissor UDP Broadcast - Desafio de mensagens em rede

Envia uma frase por minuto (do arquivo frases.txt) para o endereço de
broadcast da rede, na porta 80, repetindo o conjunto em loop.

Uso básico:
    python emissor.py                          (detecta o broadcast sozinho, assumindo /24)
    python emissor.py --broadcast 192.168.1.255
    python emissor.py --intervalo 5            (teste rápido: 1 frase a cada 5 s)
"""
import argparse
import socket
import sys
import time
from datetime import datetime

PORTA = 80


def descobrir_ip_local():
    """Descobre o IP local da máquina (não envia nenhum pacote de verdade)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def broadcast_automatico():
    """Chuta o broadcast assumindo máscara /24 (ex.: 192.168.1.50 -> 192.168.1.255).
    Se a rede do laboratório for diferente, passe --broadcast manualmente."""
    ip = descobrir_ip_local()
    if ip is None:
        return "255.255.255.255"
    return ip.rsplit(".", 1)[0] + ".255"


def carregar_frases(caminho):
    with open(caminho, encoding="utf-8") as f:
        frases = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not frases:
        sys.exit(f"Nenhuma frase encontrada em {caminho}.")
    if not 10 <= len(frases) <= 20:
        print(f"[aviso] O guia pede de 10 a 20 frases; você tem {len(frases)}.")
    return frases


def main():
    p = argparse.ArgumentParser(description="Emissor UDP broadcast")
    p.add_argument("--broadcast", default=None,
                   help="endereço de broadcast (ex.: 192.168.1.255). Padrão: detecta /24")
    p.add_argument("--porta", type=int, default=PORTA, help="porta UDP (padrão 80)")
    p.add_argument("--frases", default="frases.txt", help="arquivo com as frases")
    p.add_argument("--intervalo", type=float, default=60,
                   help="segundos entre frases (padrão 60)")
    args = p.parse_args()

    destino = args.broadcast or broadcast_automatico()
    frases = carregar_frases(args.frases)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print(f"Enviando {len(frases)} frases para {destino}:{args.porta} "
          f"(1 a cada {args.intervalo:g}s). Ctrl+C para parar.")

    i = 0
    try:
        while True:
            frase = frases[i % len(frases)]
            try:
                sock.sendto(frase.encode("utf-8"), (destino, args.porta))
                print(f"[{datetime.now():%H:%M:%S}] enviada ({i % len(frases) + 1}/{len(frases)}): {frase}")
            except OSError as e:
                print(f"[erro] não consegui enviar: {e}")
            i += 1
            time.sleep(args.intervalo)
    except KeyboardInterrupt:
        print("\nEmissor encerrado.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
