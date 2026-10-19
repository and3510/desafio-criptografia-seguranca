#!/usr/bin/env python3
"""
Receptor UDP Broadcast - Desafio de mensagens em rede

Escuta a porta 80 e registra toda frase recebida (horário, IP de origem, texto)
na tela e no arquivo capturas.csv. Ao pressionar Ctrl+C mostra um resumo
agrupado por IP, para facilitar relacionar cada origem a uma empresa/serviço.

No Linux/macOS, a porta 80 exige privilégio:  sudo python3 receptor.py
No Windows, rode o terminal como Administrador e libere o Python no firewall.

Uso:
    python receptor.py
    python receptor.py --incluir-proprio    (mostra também o que você mesmo enviou)
    python receptor.py --porta 5000         (para testes sem privilégio)
"""
import argparse
import csv
import os
import socket
from collections import defaultdict
from datetime import datetime

PORTA = 80


def ips_locais():
    """IPs desta máquina, para ignorar o que nós mesmos enviamos."""
    ips = {"127.0.0.1"}
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
    except OSError:
        pass
    finally:
        s.close()
    return ips


def main():
    p = argparse.ArgumentParser(description="Receptor UDP broadcast")
    p.add_argument("--porta", type=int, default=PORTA, help="porta UDP (padrão 80)")
    p.add_argument("--saida", default="capturas.csv", help="arquivo CSV de saída")
    p.add_argument("--incluir-proprio", action="store_true",
                   help="não ignorar pacotes vindos deste computador")
    args = p.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    try:
        sock.bind(("", args.porta))
    except PermissionError:
        raise SystemExit(f"Sem permissão para usar a porta {args.porta}. "
                         "Rode como administrador/sudo.")
    except OSError as e:
        raise SystemExit(f"Não consegui abrir a porta {args.porta}: {e}")

    meus_ips = set() if args.incluir_proprio else ips_locais()
    novo_arquivo = not os.path.exists(args.saida)
    por_ip = defaultdict(list)       # ip -> frases distintas, na ordem em que chegaram
    vistos = set()                   # (ip, frase) já registrados

    print(f"Escutando UDP na porta {args.porta}. Ctrl+C para encerrar.")
    if meus_ips:
        print(f"Ignorando pacotes dos IPs locais: {', '.join(sorted(meus_ips))}")

    with open(args.saida, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if novo_arquivo:
            w.writerow(["horario", "ip_origem", "frase"])
        try:
            while True:
                dados, (ip, _porta) = sock.recvfrom(65535)
                if ip in meus_ips:
                    continue
                frase = dados.decode("utf-8", errors="replace").strip()
                agora = datetime.now().strftime("%H:%M:%S")
                repetida = (ip, frase) in vistos
                if not repetida:
                    vistos.add((ip, frase))
                    por_ip[ip].append(frase)
                    w.writerow([agora, ip, frase])
                    f.flush()
                marca = "  (repetida)" if repetida else ""
                print(f"[{agora}] {ip:<15} -> {frase}{marca}")
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

    print("\n=== Resumo por origem ===")
    if not por_ip:
        print("Nenhuma mensagem capturada.")
    for ip, frases in sorted(por_ip.items()):
        print(f"\n{ip}  ({len(frases)} frases distintas)")
        for fr in frases:
            print(f"  - {fr}")
    print(f"\nTudo salvo em {args.saida}")


if __name__ == "__main__":
    main()
