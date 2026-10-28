"""Sniffer UDP 80: mostra ao vivo as frases de todos os grupos e tenta descobrir quem é quem.

Captura com o tshark (vem com o Wireshark) e identifica cada grupo pelo MAC de origem,
que não muda mesmo se o grupo trocar de IP ou copiar frases dos outros.
Grava tudo em sniffer.csv e, a cada minuto, imprime um resumo por grupo.
"""
import argparse
import csv
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from datetime import date, datetime
from difflib import SequenceMatcher

p = argparse.ArgumentParser()
p.add_argument("--interface", default="Ethernet", help="placa de rede para o tshark (veja: tshark -D)")
p.add_argument("--porta", type=int, default=80)
p.add_argument("--resumo", type=int, default=60, help="segundos entre os resumos")
p.add_argument("--tshark", default=shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe")
args = p.parse_args()

ARQUIVO = "sniffer.csv"
CORES = ["\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[91m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[31m"]
CINZA, NEGRITO, FIM = "\033[90m", "\033[1m", "\033[0m"

# Palavras que puxam cada setor, como regex que casa no começo da palavra
# (termine com \b para casar só a palavra inteira). Uma frase pode cair em mais de um setor.
SETORES = {
    "refrigeração": ["geladeira", "freezer", "camara fria", "camaras frias", "refrigera", "compressor", "congela", "gelo", "frigorific", "temperatura"],
    "gestão financeira": ["planilha", "relatorio", "despesa", "fluxo de caixa", "orcamento", "contabil", "balanco", "margem", "gestao", "erp", "fechar o mes", "notas fiscais"],
    "jogos": ["jogo", "game", "fase", "boss", "level", "nivel", "personagem", "jogador", "download", "console", "lancamento", "gamer"],
    "conforto": ["sofa", "colchao", "travesseiro", "poltrona", "relaxa", "conforto", r"cama\b","aconchego", "movei", "a vontade"],
    "telecom": ["internet", "sinal", "antena", "fibra", "chip", "recarga", "cobertura", "wi-fi", "wifi", "operadora", "5g", "banda larga", "cabo", "cable", "dispersao", "estacao radio base", "torre"],
    "finanças": ["cartao", "credito", "emprestimo", "juros", "parcela", "investi", "rendimento", "poupanca", "banco", "pix", "tarifa", "saque", "abrir conta"],
    "construção": ["obra", "cimento", "tijolo", "laje", "fundacao", "engenheir", "parede", "reforma", "concreto", "terreno", "construi"],
    "infra/TI": ["sla", "uptime", "ddos", "servidor", "nuvem", "data center", "protocolo", "handshake", "firewall", "backup", "pacote"],
    "saúde": ["consulta", "exame", "internacao", "ansiedade", "terapia", "sessao", "medic", "saude"],
    "academia": ["treino", "proteina", "academia", "dia de peito", "suor", "musculo", "dieta"],
    "comida": ["fome", "restaurante", "cardapio", "delivery", "quentinho", "lanche"],
}


def normaliza(texto):
    texto = unicodedata.normalize("NFD", texto.lower())
    return "".join(c for c in texto if unicodedata.category(c) != "Mn")


def setores_da_frase(frase):
    t = normaliza(frase)
    return [s for s, palavras in SETORES.items() if any(re.search(r"\b" + w, t) for w in palavras)]


def meu_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


class Grupo:
    def __init__(self, mac):
        self.mac = mac
        self.ips, self.ttls, self.portas = Counter(), Counter(), Counter()
        self.frases = []  # (hora, frase)
        self.cor = CORES[len(grupos) % len(CORES)]

    def unicas(self):
        return list(dict.fromkeys(f for _, f in self.frases))

    def ciclo_completo(self):
        vistas = [f for _, f in self.frases]
        return len(vistas) > len(set(vistas))

    def por_minuto(self):
        if len(self.frases) < 2:
            return 0.0
        minutos = (self.frases[-1][0] - self.frases[0][0]) / 60
        return (len(self.frases) - 1) / minutos if minutos else float("inf")


grupos = {}
dono_da_frase = {}  # frase normalizada -> MAC de quem mandou primeiro
eu = meu_ip()


def registra(epoch, mac, ip, porta, ttl, frase, mostrar=True):
    # linhas importadas do capturas.csv sem MAC ficam em "ip:<ip>"; quando o MAC real aparece, junta
    provisorio = grupos.pop(f"ip:{ip}", None) if not mac.startswith("ip:") else None
    if provisorio and mac not in grupos:
        provisorio.mac = mac
        grupos[mac] = provisorio
        for chave, dono in dono_da_frase.items():
            if dono == f"ip:{ip}":
                dono_da_frase[chave] = mac
    elif provisorio:
        grupos[mac].frases = sorted(provisorio.frases + grupos[mac].frases)
        grupos[mac].ips.update(provisorio.ips)
    g = grupos.get(mac) or grupos.setdefault(mac, Grupo(mac))
    g.ips[ip] += 1
    if ttl != "?":  # "?" = linha importada do capturas.csv, sem dados do pacote
        g.ttls[ttl] += 1
        g.portas[porta] += 1
    g.frases.append((epoch, frase))
    chave = normaliza(frase)
    dono_da_frase.setdefault(chave, mac)
    if mostrar:
        hora = datetime.fromtimestamp(epoch).strftime("%H:%M:%S")
        cor = CINZA if ip == eu else g.cor
        copia = "" if dono_da_frase[chave] == mac else f"  {NEGRITO}[cópia de {apelido(dono_da_frase[chave])}]{FIM}{cor}"
        print(f"{cor}[{hora}] {ip:<15} {mac[-8:]}  {frase}{copia}{FIM}", flush=True)


def apelido(mac):
    g = grupos[mac]
    return g.ips.most_common(1)[0][0] if g.ips else mac


def melhor_atribuicao(pontos):
    """Dá um setor diferente para cada grupo, maximizando a soma dos pontos."""
    macs = list(pontos)
    nomes = list(SETORES)
    memo = {}

    def busca(i, usados):
        if i == len(macs):
            return 0.0, []
        if (i, usados) in memo:
            return memo[(i, usados)]
        melhor = busca(i + 1, usados)
        melhor = (melhor[0], [None] + melhor[1])
        for j, setor in enumerate(nomes):
            if usados >> j & 1 or not pontos[macs[i]].get(setor):
                continue
            valor, resto = busca(i + 1, usados | 1 << j)
            valor += pontos[macs[i]][setor]
            if valor > melhor[0]:
                melhor = (valor, [setor] + resto)
        memo[(i, usados)] = melhor
        return melhor

    return dict(zip(macs, busca(0, 0)[1]))


def resumo():
    print(f"\n{NEGRITO}===== RESUMO {datetime.now():%H:%M:%S} — {len(grupos)} remetentes ====={FIM}")
    pontos = {}
    por_ip = defaultdict(set)
    for mac, g in grupos.items():
        for ip in g.ips:
            por_ip[ip].add(mac)
        votos = Counter()
        for frase in g.unicas():
            if dono_da_frase[normaliza(frase)] != mac:
                continue  # frase copiada de outro grupo não conta como pista
            ss = setores_da_frase(frase)
            for s in ss:
                votos[s] += 1 / len(ss)
        pontos[mac] = votos
    sugestao = melhor_atribuicao({m: v for m, v in pontos.items() if eu not in grupos[m].ips})

    for mac, g in sorted(grupos.items(), key=lambda kv: apelido(kv[0])):
        nos = eu in g.ips
        ttl = g.ttls.most_common(1)[0][0] if g.ttls else "?"
        so = {"128": "Windows", "64": "Linux/macOS"}.get(ttl, f"TTL {ttl}")
        avisos = []
        if len(g.ips) > 1:
            avisos.append(f"MESMA MÁQUINA usando {len(g.ips)} IPs")
        if g.por_minuto() > 1.5:
            avisos.append(f"FLOOD: {g.por_minuto():.1f} frases/min")
        if len(g.portas) > 2:
            avisos.append(f"{len(g.portas)} emissores diferentes")
        if re.fullmatch(r"[0-9a-f]{2}", mac[:2]) and int(mac[:2], 16) & 2:
            avisos.append("MAC aleatório")
        copiadas = sum(dono_da_frase[normaliza(f)] != mac for f in g.unicas())
        if copiadas:
            avisos.append(f"{copiadas} frases copiadas de outros")
        estado = "ciclo completo" if g.ciclo_completo() else "ciclo incompleto"
        top = ", ".join(f"{s} {v:.1f}" for s, v in pontos[mac].most_common(4)) or "sem palavras-chave"
        titulo = "NÓS" if nos else f"palpite: {sugestao.get(mac) or '?'}"
        print(f"{g.cor}{NEGRITO}{', '.join(g.ips)}{FIM}{g.cor}  [{mac}] {so} | {len(g.frases)} msgs, {len(g.unicas())} únicas, {estado} | {titulo}{FIM}")
        print(f"    setores: {top}")
        if avisos:
            print(f"    {NEGRITO}! {' | '.join(avisos)}{FIM}")
    for ip, macs in por_ip.items():
        if len(macs) > 1:
            print(f"{NEGRITO}! IP {ip} veio de {len(macs)} MACs diferentes: alguém está forjando esse IP{FIM}")
    print(flush=True)


def carrega_historico():
    if not os.path.exists(ARQUIVO):
        return 0
    n = 0
    with open(ARQUIVO, encoding="utf-8", newline="") as f:
        for epoch, mac, ip, porta, ttl, frase in csv.reader(f):
            if date.fromtimestamp(float(epoch)) == date.today():
                registra(float(epoch), mac, ip, porta, ttl, frase, mostrar=False)
                n += 1
    return n


os.system("")  # liga as cores ANSI no console do Windows
sys.stdout.reconfigure(encoding="utf-8")
if not os.path.exists(args.tshark):
    raise SystemExit("tshark não encontrado. Instale o Wireshark ou passe --tshark com o caminho.")

print(f"Histórico de hoje carregado: {carrega_historico()} frases.")
resumo()
cmd = [args.tshark, "-i", args.interface, "-l", "-f", f"udp dst port {args.porta}", "-T", "fields", "-E", "separator=\t",
       "-e", "frame.time_epoch", "-e", "eth.src", "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.ttl", "-e", "data.data"]
tshark = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
print(f"Capturando UDP {args.porta} em '{args.interface}'. Ctrl+C para parar.\n", flush=True)

proximo = time.time() + args.resumo
with open(ARQUIVO, "a", newline="", encoding="utf-8") as f:
    gravador = csv.writer(f)
    try:
        for linha in tshark.stdout:
            campos = linha.rstrip("\n").split("\t")
            if len(campos) != 6 or not campos[5]:
                continue
            epoch, mac, ip, porta, ttl, dados = campos
            frase = bytes.fromhex(dados.replace(":", "")).decode("utf-8", errors="replace").strip()
            registra(float(epoch), mac, ip, porta, ttl, frase)
            gravador.writerow([epoch, mac, ip, porta, ttl, frase])
            f.flush()
            if time.time() >= proximo:
                resumo()
                proximo = time.time() + args.resumo
    except KeyboardInterrupt:
        pass
    finally:
        tshark.terminate()
        resumo()
