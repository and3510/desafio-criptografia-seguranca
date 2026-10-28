"""Sniffer UDP 80: captura as frases de todos os grupos e mostra um painel no navegador.

Identifica cada máquina pelo MAC de origem (captura com o tshark, que vem com o Wireshark),
avisa quando alguém forja um IP ou copia frases de outro grupo, e classifica cada frase como
pista do tema do próprio grupo, isca imitando o tema de outro grupo, ou neutra.

Uso: python sniffer.py   (o painel abre em http://localhost:8765)
"""
import argparse
import csv
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import unicodedata
import webbrowser
from collections import Counter, deque
from datetime import date, datetime
from difflib import SequenceMatcher
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

p = argparse.ArgumentParser()
p.add_argument("--interface", default="Ethernet", help="placa de rede para o tshark (veja: tshark -D)")
p.add_argument("--porta", type=int, default=80)
p.add_argument("--painel", type=int, default=8765, help="porta do painel no navegador")
p.add_argument("--tshark", default=shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe")
args = p.parse_args()

PASTA = os.path.dirname(os.path.abspath(__file__))
ARQUIVO = os.path.join(PASTA, "sniffer.csv")
CONFIRMADOS = os.path.join(PASTA, "sniffer_gabarito.json")

# Temas dos outros grupos da turma. Cada palavra é uma regex que casa no começo da palavra
# (termine com \b para casar só a palavra inteira). Uma frase pode cair em mais de um tema.
TEMAS = {
    "refrigeração": ["geladeira", "freezer", "camara fria", "camaras frias", "refrigera", "compressor", "congela", "gelo", "frigorific", "temperatura", "ar-condicionado"],
    "gestão de finanças": ["planilha", "relatorio", "despesa", "fluxo de caixa", "orcamento", "contabil", "balanco", "margem", "gestao", "erp", "fechar o mes", "notas fiscais"],
    "jogos": ["jogo", "game", "fase", "boss", "level", "nivel", "personagem", "jogador", "download", "console", "lancamento", "gamer"],
    "conforto": ["sofa", "colchao", "travesseiro", "poltrona", "relaxa", "conforto", r"cama\b", "aconchego", "movei", "a vontade"],
    "telecom": ["internet", "sinal", "antena", "fibra", "chip", "recarga", "cobertura", "wi-fi", "wifi", "operadora", "5g", "banda larga", "cabo", "cable",
                "dispersao", "torre", "sla", "uptime", "ddos", "roteamento", "protocolo", "handshake", "terabits", "comprimentos de onda"],
    "finanças": ["cartao", "credito", "emprestimo", "juros", "parcela", "investi", "rendimento", "poupanca", "banco", "pix", "tarifa", "saque", "abrir conta"],
    "construção": ["obra", "cimento", "tijolo", "laje", "fundacao", "engenheir", "parede", "reforma", "concreto", "terreno", "construi"],
}
NOSSO_TEMA = "hipermercado"


def normaliza(texto):
    texto = unicodedata.normalize("NFD", texto.lower())
    return "".join(c for c in texto if unicodedata.category(c) != "Mn")


def temas_da_frase(frase):
    t = normaliza(frase)
    return [tema for tema, palavras in TEMAS.items() if any(re.search(r"\b" + w, t) for w in palavras)]


def meu_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def mac_real(mac):
    return not mac.startswith("ip:")  # "ip:<ip>" = linha importada do capturas.csv, sem MAC


class Grupo:
    def __init__(self, mac):
        self.mac = mac
        self.ips, self.ttls, self.portas = Counter(), Counter(), Counter()
        self.frases = []  # (epoch, ip, frase)


lock = threading.Lock()
grupos = {}           # MAC -> Grupo
dono_da_frase = {}    # frase normalizada -> MAC de quem mandou primeiro
copias = {}           # (MAC, frase normalizada) -> MAC do dono original
mac_do_ip = {}        # IP -> primeiro MAC visto com ele
alertas = []          # dicts {hora, tipo, texto}
chaves_alerta = set()
feed = deque(maxlen=80)
eu = meu_ip()
# O que você confirmou no painel: tema de cada MAC e as frases certas (pistas reais) de cada um.
manuais, certas = {}, {}
if os.path.exists(CONFIRMADOS):
    with open(CONFIRMADOS, encoding="utf-8") as f:
        salvo = json.load(f)
    manuais, certas = salvo.get("temas", {}), salvo.get("certas", {})


def salva_confirmados():
    with open(CONFIRMADOS, "w", encoding="utf-8") as f:
        json.dump({"temas": manuais, "certas": certas}, f, ensure_ascii=False, indent=2)


def alerta(chave, epoch, tipo, texto):
    if chave not in chaves_alerta:
        chaves_alerta.add(chave)
        alertas.append({"hora": datetime.fromtimestamp(epoch).strftime("%H:%M:%S"), "tipo": tipo, "texto": texto})


def dono_parecido(chave, mac):
    """Dono de uma frase igual ou quase igual (alguém trocou uma vírgula para disfarçar)."""
    if chave in dono_da_frase:
        return dono_da_frase[chave]
    for outra, dono in dono_da_frase.items():
        if dono != mac and SequenceMatcher(None, chave, outra).ratio() >= 0.85:
            return dono
    return None


ja_vistos = set()  # (epoch, MAC): evita contar duas vezes o mesmo pacote (ex.: dois sniffers gravando juntos)


def registra(epoch, mac, ip, porta, ttl, frase, ao_vivo=True):
    if (round(epoch, 3), mac) in ja_vistos:
        return False
    ja_vistos.add((round(epoch, 3), mac))
    provisorio = grupos.pop(f"ip:{ip}", None) if mac_real(mac) else None
    if provisorio and mac not in grupos:
        provisorio.mac = mac
        grupos[mac] = provisorio
    elif provisorio:
        grupos[mac].frases = sorted(provisorio.frases + grupos[mac].frases)
        grupos[mac].ips.update(provisorio.ips)
    if provisorio:
        for k, dono in dono_da_frase.items():
            if dono == f"ip:{ip}":
                dono_da_frase[k] = mac

    g = grupos.get(mac) or grupos.setdefault(mac, Grupo(mac))
    if ttl != "?":
        g.ttls[ttl] += 1
        g.portas[porta] += 1
    if mac_real(mac):
        if ip not in g.ips and g.ips:
            alerta(f"ips:{mac}:{ip}", epoch, "mesma máquina", f"O MAC {mac} (antes {', '.join(g.ips)}) agora também manda como {ip}.")
        original = mac_do_ip.setdefault(ip, mac)
        if original != mac:
            alerta(f"forjado:{ip}:{mac}", epoch, "IP forjado",
                   f"O IP {ip} pertence ao MAC {original}, mas chegou frase dele vinda do MAC {mac}.")
    g.ips[ip] += 1
    g.frases.append((epoch, ip, frase))

    chave = normaliza(frase)
    dono = dono_parecido(chave, mac)
    if dono is None:
        dono_da_frase[chave] = mac
    elif dono != mac:
        copias[(mac, chave)] = dono
        alerta(f"copia:{mac}:{chave}", epoch, "cópia",
               f"{rotulo(mac)} reenviou uma frase que é de {rotulo(dono)}: “{frase}”")
    if ao_vivo:
        feed.append({"epoch": epoch, "mac": mac, "ip": ip, "frase": frase})
        print(f"[{datetime.fromtimestamp(epoch):%H:%M:%S}] {ip:<15} {mac[-8:]}  {frase}", flush=True)
    return True


def rotulo(mac):
    g = grupos.get(mac)
    return g.ips.most_common(1)[0][0] if g and g.ips else mac


def melhor_atribuicao(pontos, livres):
    """Dá um tema diferente para cada grupo, maximizando a soma dos pontos."""
    macs, memo = list(pontos), {}

    def busca(i, usados):
        if i == len(macs):
            return 0.0, []
        if (i, usados) not in memo:
            valor, resto = busca(i + 1, usados)
            melhor = (valor, [None] + resto)
            for j, tema in enumerate(livres):
                if usados >> j & 1 or not pontos[macs[i]].get(tema):
                    continue
                valor, resto = busca(i + 1, usados | 1 << j)
                valor += pontos[macs[i]][tema]
                if valor > melhor[0]:
                    melhor = (valor, [tema] + resto)
            memo[(i, usados)] = melhor
        return memo[(i, usados)]

    return dict(zip(macs, busca(0, 0)[1]))


def estado():
    with lock:
        nos = {m for m, g in grupos.items() if eu in g.ips}
        pontos = {}
        for mac, g in grupos.items():
            votos = Counter()
            for chave in {normaliza(f) for _, _, f in g.frases}:
                if (mac, chave) in copias:
                    continue  # frase copiada não diz nada sobre o tema do grupo
                ts = temas_da_frase(chave)
                for t in ts:
                    votos[t] += 1 / len(ts)
            pontos[mac] = votos
        fixos = {m: t for m, t in manuais.items() if m in grupos and t in TEMAS}
        livres = [t for t in TEMAS if t not in fixos.values()]
        palpite = melhor_atribuicao({m: v for m, v in pontos.items() if m not in nos and m not in fixos}, livres)
        tema_de = {**palpite, **fixos}
        dono_do_tema = {t: m for m, t in tema_de.items() if t}

        saida = []
        for mac, g in grupos.items():
            meu_tema = NOSSO_TEMA if mac in nos else tema_de.get(mac)
            vistas = {}
            for epoch, ip, frase in g.frases:
                v = vistas.setdefault(normaliza(frase), {"frase": frase, "vezes": 0})
                v["vezes"] += 1
                v["ultima"] = epoch
            frases = []
            for chave, v in vistas.items():
                temas = temas_da_frase(frase := v["frase"])
                if (mac, chave) in copias:
                    tipo, detalhe = "copia", f"frase de {rotulo(copias[(mac, chave)])}"
                elif meu_tema and meu_tema in temas:
                    tipo, detalhe = "pista", meu_tema
                elif temas:
                    alvos = [f"{t} ({rotulo(dono_do_tema[t])})" if t in dono_do_tema and dono_do_tema[t] != mac else t for t in temas]
                    tipo, detalhe = "isca", "imita " + ", ".join(alvos)
                else:
                    tipo, detalhe = "neutra", ""
                frases.append({"frase": frase, "tipo": tipo, "detalhe": detalhe, "vezes": v["vezes"],
                               "certa": chave in certas.get(mac, []),
                               "ultima": datetime.fromtimestamp(v["ultima"]).strftime("%H:%M:%S")})
            total = len(g.frases)
            minutos = (g.frases[-1][0] - g.frases[0][0]) / 60 if total > 1 else 0
            por_minuto = (total - 1) / minutos if minutos else 0
            ttl = g.ttls.most_common(1)[0][0] if g.ttls else "?"
            votos = pontos[mac]
            saida.append({
                "mac": mac, "ip": rotulo(mac), "ips": list(g.ips), "nos": mac in nos,
                "so": {"128": "Windows", "64": "Linux/macOS"}.get(ttl, "?"),
                "mac_aleatorio": mac_real(mac) and bool(int(mac[:2], 16) & 2),
                "portas": len(g.portas), "msgs": total, "unicas": len(vistas),
                "ciclo_completo": total > len(vistas), "por_minuto": round(por_minuto, 1), "flood": por_minuto > 1.5,
                "tema": meu_tema, "tema_manual": mac in fixos,
                "confianca": round(votos[meu_tema] / sum(votos.values()) * 100) if meu_tema in votos else 0,
                "votos": {t: round(v, 1) for t, v in votos.most_common()},
                "frases": frases,
            })
        saida.sort(key=lambda g: (g["nos"], [int(x) for x in g["ip"].split(".")] if g["ip"][0].isdigit() else [999]))
        return {
            "agora": datetime.now().strftime("%H:%M:%S"), "eu": eu, "interface": args.interface,
            "temas": [gabarito(t, dono_do_tema.get(t), t in fixos.values(), saida) for t in TEMAS],
            "grupos": saida, "alertas": alertas[-40:][::-1],
            "feed": [{"hora": datetime.fromtimestamp(e["epoch"]).strftime("%H:%M:%S"), "ip": e["ip"], "mac": e["mac"], "frase": e["frase"]}
                     for e in list(feed)[::-1]],
        }


def gabarito(tema, mac, manual, saida):
    """O que levar ao professor para um tema: o grupo e as frases certas dele.
    Se você ainda não marcou nenhuma, mostra as pistas automáticas como sugestão."""
    g = next((g for g in saida if g["mac"] == mac), None)
    marcadas = [f["frase"] for f in g["frases"] if f["certa"]] if g else []
    sugeridas = [f["frase"] for f in g["frases"] if f["tipo"] == "pista"] if g and not marcadas else []
    return {"tema": tema, "mac": mac, "ip": g["ip"] if g else None, "manual": manual,
            "certas": marcadas, "sugeridas": sugeridas, "confirmado": manual and bool(marcadas)}


class Painel(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def responde(self, corpo, tipo):
        dados = corpo.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(dados)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(dados)

    def do_GET(self):
        if self.path.startswith("/api/estado"):
            self.responde(json.dumps(estado(), ensure_ascii=False), "application/json; charset=utf-8")
        else:
            with open(os.path.join(PASTA, "painel.html"), encoding="utf-8") as f:
                self.responde(f.read(), "text/html; charset=utf-8")

    def do_POST(self):
        pedido = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with lock:
            if self.path == "/api/tema":
                if pedido.get("tema") in TEMAS:
                    for m in [m for m, t in manuais.items() if t == pedido["tema"]]:
                        del manuais[m]  # cada tema é de um grupo só
                    manuais[pedido["mac"]] = pedido["tema"]
                else:
                    manuais.pop(pedido["mac"], None)
            elif self.path == "/api/certa":
                lista = certas.setdefault(pedido["mac"], [])
                chave = normaliza(pedido["frase"])
                if pedido["certa"] and chave not in lista:
                    lista.append(chave)
                elif not pedido["certa"] and chave in lista:
                    lista.remove(chave)
            salva_confirmados()
        self.responde("{}", "application/json")


def carrega_historico():
    if not os.path.exists(ARQUIVO):
        return 0
    n = 0
    with open(ARQUIVO, encoding="utf-8", newline="") as f:
        for epoch, mac, ip, porta, ttl, frase in csv.reader(f):
            if date.fromtimestamp(float(epoch)) == date.today():
                n += registra(float(epoch), mac, ip, porta, ttl, frase, ao_vivo=False)
    return n


def captura():
    cmd = [args.tshark, "-i", args.interface, "-l", "-f", f"udp dst port {args.porta}", "-T", "fields", "-E", "separator=\t",
           "-e", "frame.time_epoch", "-e", "eth.src", "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.ttl", "-e", "data.data"]
    tshark = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
    with open(ARQUIVO, "a", newline="", encoding="utf-8") as f:
        gravador = csv.writer(f)
        for linha in tshark.stdout:
            campos = linha.rstrip("\n").split("\t")
            if len(campos) != 6 or not campos[5]:
                continue
            epoch, mac, ip, porta, ttl, dados = campos
            frase = bytes.fromhex(dados.replace(":", "")).decode("utf-8", errors="replace").strip()
            with lock:
                novo = registra(float(epoch), mac, ip, porta, ttl, frase)
            if novo:
                gravador.writerow([epoch, mac, ip, porta, ttl, frase])
                f.flush()


sys.stdout.reconfigure(encoding="utf-8")
if not os.path.exists(args.tshark):
    raise SystemExit("tshark não encontrado. Instale o Wireshark ou passe --tshark com o caminho.")
print(f"Histórico de hoje: {carrega_historico()} frases.")
threading.Thread(target=captura, daemon=True).start()
servidor = ThreadingHTTPServer(("127.0.0.1", args.painel), Painel)
url = f"http://localhost:{args.painel}"
print(f"Capturando UDP {args.porta} em '{args.interface}'. Painel: {url}  (Ctrl+C para parar)\n", flush=True)
webbrowser.open(url)
try:
    servidor.serve_forever()
except KeyboardInterrupt:
    pass
