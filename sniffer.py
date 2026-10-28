"""Sniffer UDP 80: captura as frases de todos os grupos e mostra um painel no navegador.

Identifica cada máquina pelo MAC de origem (captura com o tshark, que vem com o Wireshark),
avisa quando alguém forja um IP ou copia frases de outro grupo, e mostra de que tema cada frase
fala. O tema de cada grupo e as pistas reais quem escolhe é você, no painel.

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
p.add_argument("--sem-navegador", action="store_true", help="não abre o painel no navegador")
p.add_argument("--tshark",default=shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe")
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
        self.frases = []  # (epoch, ip, frase, porta de origem)


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


def junta_provisorio(ip, mac):
    """Frases importadas sem MAC ficam em "ip:<ip>"; quando o MAC real do IP aparece, junta."""
    provisorio = grupos.pop(f"ip:{ip}", None)
    if not provisorio:
        return
    if mac not in grupos:
        provisorio.mac = mac
        grupos[mac] = provisorio
    else:
        grupos[mac].frases = sorted(provisorio.frases + grupos[mac].frases)
        grupos[mac].ips.update(provisorio.ips)
    for k, dono in dono_da_frase.items():
        if dono == f"ip:{ip}":
            dono_da_frase[k] = mac
    for k in [k for k in copias if k[0] == f"ip:{ip}"]:
        copias[(mac, k[1])] = copias.pop(k)


# Investigação de cada máquina: nome (NetBIOS / DNS reverso), MAC pela tabela ARP e fabricante da placa.
perfis = {}  # IP -> {"nome": str, "mac_arp": str}
fabricantes = {}  # "aa:bb:cc" (bloco de 24 bits) ou "aa:bb:cc:d" (bloco de 28 bits) -> nome
try:
    tabela = subprocess.run([args.tshark, "-G", "manuf"], capture_output=True, timeout=30).stdout.decode("utf-8", errors="replace")
except (subprocess.TimeoutExpired, OSError):
    tabela = ""
for linha in tabela.splitlines():
    partes = linha.split("\t")
    if len(partes) < 2 or linha.startswith("#"):
        continue
    prefixo = partes[0].strip().lower()
    if len(prefixo) == 8:
        fabricantes[prefixo] = partes[-1].strip()
    elif prefixo.endswith("/28"):
        fabricantes[prefixo[:10]] = partes[-1].strip()


def fabricante(mac):
    if not mac_real(mac):
        return "?"
    if int(mac[:2], 16) & 2:
        return "MAC aleatório (esconde o fabricante)"
    return fabricantes.get(mac[:10]) or fabricantes.get(mac[:8], "desconhecido")


def roda(cmd, segundos=8):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=segundos).stdout.decode("cp850", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return ""


def investiga_ip(ip):
    perfil = perfis.setdefault(ip, {"nome": None, "mac_arp": None})
    if perfil["nome"] is None:
        nome = re.search(r"^\s*(\S+)\s*<00>\s+(UNIQUE|EXCLUSIVO)", roda(["nbtstat", "-A", ip]), re.M)
        if not nome:
            try:
                nome = socket.gethostbyaddr(ip)[0]
            except OSError:
                nome = ""
        perfil["nome"] = nome.group(1) if hasattr(nome, "group") else nome
    roda(["ping", "-n", "1", "-w", "500", ip], 3)  # só para a ARP aprender o MAC
    achado = re.search(re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", roda(["arp", "-a", ip], 3), re.I)
    if achado:
        mac_arp = achado.group(1).lower().replace("-", ":")
        with lock:
            perfil["mac_arp"] = mac_arp
            junta_provisorio(ip, mac_arp)
            for mac, g in grupos.items():
                if ip in g.ips and mac_real(mac) and mac != mac_arp:
                    alerta(f"arp:{ip}:{mac}", datetime.now().timestamp(), "IP forjado",
                           f"A rede diz que {ip} é a placa {mac_arp}, mas chegaram frases com esse IP vindas de {mac}.")


def investigador():
    while True:
        with lock:
            ips = {ip for g in grupos.values() for ip in g.ips if ip != eu}
        for ip in sorted(ips):
            investiga_ip(ip)
        threading.Event().wait(30)


def registra(epoch, mac, ip, porta, ttl, frase, ao_vivo=True):
    if (round(epoch, 3), mac) in ja_vistos:
        return False
    ja_vistos.add((round(epoch, 3), mac))
    if mac_real(mac):
        junta_provisorio(ip, mac)

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
    g.frases.append((epoch, ip, frase, porta))

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


def estado():
    # Não existe palpite automático de tema: todo grupo manda iscas com o tema dos outros
    # (como nós), então contar palavras-chave engana. O painel só mostra indícios; quem
    # decide o tema de cada grupo, e quais frases são as pistas reais, é você.
    with lock:
        nos = {m for m, g in grupos.items() if eu in g.ips}
        tema_de = {m: t for m, t in manuais.items() if m in grupos and t in TEMAS}
        dono_do_tema = {t: m for m, t in tema_de.items()}
        citacoes = {t: Counter() for t in TEMAS}  # tema -> {MAC: quantas frases próprias citam o tema}

        saida = []
        for mac, g in grupos.items():
            meu_tema = NOSSO_TEMA if mac in nos else tema_de.get(mac)
            vistas, emissores = {}, {}
            for epoch, ip, frase, porta in g.frases:
                v = vistas.setdefault(normaliza(frase), {"frase": frase, "vezes": 0})
                v["vezes"] += 1
                v["ultima"] = epoch
                if porta != "?":
                    e = emissores.setdefault(porta, {"porta": porta, "frases": set(), "temas": Counter(), "de": epoch})
                    e["ate"] = epoch
                    if normaliza(frase) not in e["frases"]:
                        e["frases"].add(normaliza(frase))
                        e["temas"].update(temas_da_frase(frase) or ["neutra"])
            frases, citados = [], Counter()
            for chave, v in vistas.items():
                temas = temas_da_frase(frase := v["frase"])
                copia = (mac, chave) in copias
                if not copia:
                    citados.update(temas)
                    for tema in temas:
                        citacoes[tema][mac] += 1
                if copia:
                    tipo, detalhe = "copia", f"frase de {rotulo(copias[(mac, chave)])}"
                elif not temas:
                    tipo, detalhe = "neutra", ""
                elif not meu_tema:
                    tipo, detalhe = "fala", "fala de " + ", ".join(temas)
                elif meu_tema in temas:
                    tipo, detalhe = "pista", f"bate com {meu_tema}"
                else:
                    alvos = [f"{x} ({rotulo(dono_do_tema[x])})" if x in dono_do_tema else x for x in temas]
                    tipo, detalhe = "isca", "imita " + ", ".join(alvos)
                frases.append({"frase": frase, "tipo": tipo, "detalhe": detalhe, "vezes": v["vezes"],
                               "certa": chave in certas.get(mac, []),
                               "ultima": datetime.fromtimestamp(v["ultima"]).strftime("%H:%M:%S")})
            total = len(g.frases)
            minutos = (g.frases[-1][0] - g.frases[0][0]) / 60 if total > 1 else 0
            por_minuto = (total - 1) / minutos if minutos else 0
            ttl = g.ttls.most_common(1)[0][0] if g.ttls else "?"
            tempos = sorted(e for e, *_ in g.frases)
            intervalos = sorted(b - a for a, b in zip(tempos, tempos[1:]))
            fase = Counter(int(t) % 60 for t in tempos).most_common(1)
            perfil = perfis.get(rotulo(mac), {})
            # porta nova a cada vez que o grupo reinicia o emissor; só é "vários programas" se os períodos se cruzam
            periodos = sorted((e["de"], e["ate"]) for e in emissores.values())
            simultaneos = any(b[0] < a[1] - 5 for a, b in zip(periodos, periodos[1:]))
            saida.append({
                "maquina": {
                    "nome": perfil.get("nome"),  # None = ainda não consultado, "" = não respondeu
"fabricante": fabricante(mac), "mac_arp": perfil.get("mac_arp"),
                    "arp_confere": perfil.get("mac_arp") in (None, mac) if mac_real(mac) else None,
                    "intervalo": round(intervalos[len(intervalos) // 2]) if intervalos else None,
                    "segundo": fase[0][0] if fase else None,
                    "ultima": datetime.fromtimestamp(tempos[-1]).strftime("%H:%M:%S") if tempos else None,
                    "simultaneos": simultaneos,
                    "emissores": [{"porta": e["porta"], "frases": len(e["frases"]), "temas": dict(e["temas"].most_common()),
                                   "de": datetime.fromtimestamp(e["de"]).strftime("%H:%M"), "ate": datetime.fromtimestamp(e["ate"]).strftime("%H:%M")}
                                  for e in sorted(emissores.values(), key=lambda e: e["de"])],
                },
                "mac": mac, "ip": rotulo(mac), "ips": list(g.ips), "nos": mac in nos,
                "so": {"128": "Windows", "64": "Linux/macOS"}.get(ttl, "?"),
                "mac_aleatorio": mac_real(mac) and bool(int(mac[:2], 16) & 2),
                "portas": len(g.portas), "msgs": total, "unicas": len(vistas),
                "ciclo_completo": total > len(vistas), "por_minuto": round(por_minuto, 1), "flood": por_minuto > 1.5,
                "tema": meu_tema, "citados": dict(citados.most_common()), "frases": frases,
            })
        saida.sort(key=lambda g: (g["nos"], [int(x) for x in g["ip"].split(".")] if g["ip"][0].isdigit() else [999]))
        return {
            "agora": datetime.now().strftime("%H:%M:%S"), "eu": eu, "interface": args.interface,
            "temas": [gabarito(t, dono_do_tema.get(t), citacoes[t], nos, saida) for t in TEMAS],
            "grupos": saida, "alertas": alertas[-40:][::-1],
            "feed": [{"hora": datetime.fromtimestamp(e["epoch"]).strftime("%H:%M:%S"), "ip": e["ip"], "mac": e["mac"], "frase": e["frase"]}
                     for e in list(feed)[::-1]],
        }


def gabarito(tema, mac, citacoes, nos, saida):
    """O que levar ao professor para um tema: o grupo que você escolheu e as frases certas dele.
    Enquanto não houver escolha, lista quem cita o tema (lembrando que pode ser isca)."""
    g = next((g for g in saida if g["mac"] == mac), None)
    marcadas = [f["frase"] for f in g["frases"] if f["certa"]] if g else []
    citam = [{"ip": rotulo(m), "frases": n} for m, n in citacoes.most_common() if m not in nos]
    return {"tema": tema, "mac": mac, "ip": g["ip"] if g else None, "certas": marcadas,
            "citam": citam, "confirmado": bool(g and marcadas)}


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
threading.Thread(target=investigador, daemon=True).start()
servidor = ThreadingHTTPServer(("127.0.0.1", args.painel), Painel)
url = f"http://localhost:{args.painel}"
print(f"Capturando UDP {args.porta} em '{args.interface}'. Painel: {url}  (Ctrl+C para parar)\n", flush=True)
if not args.sem_navegador:
    webbrowser.open(url)
try:
    servidor.serve_forever()
except KeyboardInterrupt:
    pass
