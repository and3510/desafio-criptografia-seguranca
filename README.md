# Desafio de mensagens em rede — UDP Broadcast

Emissor e receptor em Python para o desafio de criptografia e comunicação UDP broadcast.
Nossa empresa: **Icev-Mart** — serviço: **hipermercado**.

## Arquivos

- `emissor.py`: envia uma frase por minuto do `frases.txt` por UDP broadcast (porta 80)
- `receptor.py`: escuta a porta 80, mostra as frases na tela e salva em `capturas.csv`
- `frases.txt`: as 20 frases (4 pistas reais sobre o serviço e 16 iscas para confundir)

Só precisa de Python 3, sem instalar nada.

## Teste antes da aula

Em dois terminais, na porta 80 (o receptor precisa de administrador, veja abaixo):

```
sudo python3 receptor.py
python3 emissor.py --broadcast 127.0.0.1 --intervalo 2
```

As frases devem aparecer no receptor e no `capturas.csv`.

## Em sala

1. Descubra o broadcast da rede com o professor. Ex.: IP `192.168.1.50` → `192.168.1.255`.
2. Receptor (a porta 80 exige administrador):
   - Linux/macOS: `sudo python3 receptor.py`
   - Windows: terminal como Administrador, `python receptor.py`
3. Emissor, em outro terminal, e deixe rodando a atividade toda:
   ```
   python3 emissor.py --broadcast 192.168.1.255
   ```
4. Leia as pistas de cada IP no receptor. Ao identificar um grupo, chame o professor e mostre a frase.

As frases vão em texto puro, e por isso qualquer pessoa na rede consegue lê-las.