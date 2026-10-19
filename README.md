# Desafio de mensagens em rede — UDP Broadcast

Emissor e receptor em Python para o desafio de criptografia e comunicação UDP broadcast.
Nossa empresa: **Icev-Food** — serviço: **entrega de comida**.

## Arquivos

| Arquivo | Função |
|---|---|
| `emissor.py` | Envia uma frase por minuto (do `frases.txt`) para o broadcast da rede, em loop |
| `receptor.py` | Escuta a porta 80, mostra as frases na tela e salva em `capturas.csv` |
| `frases.txt` | Conjunto de 14 frases: 4 com pistas sobre o serviço e 10 sobre outros assuntos |
| `capturas.csv` | Gerado pelo receptor: horário, IP de origem e frase |

## Requisitos

- Python 3.8 ou superior (só usa a biblioteca padrão, não precisa instalar nada)
- Estar na mesma rede do laboratório que os outros grupos

## Parâmetros da atividade

| Parâmetro | Valor |
|---|---|
| Protocolo | UDP |
| Modo | Broadcast |
| Porta | 80 |
| Endereço de broadcast | Verificar na hora (ex.: `192.168.1.255`) |

## 1. Teste antes da aula (na própria máquina)

Use outra porta para não precisar de privilégio de administrador. Abra dois terminais.

Terminal 1 (receptor):

```
python3 receptor.py --porta 5000 --incluir-proprio
```

Terminal 2 (emissor, enviando uma frase a cada 2 segundos para o próprio computador):

```
python3 emissor.py --broadcast 127.0.0.1 --porta 5000 --intervalo 2
```

Se as frases aparecerem no terminal 1 e no arquivo `capturas.csv`, está tudo certo.

## 2. Uso em sala de aula

### Passo 1: descobrir o endereço de broadcast

1. Veja o IP do seu computador: `ip a` (Linux), `ifconfig` (macOS) ou `ipconfig` (Windows).
2. Com máscara 255.255.255.0 (/24), troque o último número por 255.
   Exemplo: IP `192.168.1.50` → broadcast `192.168.1.255`.
3. Confirme com o professor, pois a rede do laboratório pode usar outra máscara.

### Passo 2: iniciar o receptor

A porta 80 exige privilégio de administrador.

- **Linux / macOS:** `sudo python3 receptor.py`
- **Windows:** abra o terminal como Administrador e rode `python receptor.py`. Se o firewall perguntar, permita o acesso do Python à rede.

### Passo 3: iniciar o emissor

Em outro terminal:

```
python3 emissor.py --broadcast 192.168.1.255
```

(troque pelo broadcast da sua rede). O emissor manda uma frase por minuto e repete o conjunto até você apertar `Ctrl+C`. Mantenha-o rodando durante toda a atividade.

### Passo 4: identificar os outros grupos

1. Acompanhe o receptor: cada linha mostra o horário, o IP de origem e a frase.
2. Ao apertar `Ctrl+C`, o receptor mostra um resumo das frases agrupadas por IP.
3. Leia as pistas de cada IP e deduza o serviço da empresa.
4. Quando tiver certeza, **chame o professor**, mostre a frase capturada e diga a qual grupo ela pertence. O professor registra a identificação e o horário.

Lembretes do guia:
- Cada grupo identificado conta uma única vez, então várias frases do mesmo grupo não aumentam o total.
- Vence quem identificar mais grupos. No empate, vence quem chamou o professor primeiro para a última identificação válida.
- Um grupo pode ter mais de um computador, então confirme antes de assumir que um IP é um grupo.

## Opções dos programas

### `emissor.py`

| Opção | Padrão | Descrição |
|---|---|---|
| `--broadcast` | detecta (/24) | Endereço de broadcast de destino |
| `--porta` | 80 | Porta UDP |
| `--frases` | `frases.txt` | Arquivo com as frases |
| `--intervalo` | 60 | Segundos entre cada frase |

### `receptor.py`

| Opção | Padrão | Descrição |
|---|---|---|
| `--porta` | 80 | Porta UDP |
| `--saida` | `capturas.csv` | Arquivo CSV de saída |
| `--incluir-proprio` | desligado | Também mostra os pacotes enviados por este computador |

## Problemas comuns

- **"Sem permissão para usar a porta 80":** rode como administrador (`sudo` no Linux/macOS).
- **"Não consegui abrir a porta 80":** outro programa (como um servidor web) pode estar usando a porta. Feche-o.
- **Não recebo nada dos outros grupos:** confira o firewall e se o computador está na mesma rede e faixa de IP. Se a rede não for /24, o broadcast automático do emissor pode estar errado, então passe `--broadcast` manualmente.
- **Meu emissor não parece estar sendo ouvido:** o receptor ignora seus próprios pacotes por padrão. Use `--incluir-proprio` só para testes.
- **Acentos aparecem errados:** as mensagens usam UTF-8. Use um terminal com UTF-8.
- **Wireshark (alternativa):** capture na interface da rede com o filtro `udp.port == 80`.

## Observação sobre segurança

As frases viajam em **texto puro**, e por isso qualquer computador da rede consegue ler. Esse é o ponto da atividade: sem criptografia, quem está na rede enxerga tudo o que passa nela.
