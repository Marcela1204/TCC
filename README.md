# Sistema de detecção de invasão com aprendizado de máquina

## Primeira execução

```bash
cp .env.example .env
$EDITOR .env                       # senha, CAPTURA_IFACE, UID_APP
echo "UID_APP=$(id -u)"  >> .env   # dono de POOL_HOST
echo "GID_APP=$(id -g)"  >> .env
mkdir -p dados                     # se não existir, o compose cria como root

docker compose up -d banco treinador
docker compose logs -f treinador
```

### 1. Treinamento fora do ciclo

```bash
tcpdump -i eth0 -w treino.pcap -c 800000            # ou um dia inteiro
python3 netanomaly.py treino.pcap --nfstream --contamination 0.01 \
        --save-model meumodelo
```

### 2. Ponha o `.joblib` e o pcap onde o container vê

Ambos vão em `PCAP_HOST` (montado como `/pcaps`, somente leitura):

```bash
cp meumodelo_flow.joblib treino.pcap pcaps/
```

### 3. Adote

```bash
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py adopt --model /pcaps/meumodelo_flow.joblib \
                       --pcap  /pcaps/treino.pcap \
                       --sensor sensor-01 --by seu-nome
```

O `--pcap` não é opcional por acaso — a captura do treino faz duas coisas que a
adoção exige:

- **gera a grade de referência de percentil** (`score_quantis`), que o bundle
  de `netanomaly.py --save-model` não tem. Sem ela o sink alimenta o pool mas
  **não grava alerta nenhum**, porque o percentil perde significado estável;
- **semeia o pool** com o dado que o modelo vigente de fato viu, que é
  exatamente o que o próximo `candidate` precisa.

Confirmação de que a grade saiu certa: o `p99` dela deve bater com o
`threshold` do bundle, já que `threshold = quantil(1 − contamination)`.

O modelo entra como `promoted`, e o registro em `na.promotions` fica com
`decisao='adotado'` — nem aprovado nem sobreposto. Um modelo semente não passou
por portão nenhum, e o histórico não deve fingir que passou.

O detector assume em segundos, sem restart. Daí em diante o sink alimenta o
pool e o ciclo se sustenta.


## Definição do goldenset

```bash
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py golden --pcap /pcaps/ataque.pcap --cicids --scenario brute_force
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py evaluate --model <uuid-do-adotado>
```
