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

## Treinamento fora do ciclo

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

## Definição do goldenset

```bash
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py golden --pcap /pcaps/ataque.pcap --cicids --scenario brute_force
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py evaluate --model <uuid-do-adotado>
```
