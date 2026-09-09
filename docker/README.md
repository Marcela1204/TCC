# Executando em container

Três papéis, uma imagem só — detector, treinador e utilitários rodam o mesmo
código e a mesma versão de scikit-learn, o que importa porque o artefato
`.joblib` é serializado por versão.

Nenhum container roda como root. As capacidades de captura são *file
capabilities* no `/usr/bin/tcpdump` (`cap_net_raw`, `cap_net_admin`), então o
processo é uid 1000 e ainda abre socket de captura. Efeito colateral bom: os
parquets no bind mount saem com o seu dono, não de root.

## Primeira subida

```bash
cp .env.example .env
$EDITOR .env                       # senha, CAPTURA_IFACE, UID_APP
echo "UID_APP=$(id -u)"  >> .env   # dono de POOL_HOST
echo "GID_APP=$(id -g)"  >> .env
mkdir -p dados                     # se não existir, o compose cria como root

docker compose up -d banco treinador
docker compose logs -f treinador
```

O treinador aplica as migrações (uma vez cada, via `na.schema_migrations`) e
entra no relógio diário. Se a migração falhar ele **aborta de propósito**:
treinar contra schema incerto grava dado que depois ninguém sabe interpretar.

## Escolhendo os perfis

Serviço sem `profiles:` sobe sempre — `banco` e `treinador` são o núcleo. Os
demais só entram se o perfil deles estiver ligado:

| serviço | perfil |
|---|---|
| `detector` | `sensor` |
| `detector-isolado` | `sensor-isolado` |
| `replay` | `replay` |
| `grafana` | `painel` |

Três formas, em ordem de conveniência:

```bash
# 1. no .env -- vale para TODOS os subcomandos. É o que usar na máquina de IDS.
echo "COMPOSE_PROFILES=sensor,painel" >> .env
docker compose up -d

# 2. variável de ambiente (aceita vírgula)
COMPOSE_PROFILES=sensor,painel docker compose up -d

# 3. na linha de comando -- antes do subcomando, um --profile para cada
docker compose --profile sensor --profile painel up -d
```

**A pegadinha:** com a forma 3, o perfil precisa estar presente também nos
comandos *seguintes*, senão o Compose não sabe que o serviço existe:

```bash
docker compose --profile sensor up -d
docker compose logs detector                    # ERRO: no such service
docker compose --profile sensor logs detector   # ok
docker compose down                             # deixa o detector rodando!
```

Vale para `logs`, `restart`, `stop`, `down`, `ps`. Definir `COMPOSE_PROFILES`
no `.env` elimina essa classe inteira de erro.

## Partida a frio: adotando um modelo treinado fora

A instalação nova tem um impasse circular: o detector precisa de modelo
promovido, a promoção precisa de candidato, o candidato precisa de pool, e o
pool é alimentado pelo sink do detector. `lifecycle.py adopt` rompe o círculo
semeando o sistema com um modelo já pronto.

### 1. Treine fora do ciclo, como sempre

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

### 4. Golden set e linha de base do portão

Adotar sem golden set deixa o portão **meio cego**: `v_gate_check` compara o
candidato contra as avaliações da *produção*, e sem elas a checagem de queda
relativa nunca dispara — só o piso absoluto sobra.

Se você não tinha golden set na hora de adotar, registre depois e reavalie:

```bash
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py golden --pcap /pcaps/ataque.pcap --cicids --scenario brute_force
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py evaluate --model <uuid-do-adotado>
```

A partir daí o `candidate` diário passa a ser comparado contra a produção.

### O que continua manual

A **promoção** dos candidatos seguintes. É deliberado, e vale mais do que
parece: promoção automática vale exatamente o que vale a cobertura do golden
set. Com um cenário só, um portão que aprova sozinho é carimbo — pior que não
ter portão, porque dá aparência de verificação ao que não foi verificado.

## Instância nova: o detector espera, não quebra

Numa instalação limpa não existe modelo promovido — ninguém treinou nada ainda.
O detector **não** morre nem entra em laço de reinício: ele espera, explica o
que falta, e começa a capturar sozinho no instante em que houver promoção
(reconfere a cada `DETECTOR_ESPERA`, 15 s por padrão).

```
[detector] aguardando modelo promovido -- o artefato ainda nao existe
[detector]   arquivo esperado: /var/lib/netanomaly/models/current_flow.joblib
[detector] Numa instancia nova isto e esperado. Faca o bootstrap:
[detector]   ...
[detector] Assim que houver promocao, comeco a capturar sozinho.
```

Ele reconhece três situações distintas e diz qual é: o artefato não existe, o
artefato existe mas não está registrado em `na.models`, ou está registrado com
status diferente de `promoted`.

**Ele não treina sozinho, e isso é deliberado.** Treinar o detector no tráfego
que por acaso estiver passando é exatamente o caminho do envenenamento: se
houver ataque em curso, o ataque entra no baseline como normal. O modelo tem de
nascer de uma promoção que passou pelo portão.

Sequência numa instância nova:

```bash
git clone <repo> && cd TCC
cp .env.example .env
$EDITOR .env                        # senha, CAPTURA_IFACE, COMPOSE_PROFILES
echo "UID_APP=$(id -u)" >> .env
echo "GID_APP=$(id -g)" >> .env
mkdir -p dados pcaps                # ANTES do up, senão o Compose cria como root

docker compose up -d                # detector sobe e espera
# ... bootstrap ...                 # detector começa a capturar sozinho
```

## "Não encontra o .joblib"

O detector procura `/var/lib/netanomaly/models/current_flow.joblib`, que é um
symlink criado pelo `lifecycle.py promote` **dentro** do bind mount. Três
causas, em ordem de frequência:

1. **Nunca houve promoção.** O arquivo não é copiado de lugar nenhum — ele
   nasce do ciclo. Faça o bootstrap:

   ```bash
   docker compose run --rm --entrypoint python3 treinador \
       lifecycle.py extract --pcap /pcaps/dia.pcap --sensor cic-lan --view flow
   docker compose run --rm --entrypoint python3 treinador \
       lifecycle.py golden --pcap /pcaps/ataque.pcap --cicids --scenario brute_force
   docker compose run --rm --entrypoint python3 treinador \
       lifecycle.py candidate --view flow --contamination 0.01
   docker compose run --rm --entrypoint python3 treinador \
       lifecycle.py promote --model <uuid> --by seu-nome
   ```

2. **`POOL_HOST` foi criado pelo Compose como `root`** e o container (não-root)
   não consegue escrever. O treinador detecta e aborta com o conserto na
   mensagem:

   ```bash
   docker run --rm -v "$PWD/dados:/d" alpine chown -R $(id -u):$(id -g) /d
   ```

3. **O `.joblib` que você já tinha está na raiz do repositório.** Os
   `cic2017_flow.joblib` e afins vieram de `netanomaly.py --save-model` e não
   servem direto: além de estarem fora do mount, o `--sink` exige que o
   artefato esteja registrado em `na.models` — é isso que faz cada alerta
   apontar para o modelo que o produziu. Um artefato solto não tem essa
   identidade. Refaça pelo ciclo, ou peça um `lifecycle.py adopt`.

## Captura de tráfego: a escolha que importa

Um container só fareja o que chega ao *namespace de rede* dele. Isso descarta a
opção mais intuitiva:

> **`macvlan` em modo bridge não serve para IDS.** Ele dá ao container MAC e IP
> próprios na LAN — uma "interface paralela à física" — mas o kernel entrega a
> ele apenas o tráfego destinado ao seu MAC, mais broadcast e multicast. Um IDS
> precisa do tráfego *dos outros*.

As duas que funcionam:

### `--profile sensor` — recomendado

`network_mode: host`. O container vê todas as interfaces do host, inclusive uma
em modo promíscuo ligada à porta espelho (SPAN) ou a um tap. É como Suricata e
Zeek em container fazem.

```bash
docker compose --profile sensor up -d detector
```

Custo: sem isolamento de rede — as portas do container são as do host. Por isso
a porta do banco é publicada só em `127.0.0.1`.

### `--profile sensor-isolado` — NIC dedicada

`macvlan` em modo **passthru**: entrega a placa inteira ao container, que passa
a poder colocá-la em promíscuo, e mantém o detector também na rede interna para
falar com o banco.

A rede é **externa** de propósito: tirar uma NIC do host não deve ser efeito
colateral de um `up`. Crie uma vez, na máquina de IDS:

```bash
docker network create -d macvlan \
    -o parent=eth1 -o macvlan_mode=passthru \
    netanomaly-captura

docker compose --profile sensor-isolado up -d detector-isolado
```

Custo: exige NIC dedicada — o host perde o acesso a ela, e só um container pode
usá-la.

### Desenho na máquina dedicada

O arranjo clássico são duas placas:

```
   eth0  gerência   IP, SSH, Grafana, banco
   eth1  captura    sem IP, promíscua, ligada ao espelho do switch
```

`CAPTURA_IFACE=eth1`. Ponha a interface em promíscuo no host (`ip link set eth1
promisc on`) — ou deixe o passthru fazê-lo.

## Teste sem captura

```bash
mkdir -p pcaps && cp /caminho/algum.pcap pcaps/atual.pcap
docker compose --profile replay run --rm replay
```

## Operação

```bash
# ver o pool de treino
docker compose run --rm --entrypoint python3 treinador lifecycle.py pool --view flow

# treinar um candidato agora, fora do relógio
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py candidate --view flow --contamination 0.01

# promover: MANUAL de propósito. Um portão que se auto-aprova não é portão.
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py promote --model <uuid> --by seu-nome

# despejar janela após IOC retroativo
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py evict --windows <id> --reason "INC-441" --by seu-nome

# registrar captura de pentest no golden set
docker compose run --rm --entrypoint python3 treinador \
    lifecycle.py golden --pcap /pcaps/nmap.pcap --scenario recon --label 1
```

Depois de promover, reinicie o detector para ele recarregar o artefato:
`docker compose --profile sensor restart detector`.

## Painel

```bash
docker compose --profile painel up -d grafana   # :3000, admin/$SENHA_GRAFANA
```

Datasource já provisionado. O `search_path=na` é definido pela migração com
`ALTER ROLE` — sem ele o Grafana conecta, autentica e não lista tabela nenhuma.

## Cuidados

- **`POOL_HOST` é o histórico curado de treino.** Perdê-lo é perder a
  quarentena, a procedência dos modelos e a capacidade de despejar janela por
  IOC retroativo. Faça backup dele junto com o volume do banco.
- **Editar migração já aplicada** não tem efeito: o `migrar.py` avisa que o
  arquivo mudou e que o banco está com a versão antiga. Em desenvolvimento,
  `docker compose down -v`; em produção, escreva uma migração nova.
- O relógio de promoção **não** está automatizado, e isso é deliberado.
