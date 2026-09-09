# Imagem unica para os tres papeis do sistema: detector (netanomaly_live),
# treinador (lifecycle) e utilitarios. O papel e escolhido pelo comando, nao
# pela imagem -- assim detector e treinador rodam exatamente o mesmo codigo e
# a mesma versao de scikit-learn, o que importa porque o artefato .joblib e
# serializado por versao.
FROM python:3.13-slim

# libpcap: nfstream e scapy capturam por ela.
# tcpdump: netanomaly_live chama o binario para ler da interface.
# procps: para diagnosticar dentro do container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tcpdump \
        procps \
        iproute2 \
        libcap2-bin \
    # Capacidades NO BINARIO, nao no processo. Com isto o container roda sem
    # root nenhum: um processo uid 1000 abre socket de captura porque o
    # tcpdump carrega cap_net_raw/cap_net_admin como file capability, e o
    # Docker so precisa te-las no bounding set (cap_add).
    #
    # A alternativa era rodar root e conceder tambem SETUID/SETGID, para o
    # tcpdump renunciar ao privilegio depois de abrir o socket. Medi as duas:
    # ambas capturam, mas esta nunca tem root, e de quebra os parquets no
    # bind mount saem com o dono do host em vez de root.
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# As dependencias primeiro, para a camada ficar em cache entre builds.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netanomaly.py netanomaly_live.py lifecycle.py sink.py ./
COPY scripts/ ./scripts/
COPY migrations/ ./migrations/
COPY docker/entrypoint-treinador.sh /usr/local/bin/entrypoint-treinador
COPY docker/entrypoint-detector.sh /usr/local/bin/entrypoint-detector
COPY docker/migrar.py /usr/local/bin/migrar
RUN chmod +x /usr/local/bin/entrypoint-treinador \
             /usr/local/bin/entrypoint-detector \
             /usr/local/bin/migrar

# Onde o pool de parquets e os artefatos de modelo vivem. Precisa ser volume:
# detector e treinador compartilham este diretorio, e perder o pool significa
# perder o historico curado de treino.
ENV NETANOMALY_POOL=/var/lib/netanomaly \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
# 0777 porque o compose roda com --user <uid do host>, e esse uid nao existe
# em /etc/passwd da imagem. Num bind mount quem manda e o dono do diretorio
# no host; isto so cobre o caso de volume nomeado.
RUN mkdir -p /var/lib/netanomaly && chmod 0777 /var/lib/netanomaly

# Sem CMD proposital: cada servico do compose declara o seu.
