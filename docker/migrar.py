#!/usr/bin/env python3
"""
migrar.py -- aplica as migracoes ainda nao aplicadas, uma vez cada.

Existe porque o 001_init.sql NAO e idempotente: sao 13 CREATE TABLE sem
IF NOT EXISTS, mais indices e triggers. Reaplica-lo aborta a transacao no
primeiro CREATE e desfaz TUDO que veio antes -- inclusive o ALTER ROLE que
define o search_path, o que fazia o Grafana nao achar tabela nenhuma.

Cada migracao roda dentro de UMA transacao junto com o registro dela, entao
ou aplica e fica registrada, ou nada acontece. Sem estado intermediario.

Uso:  migrar.py [diretorio]        (padrao: /app/migrations)
      NETANOMALY_DSN no ambiente.
"""

import hashlib
import os
import sys
from pathlib import Path

import psycopg

CONTROLE = """
CREATE SCHEMA IF NOT EXISTS na;
CREATE TABLE IF NOT EXISTS na.schema_migrations (
    arquivo    text        PRIMARY KEY,
    sha256     text        NOT NULL,
    aplicada_em timestamptz NOT NULL DEFAULT now()
);
"""


def main():
    diretorio = Path(sys.argv[1] if len(sys.argv) > 1 else "/app/migrations")
    dsn = os.environ.get("NETANOMALY_DSN")
    if not dsn:
        sys.exit("[migrar] NETANOMALY_DSN nao definida")

    arquivos = sorted(diretorio.glob("*.sql"))
    if not arquivos:
        sys.exit(f"[migrar] nenhum .sql em {diretorio}")

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(CONTROLE)
        aplicadas = {
            r[0]: r[1] for r in
            conn.execute("SELECT arquivo, sha256 FROM na.schema_migrations")
        }

    novas = 0
    for caminho in arquivos:
        conteudo = caminho.read_text()
        sha = hashlib.sha256(conteudo.encode()).hexdigest()

        if caminho.name in aplicadas:
            if aplicadas[caminho.name] != sha:
                # Editar migracao ja aplicada e como mudar o passado: o banco
                # em producao continua com o schema antigo e nada avisa.
                print(f"[migrar] !! {caminho.name} MUDOU desde que foi "
                      f"aplicada. O banco esta com a versao antiga.\n"
                      f"[migrar]    Em desenvolvimento: recrie o banco "
                      f"(banco_dev.sh reset / docker compose down -v).\n"
                      f"[migrar]    Em producao: escreva uma migracao nova.",
                      file=sys.stderr)
            else:
                print(f"[migrar] {caminho.name} ja aplicada")
            continue

        # Uma transacao para a migracao E o registro dela.
        with psycopg.connect(dsn) as conn:
            with conn.transaction():
                conn.execute(conteudo)
                conn.execute(
                    "INSERT INTO na.schema_migrations (arquivo, sha256) "
                    "VALUES (%s, %s)", (caminho.name, sha))
        print(f"[migrar] {caminho.name} aplicada")
        novas += 1

    print(f"[migrar] {novas} migracao(oes) nova(s), "
          f"{len(arquivos) - novas} ja estavam aplicadas")


if __name__ == "__main__":
    main()
