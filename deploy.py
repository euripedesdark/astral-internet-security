#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Astral Internet Security - Compilador e Publicador Limpo
Executa compilação limpa em Rust (cargo clean + cargo build --release),
copia o executável para o diretório global /opt/astral-internet-security
e reinicia o serviço no systemd.

Uso:
    ./deploy.py
ou
    python3 deploy.py
"""

import os
import sys
import subprocess
import time

SERVICE_NAME = "astral-internet-security"
PORT = 8084
GLOBAL_DIR = "/opt/astral-internet-security"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
SUDO_PASS = "Btf1_Mk3"

GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
NC = "\033[0m"

def log(msg, color=BLUE):
    print(f"{color}{BOLD}[ASTRAL-DEPLOY]{NC} {msg}")

def run_sudo(cmd):
    if os.geteuid() == 0:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return subprocess.run(f"sudo -S {cmd}", shell=True, input=f"{SUDO_PASS}\n", capture_output=True, text=True)

def main():
    print(f"{BLUE}{BOLD}============================================================{NC}")
    print(f"{GREEN}{BOLD}   Astral Internet Security - Compilação & Publicação Limpa   {NC}")
    print(f"{BLUE}{BOLD}============================================================{NC}")

    os.chdir(APP_DIR)

    # 1. Limpeza Completa (Clean Build)
    log("Limpando cache de compilação anterior (cargo clean)...", YELLOW)
    clean_proc = subprocess.run(["cargo", "clean", "-p", SERVICE_NAME], capture_output=True, text=True)
    if clean_proc.returncode != 0:
        # Se falhar limpar o pacote especifico, limpa o target inteiro
        subprocess.run(["cargo", "clean"], capture_output=True, text=True)
    log("Cache limpo com sucesso.", GREEN)

    # 2. Compilação Otimizada de Release
    log("Iniciando compilação otimizada em Rust (cargo build --release)...", BLUE)
    start_time = time.time()
    build_proc = subprocess.run(["cargo", "build", "--release"])
    if build_proc.returncode != 0:
        log("ERRO: Falha na compilação do Rust!", RED)
        sys.exit(1)
    elapsed = time.time() - start_time
    log(f"Compilação concluída com sucesso em {elapsed:.2f} segundos!", GREEN)

    bin_path = os.path.join(APP_DIR, "target", "release", SERVICE_NAME)
    if not os.path.exists(bin_path):
        log(f"ERRO: Binário compilado não encontrado em {bin_path}", RED)
        sys.exit(1)

    # 3. Publicação no Diretório do Sistema (/opt/...)
    log(f"Instalando binário no diretório global {GLOBAL_DIR}...", BLUE)
    run_sudo(f"mkdir -p {GLOBAL_DIR}")
    target_bin = os.path.join(GLOBAL_DIR, SERVICE_NAME)
    
    # Copia o binário com sudo
    cp_res = run_sudo(f"cp -f {bin_path} {target_bin}")
    if cp_res.returncode != 0:
        log(f"ERRO ao copiar binário: {cp_res.stderr}", RED)
        sys.exit(1)

    run_sudo(f"chmod 755 {target_bin}")
    log(f"Binário instalado em {target_bin} com permissões 755.", GREEN)

    # 4. Reinicialização do Serviço no Systemd
    log(f"Reiniciando serviço systemd '{SERVICE_NAME}'...", YELLOW)
    run_sudo(f"systemctl restart {SERVICE_NAME}")
    time.sleep(1.5)

    # 5. Verificação de Saúde
    status_proc = run_sudo(f"systemctl is-active {SERVICE_NAME}")
    status = status_proc.stdout.strip()
    if status == "active":
        log(f"SUCESSO! O serviço '{SERVICE_NAME}' está ATIVO e rodando na porta {PORT}.", GREEN)
    else:
        log(f"AVISO: O serviço retornou status: {status}", RED)
        log("Verificando logs recentes do journalctl:", YELLOW)
        journal = run_sudo(f"journalctl -u {SERVICE_NAME} -n 10 --no-pager")
        print(journal.stdout)
        sys.exit(1)

    # 6. Exibir porta e logs recentes
    ports = run_sudo(f"ss -tulpn | grep :{PORT} || true")
    if ports.stdout.strip():
        print(f"\n{GREEN}Porta em escuta:{NC}\n{ports.stdout.strip()}")

    print(f"\n{BLUE}{BOLD}============================================================{NC}")
    print(f"{GREEN}{BOLD}   Publicação concluída e validada com sucesso!             {NC}")
    print(f"{BLUE}{BOLD}============================================================{NC}")

if __name__ == "__main__":
    main()
