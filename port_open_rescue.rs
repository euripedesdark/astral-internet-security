#!/usr/bin/env rust
use std::process::Command;

const PORTS: &[u16] = &[8040, 5001, 9090, 8081, 5432, 5173, 5000, 3000, 443, 80, 22];

fn run_cmd(cmd: &str) {
    println!("[RUN] {}", cmd);
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status();
    match status {
        Ok(s) if s.success() => {},
        Ok(s) => eprintln!("[AVISO] Código de saída não-zero: {:?}", s.code()),
        Err(e) => eprintln!("[ERRO] Falha ao executar: {}", e),
    }
}

fn main() {
    println!("=== Astral Rescue: Restaurando Acesso de Portas e IPTables em Rust ===");
    println!("Limpando tabelas do firewall...");
    run_cmd("iptables -F");
    run_cmd("iptables -X");
    run_cmd("iptables -t nat -F");
    run_cmd("iptables -t nat -X");
    run_cmd("iptables -t mangle -F");
    run_cmd("iptables -t mangle -X");
    run_cmd("iptables -P INPUT ACCEPT");
    run_cmd("iptables -P FORWARD ACCEPT");
    run_cmd("iptables -P OUTPUT ACCEPT");

    println!("Liberando portas necessárias...");
    for &port in PORTS {
        run_cmd(&format!("iptables -A INPUT -p tcp --dport {} -j ACCEPT", port));
        run_cmd(&format!("iptables -A INPUT -p udp --dport {} -j ACCEPT", port));
    }

    println!("Habilitando Masquerade na interface eth0...");
    run_cmd("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE");
    println!("✓ Sucesso: Regras de emergência aplicadas via Rust!");
}
