#!/usr/bin/env rust
use std::process::Command;

fn check_service(name: &str) {
    let out = Command::new("systemctl")
        .args(["is-active", name])
        .output();
    match out {
        Ok(o) => {
            let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
            println!("[STATUS] {} -> {}", name, status);
        },
        Err(e) => eprintln!("[ERRO] Não foi possível checar {}: {}", name, e),
    }
}

fn main() {
    println!("=== Verificação de Saúde do Astral Internet Security ===");
    check_service("astral-internet-security");
    println!("Verificando regras de iptables...");
    let _ = Command::new("iptables").args(["-L", "-n"]).status();
    println!("✓ Diagnóstico completo!");
}
