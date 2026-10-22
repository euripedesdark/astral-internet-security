#!/usr/bin/env rust
use std::fs;
use std::process::Command;

fn run_cmd(cmd: &str) {
    println!("[EXEC] {}", cmd);
    let _ = Command::new("sh").arg("-c").arg(cmd).status();
}

fn main() {
    println!("=== Desinstalador Astral Internet Security ===");
    run_cmd("systemctl stop astral-internet-security || true");
    run_cmd("systemctl disable astral-internet-security || true");
    let _ = fs::remove_file("/etc/systemd/system/astral-internet-security.service");
    let _ = fs::remove_file("/usr/local/bin/astral-internet-security");
    run_cmd("systemctl daemon-reload");
    println!("✓ Astral Internet Security desinstalado com sucesso.");
}
