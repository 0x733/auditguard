use std::fs::File;
use std::io::{self, Write};
use std::process::Command;
use colored::Colorize;
use crate::audit;

pub fn run_harden() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Starting System Security Hardening...".bold().cyan());

    if nix::unistd::Uid::effective().is_root() == false {
        println!("{}", "Error: Hardening operations require root privileges. Please run with sudo.".bold().red());
        return Ok(());
    }

    harden_sysctl()?;
    harden_suid_files()?;
    harden_network_ports()?;

    println!("\n{}", "System Hardening completed successfully.".bold().green());
    Ok(())
}

fn harden_sysctl() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "--- Hardening Kernel Sysctl Parameters ---".bold().yellow());
    
    let config_path = "/etc/sysctl.d/99-auditguard.conf";
    let content = "fs.protected_symlinks=1\n\
                   fs.protected_hardlinks=1\n\
                   kernel.kptr_restrict=2\n\
                   kernel.randomize_va_space=2\n\
                   kernel.yama.ptrace_scope=1\n";

    let mut file = File::create(config_path)?;
    file.write_all(content.as_bytes())?;
    println!("Security configurations written to {}", config_path.bold().blue());

    let output = Command::new("sysctl")
        .arg("--system")
        .output()?;

    if output.status.success() {
        println!("{}", "Sysctl parameters applied successfully.".green());
    } else {
        println!("{}", "Warning: Failed to apply sysctl parameters automatically.".red());
    }

    Ok(())
}

fn harden_suid_files() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "--- Reviewing SUID/SGID Privilege Risks ---".bold().yellow());
    let result = audit::run_security_audit();
    
    let dangerous_suid_candidates = [
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/bin/newgrp",
        "/usr/bin/write",
        "/bin/write",
    ];

    let mut found_to_harden = Vec::new();
    for path in &dangerous_suid_candidates {
        if result.suid_files.contains(&path.to_string()) {
            found_to_harden.push(path.to_string());
        }
    }

    if found_to_harden.is_empty() {
        println!("{}", "No redundant SUID/SGID files found to harden.".green());
        return Ok(());
    }

    println!("The following non-essential SUID/SGID binaries were found:");
    for path in &found_to_harden {
        println!("  - {}", path.bold().red());
    }

    print!("Do you want to disable SUID/SGID bit for these files? (y/N): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input == "y" || input == "yes" {
        for path in &found_to_harden {
            let output = Command::new("chmod")
                .arg("u-s")
                .arg("g-s")
                .arg(path)
                .output()?;
            if output.status.success() {
                println!("Successfully disabled SUID/SGID on {}", path.green());
            } else {
                println!("Failed to change permissions on {}", path.red());
            }
        }
    } else {
        println!("{}", "Skipped SUID hardening.".yellow());
    }

    Ok(())
}

fn harden_network_ports() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "--- Reviewing Listening Network Services ---".bold().yellow());
    let result = audit::run_security_audit();

    let unpriv_ports: Vec<&audit::ListeningPort> = result.listening_ports.iter()
        .filter(|p| p.port > 1024)
        .collect();

    if unpriv_ports.is_empty() {
        println!("{}", "No unprivileged listening services found to harden.".green());
        return Ok(());
    }

    println!("Found {} active unprivileged listening services (>1024):", unpriv_ports.len());
    for p in &unpriv_ports {
        println!("  - Protocol: {} | IP: {} | Port: {}", p.protocol.bold(), p.ip, p.port.to_string().bold().red());
    }

    println!("\nSuggestions for ports:");
    println!("  1. Block incoming traffic using iptables/ufw.");
    println!("  2. Manually kill process using: kill $(lsof -t -i :<port>)");
    
    print!("Would you like to generate ufw block rules for these ports? (y/N): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input == "y" || input == "yes" {
        for p in &unpriv_ports {
            let output = Command::new("ufw")
                .arg("deny")
                .arg(&p.port.to_string())
                .output()?;
            if output.status.success() {
                println!("Successfully blocked port {} with UFW.", p.port.to_string().green());
            } else {
                println!("Failed to configure UFW for port {}. Is UFW installed?", p.port.to_string().red());
            }
        }
    } else {
        println!("{}", "Skipped UFW port blocking.".yellow());
    }

    Ok(())
}
