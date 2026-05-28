use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditResult {
    pub score: u32,
    pub suid_files: Vec<String>,
    pub world_writable_files: Vec<String>,
    pub sysctl_issues: Vec<SysctlIssue>,
    pub listening_ports: Vec<ListeningPort>,
    pub hardware: HardwareStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HardwareStatus {
    pub tpm_enabled: bool,
    pub edac_installed: bool,
    pub edac_errors: u64,
    pub usb_devices_count: usize,
    pub pci_devices_count: usize,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SysctlIssue {
    pub parameter: String,
    pub expected: String,
    pub actual: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ListeningPort {
    pub protocol: String,
    pub ip: String,
    pub port: u16,
}

pub fn run_security_audit() -> AuditResult {
    let mut suid_files = Vec::new();
    let mut world_writable_files = Vec::new();
    let mut sysctl_issues = Vec::new();
    let mut listening_ports = Vec::new();

    scan_suid_sgid(&mut suid_files);
    scan_world_writable(&mut world_writable_files);
    check_sysctl_security(&mut sysctl_issues);
    audit_network_ports(&mut listening_ports);
    let hardware = check_hardware_status();

    let mut score: u32 = 100;
    
    if suid_files.len() > 20 {
        score = score.saturating_sub(10);
    }
    
    if !world_writable_files.is_empty() {
        score = score.saturating_sub(20);
    }
    
    let sysctl_penalty = (sysctl_issues.len() as u32) * 15;
    score = score.saturating_sub(sysctl_penalty);
    
    let unpriv_ports = listening_ports.iter().filter(|p| p.port > 1024).count() as u32;
    if unpriv_ports > 5 {
        score = score.saturating_sub(10);
    }

    AuditResult {
        score,
        suid_files,
        world_writable_files,
        sysctl_issues,
        listening_ports,
        hardware,
    }
}

fn check_hardware_status() -> HardwareStatus {
    let tpm_enabled = PathBuf::from("/sys/class/tpm/tpm0").exists() || PathBuf::from("/dev/tpm0").exists();
    let edac_path = PathBuf::from("/sys/devices/system/edac/mc");
    let edac_installed = edac_path.exists();
    let mut edac_errors = 0;
    if edac_installed {
        if let Ok(entries) = fs::read_dir(&edac_path) {
            for entry in entries.flatten() {
                let p = entry.path().join("ce_count");
                if p.exists() {
                    if let Ok(content) = fs::read_to_string(p) {
                        if let Ok(val) = content.trim().parse::<u64>() {
                            edac_errors += val;
                        }
                    }
                }
                let p_ue = entry.path().join("ue_count");
                if p_ue.exists() {
                    if let Ok(content) = fs::read_to_string(p_ue) {
                        if let Ok(val) = content.trim().parse::<u64>() {
                            edac_errors += val;
                        }
                    }
                }
            }
        }
    }
    let mut usb_devices_count = 0;
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        usb_devices_count = entries.count();
    }
    let mut pci_devices_count = 0;
    if let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") {
        pci_devices_count = entries.count();
    }
    HardwareStatus {
        tpm_enabled,
        edac_installed,
        edac_errors,
        usb_devices_count,
        pci_devices_count,
    }
}


fn scan_suid_sgid(list: &mut Vec<String>) {
    let paths_to_scan = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];
    for path in &paths_to_scan {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if let Ok(metadata) = entry_path.metadata() {
                    let mode = metadata.mode();
                    let is_suid = (mode & libc::S_ISUID as u32) != 0;
                    let is_sgid = (mode & libc::S_ISGID as u32) != 0;
                    if is_suid || is_sgid {
                        list.push(entry_path.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
}

fn scan_world_writable(list: &mut Vec<String>) {
    let paths_to_scan = ["/etc", "/opt", "/var/tmp", "/tmp"];
    for path in &paths_to_scan {
        let mut stack = vec![PathBuf::from(path)];
        let mut count = 0;
        while let Some(current_path) = stack.pop() {
            count += 1;
            if count > 500 {
                break;
            }
            if let Ok(entries) = fs::read_dir(&current_path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if let Ok(metadata) = entry_path.symlink_metadata() {
                        let mode = metadata.mode();
                        let is_dir = metadata.is_dir();
                        let is_file = metadata.is_file();
                        
                        if is_file && (mode & 0o002) != 0 {
                            list.push(entry_path.to_string_lossy().to_string());
                        }
                        
                        if is_dir && !entry_path.starts_with("/tmp") && !entry_path.starts_with("/var/tmp") {
                            stack.push(entry_path);
                        }
                    }
                }
            }
        }
    }
}

fn check_sysctl_security(issues: &mut Vec<SysctlIssue>) {
    let checks = [
        (
            "/proc/sys/fs/protected_symlinks",
            "1",
            "fs.protected_symlinks",
            "Protects symlink traversal against arbitrary file access."
        ),
        (
            "/proc/sys/fs/protected_hardlinks",
            "1",
            "fs.protected_hardlinks",
            "Protects hardlink creation permissions."
        ),
        (
            "/proc/sys/kernel/kptr_restrict",
            "2",
            "kernel.kptr_restrict",
            "Restricts access to raw kernel memory pointers."
        ),
        (
            "/proc/sys/kernel/randomize_va_space",
            "2",
            "kernel.randomize_va_space",
            "Enables Address Space Layout Randomization (ASLR)."
        ),
        (
            "/proc/sys/kernel/yama/ptrace_scope",
            "1",
            "kernel.yama.ptrace_scope",
            "Restricts ptrace processes relationships."
        )
    ];

    for &(path, expected, param, desc) in &checks {
        if let Ok(val) = fs::read_to_string(path) {
            let actual = val.trim();
            if actual != expected {
                issues.push(SysctlIssue {
                    parameter: param.to_string(),
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                    description: desc.to_string(),
                });
            }
        }
    }
}

fn audit_network_ports(ports: &mut Vec<ListeningPort>) {
    if let Ok(file) = File::open("/proc/net/tcp") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1).flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                let local = parts[1];
                let state = parts[3];
                if state == "0A" {
                    if let Some(port_info) = parse_proc_net_address(local, "TCP") {
                        ports.push(port_info);
                    }
                }
            }
        }
    }

    if let Ok(file) = File::open("/proc/net/udp") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1).flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                let local = parts[1];
                let state = parts[3];
                if state == "07" {
                    if let Some(port_info) = parse_proc_net_address(local, "UDP") {
                        ports.push(port_info);
                    }
                }
            }
        }
    }
}

fn parse_proc_net_address(addr_hex: &str, protocol: &str) -> Option<ListeningPort> {
    let parts: Vec<&str> = addr_hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let ip_hex = parts[0];
    let port_hex = parts[1];
    
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    
    if ip_hex.len() == 8 {
        let ip_val = u32::from_str_radix(ip_hex, 16).ok()?;
        let bytes = ip_val.to_le_bytes();
        let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
        return Some(ListeningPort {
            protocol: protocol.to_string(),
            ip,
            port,
        });
    }
    
    None
}
