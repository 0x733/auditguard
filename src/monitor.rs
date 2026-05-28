use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use sysinfo::System;
use notify::{Watcher, RecursiveMode, EventKind};

#[derive(Clone, Debug)]
pub enum MonitorEvent {
    ProcessExec { pid: u32, name: String, uid: u32 },
    ProcessExit { pid: u32 },
    FileChange { path: String, op: String },
    UsbChange { count: usize },
}


pub async fn start_process_monitor(tx: UnboundedSender<MonitorEvent>) {
    tokio::spawn(async move {
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut active_pids: HashSet<u32> = sys.processes().keys().map(|pid| pid.as_u32()).collect();

        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            sys.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::All,
                true,
                sysinfo::ProcessRefreshKind::nothing()
            );
            
            let current_pids: HashSet<u32> = sys.processes().keys().map(|pid| pid.as_u32()).collect();

            for &pid in &current_pids {
                if !active_pids.contains(&pid) {
                    if let Some(p) = sys.process(sysinfo::Pid::from(pid as usize)) {
                        let name = p.name().to_string_lossy().to_string();
                        let mut uid = 0;
                        if let Ok(metadata) = std::fs::metadata(format!("/proc/{}", pid)) {
                            uid = metadata.uid();
                        }
                        let _ = tx.send(MonitorEvent::ProcessExec { pid, name, uid });
                    }
                }
            }

            for &pid in &active_pids {
                if !current_pids.contains(&pid) {
                    let _ = tx.send(MonitorEvent::ProcessExit { pid });
                }
            }

            active_pids = current_pids;
        }
    });
}

pub fn start_file_monitor(tx: UnboundedSender<MonitorEvent>) -> Result<notify::RecommendedWatcher, notify::Error> {
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        if let Ok(event) = res {
            let op = match event.kind {
                EventKind::Create(_) => "CREATE",
                EventKind::Modify(_) => "MODIFY",
                EventKind::Remove(_) => "REMOVE",
                _ => "ACCESS",
            };
            for path in event.paths {
                let path_str = path.to_string_lossy().to_string();
                let _ = tx.send(MonitorEvent::FileChange {
                    path: path_str,
                    op: op.to_string(),
                });
            }
        }
    })?;

    let critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/resolv.conf"];
    for &p in &critical_paths {
        if Path::new(p).exists() {
            let _ = watcher.watch(Path::new(p), RecursiveMode::NonRecursive);
        }
    }

    Ok(watcher)
}

pub async fn start_usb_monitor(tx: UnboundedSender<MonitorEvent>) {
    tokio::spawn(async move {
        let mut last_count = 0;
        if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
            last_count = entries.count();
        }
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
                let count = entries.count();
                if count != last_count {
                    let _ = tx.send(MonitorEvent::UsbChange { count });
                    last_count = count;
                }
            }
        }
    });
}

