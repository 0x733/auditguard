use clap::{Parser, Subcommand};
use colored::Colorize;

mod audit;
mod monitor;
mod report;
mod ui;
mod harden;

#[derive(Parser)]
#[command(name = "auditguard")]
#[command(about = "Linux System Security Auditing and Monitoring Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(short, long, default_value = "audit_report.json")]
        output: String,
    },
    Monitor,
    Harden,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { output } => {
            run_scan(&output)?;
        }
        Commands::Monitor => {
            run_monitor().await?;
        }
        Commands::Harden => {
            harden::run_harden()?;
        }
    }

    Ok(())
}

fn run_scan(output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Starting Security Audit Scan...".bold().cyan());
    let result = audit::run_security_audit();
    
    let score_color = if result.score > 80 {
        colored::Color::Green
    } else if result.score > 50 {
        colored::Color::Yellow
    } else {
        colored::Color::Red
    };
    
    println!("Security Audit Score: {}", format!("{}/100", result.score).bold().color(score_color));
    
    println!("\n{}", "--- Summary of Findings ---".bold().yellow());
    println!("SUID/SGID Files Found: {}", result.suid_files.len());
    println!("World Writable Files Found: {}", result.world_writable_files.len());
    println!("Sysctl Issues Found: {}", result.sysctl_issues.len());
    println!("Listening Ports Found: {}", result.listening_ports.len());

    println!("\n{}", "--- Hardware Security & Device Status ---".bold().yellow());
    println!("TPM 2.0 Enabled: {}", if result.hardware.tpm_enabled { "Yes".green() } else { "No".red() });
    println!("EDAC Memory Error Detection Installed: {}", if result.hardware.edac_installed { "Yes".green() } else { "No".yellow() });
    println!("EDAC Errors Logged: {}", if result.hardware.edac_errors > 0 { format!("{}", result.hardware.edac_errors).red() } else { "0".green() });
    println!("Attached USB Devices: {}", result.hardware.usb_devices_count);
    println!("Attached PCI Devices: {}", result.hardware.pci_devices_count);


    if !result.sysctl_issues.is_empty() {
        println!("\n{}", "--- Sysctl Configuration Recommendations ---".bold().red());
        for issue in &result.sysctl_issues {
            println!("  Parameter: {}", issue.parameter.bold());
            println!("    Expected: {}, Actual: {}", issue.expected, issue.actual);
            println!("    Description: {}", issue.description);
        }
    }

    report::save_report(&result, output_path)?;
    println!("\nDetailed security audit report saved to {}", output_path.bold().green());
    Ok(())
}

async fn run_monitor() -> Result<(), Box<dyn std::error::Error>> {
    let result = audit::run_security_audit();
    let mut app = ui::TuiApp::new(result);
    
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    
    monitor::start_process_monitor(tx.clone()).await;
    monitor::start_usb_monitor(tx.clone()).await;
    
    let _watcher = monitor::start_file_monitor(tx.clone())?;
    
    let mut terminal = ratatui::init();
    
    let tick_rate = std::time::Duration::from_millis(100);
    let mut last_tick = std::time::Instant::now();
    
    loop {
        terminal.draw(|f| ui::draw_ui(f, &mut app))?;
        
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| std::time::Duration::from_secs(0));
            
        tokio::select! {
            Some(event) = rx.recv() => {
                let timestamp = chrono::Local::now().format("%H:%M:%S");
                let log = match event {
                    monitor::MonitorEvent::ProcessExec { pid, name, uid } => {
                        format!("[{}] EXEC PID: {} | Name: {} | UID: {}", timestamp, pid, name, uid)
                    }
                    monitor::MonitorEvent::ProcessExit { pid } => {
                        format!("[{}] EXIT PID: {}", timestamp, pid)
                    }
                    monitor::MonitorEvent::FileChange { path, op } => {
                        format!("[{}] FILE {}: {}", timestamp, op, path)
                    }
                    monitor::MonitorEvent::UsbChange { count } => {
                        format!("[{}] USB HW EVENT: Device count changed to {}", timestamp, count)
                    }
                };
                app.monitor_logs.push(log);
                if app.monitor_logs.len() > 100 {
                    app.monitor_logs.remove(0);
                }
            }
            _ = tokio::time::sleep(timeout) => {
                if last_tick.elapsed() >= tick_rate {
                    last_tick = std::time::Instant::now();
                }
            }
        }
        
        if crossterm::event::poll(std::time::Duration::from_secs(0))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                match key.code {
                    crossterm::event::KeyCode::Char('q') => app.should_quit = true,
                    crossterm::event::KeyCode::Tab => app.next_tab(),
                    crossterm::event::KeyCode::Left | crossterm::event::KeyCode::Char('h') => app.prev_tab(),
                    crossterm::event::KeyCode::Right | crossterm::event::KeyCode::Char('l') => app.next_tab(),
                    crossterm::event::KeyCode::Char('1') => app.active_tab = 0,
                    crossterm::event::KeyCode::Char('2') => app.active_tab = 1,
                    crossterm::event::KeyCode::Char('3') => app.active_tab = 2,
                    crossterm::event::KeyCode::Char('4') => app.active_tab = 3,
                    crossterm::event::KeyCode::Down | crossterm::event::KeyCode::Char('j') => app.scroll_down(),
                    crossterm::event::KeyCode::Up | crossterm::event::KeyCode::Char('k') => app.scroll_up(),
                    _ => {}
                }
            }
        }
        
        if app.should_quit {
            break;
        }
    }
    
    ratatui::restore();
    Ok(())
}
