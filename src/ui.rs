use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Tabs},
    Frame,
};
use crate::audit::AuditResult;

pub struct TuiApp {
    pub audit_result: AuditResult,
    pub monitor_logs: Vec<String>,
    pub active_tab: usize,
    pub should_quit: bool,
    pub sysctl_state: ListState,
    pub ports_state: ListState,
    pub suid_state: ListState,
}

impl TuiApp {
    pub fn new(result: AuditResult) -> Self {
        let mut sysctl_state = ListState::default();
        sysctl_state.select(Some(0));
        let mut ports_state = ListState::default();
        ports_state.select(Some(0));
        let mut suid_state = ListState::default();
        suid_state.select(Some(0));

        Self {
            audit_result: result,
            monitor_logs: vec!["System monitor initialized.".to_string()],
            active_tab: 0,
            should_quit: false,
            sysctl_state,
            ports_state,
            suid_state,
        }
    }

    pub fn next_tab(&mut self) {
        self.active_tab = (self.active_tab + 1) % 4;
    }

    pub fn prev_tab(&mut self) {
        if self.active_tab == 0 {
            self.active_tab = 3;
        } else {
            self.active_tab -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        match self.active_tab {
            1 => {
                let count = self.audit_result.sysctl_issues.len();
                if count > 0 {
                    let i = match self.sysctl_state.selected() {
                        Some(i) => if i >= count - 1 { 0 } else { i + 1 },
                        None => 0,
                    };
                    self.sysctl_state.select(Some(i));
                }
            }
            2 => {
                let count = self.audit_result.listening_ports.len();
                if count > 0 {
                    let i = match self.ports_state.selected() {
                        Some(i) => if i >= count - 1 { 0 } else { i + 1 },
                        None => 0,
                    };
                    self.ports_state.select(Some(i));
                }
            }
            3 => {
                let count = self.audit_result.suid_files.len();
                if count > 0 {
                    let i = match self.suid_state.selected() {
                        Some(i) => if i >= count - 1 { 0 } else { i + 1 },
                        None => 0,
                    };
                    self.suid_state.select(Some(i));
                }
            }
            _ => {}
        }
    }

    pub fn scroll_up(&mut self) {
        match self.active_tab {
            1 => {
                let count = self.audit_result.sysctl_issues.len();
                if count > 0 {
                    let i = match self.sysctl_state.selected() {
                        Some(i) => if i == 0 { count - 1 } else { i - 1 },
                        None => 0,
                    };
                    self.sysctl_state.select(Some(i));
                }
            }
            2 => {
                let count = self.audit_result.listening_ports.len();
                if count > 0 {
                    let i = match self.ports_state.selected() {
                        Some(i) => if i == 0 { count - 1 } else { i - 1 },
                        None => 0,
                    };
                    self.ports_state.select(Some(i));
                }
            }
            3 => {
                let count = self.audit_result.suid_files.len();
                if count > 0 {
                    let i = match self.suid_state.selected() {
                        Some(i) => if i == 0 { count - 1 } else { i - 1 },
                        None => 0,
                    };
                    self.suid_state.select(Some(i));
                }
            }
            _ => {}
        }
    }
}

pub fn draw_ui(f: &mut Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    let score = app.audit_result.score;
    let score_color = if score > 80 {
        Color::Green
    } else if score > 50 {
        Color::Yellow
    } else {
        Color::Red
    };

    let score_gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Security Health Score "))
        .gauge_style(Style::default().fg(score_color))
        .percent(score as u16)
        .label(format!("{}/100", score));
    f.render_widget(score_gauge, chunks[0]);

    let tab_titles = vec!["[1] Overview & Logs", "[2] Sysctl Kernel", "[3] Open Ports", "[4] SUID/SGID Files"];
    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title(" Navigation Tabs "))
        .select(app.active_tab)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[1]);

    match app.active_tab {
        0 => {
            let inner_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(chunks[2]);

            let hw = &app.audit_result.hardware;
            let issues_summary = vec![
                ListItem::new(format!(" SUID/SGID Binary Files: {}", app.audit_result.suid_files.len())),
                ListItem::new(format!(" World Writable System Files: {}", app.audit_result.world_writable_files.len())),
                ListItem::new(format!(" Failed Sysctl Configuration Settings: {}", app.audit_result.sysctl_issues.len())),
                ListItem::new(format!(" Total Listening Network Services: {}", app.audit_result.listening_ports.len())),
                ListItem::new(""),
                ListItem::new(format!(" TPM 2.0 Security State: {}", if hw.tpm_enabled { "ENABLED" } else { "DISABLED / NOT FOUND" })),
                ListItem::new(format!(" EDAC RAM Error Check: {}", if hw.edac_installed { "ACTIVE" } else { "INACTIVE / NO ECC" })),
                ListItem::new(format!(" Memory Errors Logged: {}", hw.edac_errors)),
                ListItem::new(format!(" Connected USB Devices: {}", hw.usb_devices_count)),
                ListItem::new(format!(" Connected PCI Devices: {}", hw.pci_devices_count)),
            ];
            let summary_list = List::new(issues_summary)
                .block(Block::default().borders(Borders::ALL).title(" Security Scan Summary & Hardware Status "));
            f.render_widget(summary_list, inner_chunks[0]);

            let log_items: Vec<ListItem> = app.monitor_logs
                .iter()
                .rev()
                .take(inner_chunks[1].height as usize)
                .map(|log| ListItem::new(log.as_str()))
                .collect();
            let logs_list = List::new(log_items)
                .block(Block::default().borders(Borders::ALL).title(" Real-time Security Audit Log Monitor "));
            f.render_widget(logs_list, inner_chunks[1]);
        }
        1 => {
            let items: Vec<ListItem> = app.audit_result.sysctl_issues
                .iter()
                .map(|issue| {
                    ListItem::new(format!(
                        " {} | Expected: {} | Actual: {} | {}",
                        issue.parameter,
                        issue.expected,
                        issue.actual,
                        issue.description
                    ))
                })
                .collect();

            let sysctl_list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Sysctl Security Parameters Audit Failed Items "))
                .highlight_style(Style::default().bg(Color::Indexed(236)).fg(Color::White).add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");
            f.render_stateful_widget(sysctl_list, chunks[2], &mut app.sysctl_state);
        }
        2 => {
            let items: Vec<ListItem> = app.audit_result.listening_ports
                .iter()
                .map(|p| {
                    ListItem::new(format!(
                        " {:<8} | {:<20} | Port: {} ",
                        p.protocol,
                        p.ip,
                        p.port
                    ))
                })
                .collect();

            let ports_list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Active Listening Ports & Protocols "))
                .highlight_style(Style::default().bg(Color::Indexed(236)).fg(Color::White).add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");
            f.render_stateful_widget(ports_list, chunks[2], &mut app.ports_state);
        }
        3 => {
            let items: Vec<ListItem> = app.audit_result.suid_files
                .iter()
                .map(|f| ListItem::new(format!(" {}", f)))
                .collect();

            let suid_list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Found SUID/SGID Privilege Escalation Target Files "))
                .highlight_style(Style::default().bg(Color::Indexed(236)).fg(Color::White).add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");
            f.render_stateful_widget(suid_list, chunks[2], &mut app.suid_state);
        }
        _ => {}
    }

    let help_text = " q: Quit | Tab: Cycle tabs | 1-4: Select tabs | j/k or Up/Down: Scroll list views";
    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title(" Quick Shortcuts & Guide "));
    f.render_widget(help_paragraph, chunks[3]);
}
