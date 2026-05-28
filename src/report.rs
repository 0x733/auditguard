use std::fs::File;
use std::io::Write;
use crate::audit::AuditResult;
use anyhow::Result;

pub fn save_report(result: &AuditResult, path: &str) -> Result<()> {
    let json_data = serde_json::to_string_pretty(result)?;
    let mut file = File::create(path)?;
    file.write_all(json_data.as_bytes())?;
    Ok(())
}
