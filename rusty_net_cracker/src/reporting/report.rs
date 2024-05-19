use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub credentials: String,
    pub success: bool,
}

pub fn generate_report(report: &Report) {
    let json = serde_json::to_string(report).unwrap();
    std::fs::write("report.json", json).unwrap();
}
