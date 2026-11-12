use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    New,
    Ack,
    Escalated,
    FalsePositive,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::New => "new",
            Status::Ack => "ack",
            Status::Escalated => "escalated",
            Status::FalsePositive => "false+",
        }
    }
    pub fn is_open(self) -> bool {
        matches!(self, Status::New | Status::Ack)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    #[serde(default)]
    pub id: u32,
    /// Seconds since the start of the shift.
    #[serde(default)]
    pub ts: u32,
    pub rule: String,
    pub tactic: String,
    pub technique: String,
    pub severity: Severity,
    pub host: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub detail: String,
    /// Business criticality of the asset, 1 (lab) to 5 (crown jewels).
    #[serde(default = "default_crit")]
    pub criticality: u8,
    #[serde(default)]
    pub intel_hit: bool,
    #[serde(default)]
    pub status: Status,
    #[serde(default)]
    pub playbook: Vec<String>,
}

fn default_crit() -> u8 {
    2
}

/// Parses JSON Lines. Bad lines are skipped and counted so one corrupt record cannot hide the rest.
pub fn parse_jsonl(text: &str) -> (Vec<Alert>, usize) {
    let mut out = Vec::new();
    let mut bad = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match serde_json::from_str::<Alert>(line) {
            Ok(mut a) => {
                a.criticality = a.criticality.clamp(1, 5);
                out.push(a);
            }
            Err(_) => bad += 1,
        }
    }
    for (i, a) in out.iter_mut().enumerate() {
        if a.id == 0 {
            a.id = i as u32 + 1;
        }
    }
    (out, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_good_lines_and_counts_bad_ones() {
        let t = r#"{"rule":"r","tactic":"Execution","technique":"T1059","severity":"high","host":"h"}
not json
{"rule":"r2","tactic":"Impact","technique":"T1486","severity":"critical","host":"h2","criticality":99,"intel_hit":true}

{"rule":"x","severity":"bogus"}"#;
        let (a, bad) = parse_jsonl(t);
        assert_eq!(a.len(), 2);
        assert_eq!(bad, 2);
        assert_eq!(a[0].id, 1);
        assert_eq!(a[0].criticality, 2, "default");
        assert_eq!(a[1].criticality, 5, "clamped");
        assert_eq!(a[1].severity, Severity::Critical);
        assert_eq!(a[0].status, Status::New);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High && Severity::Low < Severity::Medium);
        assert!(
            Status::Ack.is_open()
                && !Status::FalsePositive.is_open()
                && !Status::Escalated.is_open()
        );
    }
}
