//! Risk scoring with explanations. Every point of the score comes with a reason the analyst can read.

use crate::model::{Alert, Severity};
use std::collections::HashSet;

pub const CORRELATION_WINDOW: u32 = 600; // seconds

pub struct Score {
    pub value: u32,
    pub reasons: Vec<String>,
}

impl Score {
    pub fn priority(&self) -> &'static str {
        match self.value {
            80.. => "P1",
            60..=79 => "P2",
            40..=59 => "P3",
            _ => "P4",
        }
    }
}

pub fn score(a: &Alert, all: &[Alert]) -> Score {
    let (base, name) = match a.severity {
        Severity::Low => (15, "low"),
        Severity::Medium => (35, "medium"),
        Severity::High => (55, "high"),
        Severity::Critical => (75, "critical"),
    };
    let mut value = base;
    let mut reasons = vec![format!("+{base} {name} severity rule")];
    let crit = a.criticality.clamp(1, 5) as u32;
    if crit >= 3 {
        let pts = (crit - 2) * 3;
        value += pts;
        reasons.push(format!("+{pts} asset criticality {crit}/5 ({})", a.host));
    }
    if a.intel_hit {
        value += 10;
        reasons.push("+10 source matches threat intelligence".into());
    }
    let same_host: Vec<&Alert> = all
        .iter()
        .filter(|o| o.host == a.host && o.id != a.id && o.ts.abs_diff(a.ts) <= CORRELATION_WINDOW)
        .collect();
    if same_host.len() >= 2 {
        value += 8;
        reasons.push(format!(
            "+8 {} other alerts on {} within 10 minutes",
            same_host.len(),
            a.host
        ));
    }
    let tactics: HashSet<&str> = same_host
        .iter()
        .map(|o| o.tactic.as_str())
        .chain([a.tactic.as_str()])
        .collect();
    if tactics.len() >= 3 {
        value += 12;
        reasons.push(format!(
            "+12 kill chain: {} distinct tactics on one host",
            tactics.len()
        ));
    }
    Score {
        value: value.min(100),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;

    fn alert(id: u32, ts: u32, host: &str, tactic: &str, sev: Severity) -> Alert {
        Alert {
            id,
            ts,
            rule: "r".into(),
            tactic: tactic.into(),
            technique: "T0".into(),
            severity: sev,
            host: host.into(),
            user: String::new(),
            src_ip: String::new(),
            detail: String::new(),
            criticality: 1,
            intel_hit: false,
            status: Status::New,
            playbook: vec![],
        }
    }

    #[test]
    fn base_score_follows_severity() {
        let a = alert(1, 0, "h", "x", Severity::Low);
        assert_eq!(score(&a, std::slice::from_ref(&a)).value, 15);
        let c = alert(1, 0, "h", "x", Severity::Critical);
        assert_eq!(score(&c, std::slice::from_ref(&c)).value, 75);
    }

    #[test]
    fn asset_criticality_and_intel_add_points_with_reasons() {
        let mut a = alert(1, 0, "dc-01", "x", Severity::High);
        a.criticality = 5;
        a.intel_hit = true;
        let s = score(&a, std::slice::from_ref(&a));
        assert_eq!(s.value, 55 + 9 + 10);
        assert!(
            s.reasons
                .iter()
                .any(|r| r.contains("asset criticality 5/5"))
                && s.reasons.iter().any(|r| r.contains("threat intelligence"))
        );
        assert_eq!(s.priority(), "P2");
    }

    #[test]
    fn same_host_burst_and_kill_chain_raise_the_score() {
        let all = vec![
            alert(1, 0, "h", "Initial Access", Severity::Medium),
            alert(2, 100, "h", "Execution", Severity::Medium),
            alert(3, 200, "h", "Persistence", Severity::Medium),
            alert(4, 200, "other", "Persistence", Severity::Medium),
        ];
        let s = score(&all[2], &all);
        assert_eq!(s.value, 35 + 8 + 12);
        assert!(s.reasons.iter().any(|r| r.contains("kill chain: 3")));
        assert_eq!(
            score(&all[3], &all).value,
            35,
            "a different host is not correlated"
        );
    }

    #[test]
    fn alerts_outside_the_window_do_not_correlate() {
        let all = vec![
            alert(1, 0, "h", "a", Severity::Low),
            alert(2, 5000, "h", "b", Severity::Low),
            alert(3, 9000, "h", "c", Severity::Low),
        ];
        assert_eq!(score(&all[1], &all).value, 15);
    }

    #[test]
    fn score_is_capped_and_priority_bands() {
        let mut a = alert(1, 0, "h", "a", Severity::Critical);
        a.criticality = 5;
        a.intel_hit = true;
        let mut all = vec![a.clone()];
        for (i, t) in ["b", "c", "d"].iter().enumerate() {
            all.push(alert(10 + i as u32, 10, "h", t, Severity::High));
        }
        let s = score(&a, &all);
        assert_eq!(s.value, 100);
        assert_eq!(s.priority(), "P1");
        assert_eq!(
            Score {
                value: 59,
                reasons: vec![]
            }
            .priority(),
            "P3"
        );
        assert_eq!(
            Score {
                value: 10,
                reasons: vec![]
            }
            .priority(),
            "P4"
        );
    }
}
