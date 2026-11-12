//! Deterministic alert generator so the console can be demoed and tested without a SIEM.

use crate::model::{Alert, Severity, Status};

pub struct Rng(pub u64);
impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

struct Tpl {
    rule: &'static str,
    tactic: &'static str,
    technique: &'static str,
    sev: Severity,
    detail: &'static str,
    playbook: [&'static str; 3],
    weight: usize,
}

const TPLS: &[Tpl] = &[
    Tpl {
        rule: "SSH brute force",
        tactic: "Credential Access",
        technique: "T1110.001",
        sev: Severity::Medium,
        detail: "{n} failed logins from {ip} in 60 seconds, then 1 success",
        playbook: [
            "Block the source at the perimeter",
            "Check the successful login for follow-up activity",
            "Force a password reset for the account",
        ],
        weight: 8,
    },
    Tpl {
        rule: "Impossible travel",
        tactic: "Initial Access",
        technique: "T1078",
        sev: Severity::High,
        detail: "Logins from two countries {n} minutes apart",
        playbook: [
            "Revoke active sessions",
            "Confirm with the user out of band",
            "Review mailbox rules created today",
        ],
        weight: 5,
    },
    Tpl {
        rule: "Encoded PowerShell",
        tactic: "Execution",
        technique: "T1059.001",
        sev: Severity::High,
        detail: "powershell -enc with a {n} KB base64 payload spawned by winword.exe",
        playbook: [
            "Isolate the host",
            "Decode the payload and extract IOCs",
            "Hunt the parent document across mailboxes",
        ],
        weight: 5,
    },
    Tpl {
        rule: "New local administrator",
        tactic: "Persistence",
        technique: "T1136.001",
        sev: Severity::High,
        detail: "Account svc_upd{n} added to local Administrators",
        playbook: [
            "Disable the account",
            "Find who created it and from where",
            "Check for scheduled tasks and services",
        ],
        weight: 3,
    },
    Tpl {
        rule: "Ransomware canary modified",
        tactic: "Impact",
        technique: "T1486",
        sev: Severity::Critical,
        detail: "{n} canary files renamed with an unknown extension",
        playbook: [
            "Isolate the host from the network now",
            "Snapshot memory if possible",
            "Invoke the ransomware runbook and notify the incident lead",
        ],
        weight: 1,
    },
    Tpl {
        rule: "LSASS memory access",
        tactic: "Credential Access",
        technique: "T1003.001",
        sev: Severity::Critical,
        detail: "Process opened lsass.exe with PROCESS_VM_READ ({n} handles)",
        playbook: [
            "Isolate the host",
            "Reset credentials of every user logged on",
            "Check for lateral movement from this host",
        ],
        weight: 2,
    },
    Tpl {
        rule: "DNS tunneling suspected",
        tactic: "Command and Control",
        technique: "T1071.004",
        sev: Severity::Medium,
        detail: "{n} TXT queries with high-entropy labels to one domain",
        playbook: [
            "Sinkhole the domain",
            "Identify the process generating the queries",
            "Review data volume sent",
        ],
        weight: 4,
    },
    Tpl {
        rule: "Cloud key used from new country",
        tactic: "Initial Access",
        technique: "T1078.004",
        sev: Severity::High,
        detail: "Access key used from {ip}, never seen before ({n} API calls)",
        playbook: [
            "Deactivate the key",
            "Review CloudTrail for the last 24 hours",
            "Rotate every secret the role can read",
        ],
        weight: 3,
    },
    Tpl {
        rule: "Large outbound transfer",
        tactic: "Exfiltration",
        technique: "T1048",
        sev: Severity::Medium,
        detail: "{n} GB sent to a rarely seen ASN in one hour",
        playbook: [
            "Identify the data source",
            "Check the destination reputation",
            "Engage the data owner",
        ],
        weight: 3,
    },
    Tpl {
        rule: "Internal port scan",
        tactic: "Discovery",
        technique: "T1046",
        sev: Severity::Low,
        detail: "{n} hosts probed on 445 and 3389 within two minutes",
        playbook: [
            "Identify the scanning process",
            "Confirm whether it is an approved vulnerability scan",
            "Block the host if the scan is not approved",
        ],
        weight: 8,
    },
    Tpl {
        rule: "Phishing link clicked",
        tactic: "Initial Access",
        technique: "T1566.002",
        sev: Severity::Medium,
        detail: "User opened a URL flagged by {n} reputation feeds",
        playbook: [
            "Purge the message from all mailboxes",
            "Check proxy logs for credential posts",
            "Reset the password if the form was submitted",
        ],
        weight: 6,
    },
    Tpl {
        rule: "MFA fatigue",
        tactic: "Credential Access",
        technique: "T1621",
        sev: Severity::Medium,
        detail: "{n} push prompts denied then one approved",
        playbook: [
            "Call the user",
            "Revoke sessions",
            "Review sign-ins after the approval",
        ],
        weight: 4,
    },
];

/// (host, criticality)
const HOSTS: &[(&str, u8)] = &[
    ("dc-01", 5),
    ("db-prod-01", 5),
    ("backup-01", 4),
    ("web-01", 3),
    ("web-02", 3),
    ("vpn-gw", 4),
    ("fin-ws-12", 3),
    ("hr-ws-04", 2),
    ("jump-01", 4),
    ("dev-ws-33", 1),
    ("print-02", 1),
];
const USERS: &[&str] = &[
    "a.silva",
    "m.garcia",
    "j.lopez",
    "svc_backup",
    "admin",
    "l.fernandez",
    "r.santos",
    "root",
];

pub struct Generator {
    rng: Rng,
    next_id: u32,
    focus: Option<(usize, u8)>, // host index and alerts left in the "campaign"
}

impl Generator {
    pub fn new(seed: u64) -> Self {
        Generator {
            rng: Rng(seed),
            next_id: 1,
            focus: None,
        }
    }

    /// How many alerts arrive this tick. Quiet most of the time, busier during a campaign.
    pub fn arrivals(&mut self) -> usize {
        let base = match self.rng.below(20) {
            0..=4 => 0,
            5..=13 => 1,
            14..=17 => 2,
            _ => 4,
        };
        base + usize::from(self.focus.is_some())
    }

    pub fn next(&mut self, ts: u32) -> Alert {
        // About one alert in five starts a campaign: several alerts on one host, which the
        // correlation logic should surface.
        let host_idx = match self.focus {
            Some((h, left)) if left > 0 => {
                self.focus = Some((h, left - 1));
                h
            }
            _ => {
                let h = self.rng.below(HOSTS.len());
                self.focus = (self.rng.below(5) == 0).then(|| (h, 3 + self.rng.below(4) as u8));
                h
            }
        };
        let total: usize = TPLS.iter().map(|t| t.weight).sum();
        let mut pick = self.rng.below(total);
        let tpl = TPLS
            .iter()
            .find(|t| {
                if pick < t.weight {
                    true
                } else {
                    pick -= t.weight;
                    false
                }
            })
            .unwrap_or(&TPLS[0]);
        let ip = format!(
            "{}.{}",
            ["192.0.2", "198.51.100", "203.0.113"][self.rng.below(3)],
            1 + self.rng.below(254)
        );
        let n = 2 + self.rng.below(40);
        let id = self.next_id;
        self.next_id += 1;
        Alert {
            id,
            ts,
            rule: tpl.rule.into(),
            tactic: tpl.tactic.into(),
            technique: tpl.technique.into(),
            severity: tpl.sev,
            host: HOSTS[host_idx].0.into(),
            user: USERS[self.rng.below(USERS.len())].into(),
            detail: tpl
                .detail
                .replace("{n}", &n.to_string())
                .replace("{ip}", &ip),
            src_ip: ip,
            criticality: HOSTS[host_idx].1,
            intel_hit: self.rng.below(6) == 0,
            status: Status::New,
            playbook: tpl.playbook.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_a_seed_and_different_across_seeds() {
        let run = |s| {
            let mut g = Generator::new(s);
            (0..30).map(|i| g.next(i).detail).collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7));
        assert_ne!(run(7), run(8));
    }

    #[test]
    fn alerts_are_well_formed_and_documentation_ips_only() {
        let mut g = Generator::new(1);
        for i in 0..500 {
            let a = g.next(i);
            assert_eq!(a.id, i + 1);
            assert!(
                !a.detail.contains('{'),
                "unresolved placeholder: {}",
                a.detail
            );
            assert!(a.playbook.len() >= 2 && (1..=5).contains(&a.criticality));
            assert!(
                ["192.0.2.", "198.51.100.", "203.0.113."]
                    .iter()
                    .any(|p| a.src_ip.starts_with(p)),
                "{}",
                a.src_ip
            );
        }
    }

    #[test]
    fn campaigns_repeat_hosts() {
        let mut g = Generator::new(3);
        let hosts: Vec<_> = (0..200).map(|i| g.next(i).host).collect();
        assert!(
            hosts.windows(3).any(|w| w[0] == w[1] && w[1] == w[2]),
            "expected same-host runs"
        );
    }

    #[test]
    fn rng_below_stays_in_range() {
        let mut r = Rng(0);
        assert!((0..1000).all(|_| r.below(7) < 7));
    }
}
