use crate::gen::Generator;
use crate::model::{Alert, Severity, Status};
use crate::triage::score;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Score,
    Time,
    Severity,
}

impl Sort {
    pub fn label(self) -> &'static str {
        match self {
            Sort::Score => "risk score",
            Sort::Time => "newest",
            Sort::Severity => "severity",
        }
    }
    fn next(self) -> Sort {
        match self {
            Sort::Score => Sort::Time,
            Sort::Time => Sort::Severity,
            Sort::Severity => Sort::Score,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Filter,
    Help,
}

const MAX_ALERTS: usize = 2000;
const MAX_LOG: usize = 200;
const BUCKETS: usize = 48;

pub struct App {
    pub alerts: Vec<Alert>,
    pub selected: usize, // index into visible()
    pub filter: String,
    pub min_sev: Option<Severity>,
    pub only_open: bool,
    pub sort: Sort,
    pub mode: Mode,
    pub paused: bool,
    pub quit: bool,
    pub clock: u32,
    pub log: Vec<String>,
    pub rate: Vec<u64>,
    pub skipped_lines: usize,
    gen: Option<Generator>,
}

impl App {
    pub fn live(seed: u64) -> Self {
        let mut a = Self::empty();
        a.gen = Some(Generator::new(seed));
        a
    }

    pub fn from_alerts(alerts: Vec<Alert>, skipped: usize) -> Self {
        let mut a = Self::empty();
        a.clock = alerts.iter().map(|x| x.ts).max().unwrap_or(0);
        a.alerts = alerts;
        a.skipped_lines = skipped;
        a.rate = vec![0; BUCKETS];
        a.log(format!(
            "loaded {} alerts ({} bad lines skipped)",
            a.alerts.len(),
            skipped
        ));
        a
    }

    fn empty() -> Self {
        App {
            alerts: vec![],
            selected: 0,
            filter: String::new(),
            min_sev: None,
            only_open: true,
            sort: Sort::Score,
            mode: Mode::Normal,
            paused: false,
            quit: false,
            clock: 0,
            log: vec![],
            rate: vec![0; BUCKETS],
            skipped_lines: 0,
            gen: None,
        }
    }

    pub fn log(&mut self, m: String) {
        self.log.push(m);
        if self.log.len() > MAX_LOG {
            self.log.remove(0);
        }
    }

    /// One simulated tick: time advances and maybe an alert arrives.
    pub fn tick(&mut self) {
        if self.paused {
            return;
        }
        self.clock += 20;
        let mut arrived = 0;
        if let Some(g) = self.gen.as_mut() {
            for _ in 0..g.arrivals() {
                self.alerts.push(g.next(self.clock));
                arrived += 1;
            }
            if self.alerts.len() > MAX_ALERTS {
                let extra = self.alerts.len() - MAX_ALERTS;
                self.alerts.drain(..extra);
            }
        }
        self.rate.push(arrived);
        if self.rate.len() > BUCKETS {
            self.rate.remove(0);
        }
    }

    pub fn score_of(&self, a: &Alert) -> u32 {
        score(a, &self.alerts).value
    }

    /// Indices into `alerts`, filtered and sorted.
    pub fn visible(&self) -> Vec<usize> {
        let f = self.filter.to_lowercase();
        let mut v: Vec<(usize, u32)> = self
            .alerts
            .iter()
            .enumerate()
            .filter(|(_, a)| !self.only_open || a.status.is_open())
            .filter(|(_, a)| self.min_sev.is_none_or(|m| a.severity >= m))
            .filter(|(_, a)| {
                f.is_empty()
                    || [
                        &a.rule,
                        &a.host,
                        &a.user,
                        &a.src_ip,
                        &a.technique,
                        &a.tactic,
                        &a.detail,
                    ]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&f))
            })
            .map(|(i, a)| {
                (
                    i,
                    if self.sort == Sort::Score {
                        self.score_of(a)
                    } else {
                        0
                    },
                )
            })
            .collect();
        match self.sort {
            Sort::Score => v.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then(self.alerts[b.0].ts.cmp(&self.alerts[a.0].ts))
            }),
            Sort::Time => v.sort_by(|a, b| {
                self.alerts[b.0]
                    .ts
                    .cmp(&self.alerts[a.0].ts)
                    .then(b.0.cmp(&a.0))
            }),
            Sort::Severity => v.sort_by(|a, b| {
                self.alerts[b.0]
                    .severity
                    .cmp(&self.alerts[a.0].severity)
                    .then(self.alerts[b.0].ts.cmp(&self.alerts[a.0].ts))
            }),
        }
        v.into_iter().map(|x| x.0).collect()
    }

    pub fn selected_alert(&self) -> Option<&Alert> {
        self.visible().get(self.selected).map(|&i| &self.alerts[i])
    }

    fn clamp(&mut self) {
        let n = self.visible().len();
        self.selected = if n == 0 { 0 } else { self.selected.min(n - 1) };
    }

    fn set_status(&mut self, st: Status) {
        let Some(&i) = self.visible().get(self.selected) else {
            return;
        };
        let (id, rule, host) = (
            self.alerts[i].id,
            self.alerts[i].rule.clone(),
            self.alerts[i].host.clone(),
        );
        self.alerts[i].status = st;
        self.log(format!("#{id} {rule} on {host}: {}", st.label()));
        self.clamp();
    }

    pub fn open_count(&self) -> usize {
        self.alerts.iter().filter(|a| a.status.is_open()).count()
    }

    pub fn count_sev(&self, s: Severity) -> u64 {
        self.alerts
            .iter()
            .filter(|a| a.status.is_open() && a.severity == s)
            .count() as u64
    }

    pub fn handle_key(&mut self, k: KeyEvent) {
        if k.kind == KeyEventKind::Release {
            return;
        }
        match self.mode {
            Mode::Help => self.mode = Mode::Normal,
            Mode::Filter => match k.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.mode = Mode::Normal;
                    self.selected = 0;
                }
                KeyCode::Enter => self.mode = Mode::Normal,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.selected = 0;
                }
                KeyCode::Char(c)
                    if !k.modifiers.contains(KeyModifiers::CONTROL)
                        && self.filter.chars().count() < 40 =>
                {
                    self.filter.push(c);
                    self.selected = 0;
                }
                _ => {}
            },
            Mode::Normal => {
                let n = self.visible().len();
                match k.code {
                    KeyCode::Char('q') => self.quit = true,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.quit = true
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        self.selected = (self.selected + 1).min(n.saturating_sub(1))
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.selected = self.selected.saturating_sub(1)
                    }
                    KeyCode::Char('g') | KeyCode::Home => self.selected = 0,
                    KeyCode::Char('G') | KeyCode::End => self.selected = n.saturating_sub(1),
                    KeyCode::PageDown => {
                        self.selected = (self.selected + 10).min(n.saturating_sub(1))
                    }
                    KeyCode::PageUp => self.selected = self.selected.saturating_sub(10),
                    KeyCode::Char('a') => self.set_status(Status::Ack),
                    KeyCode::Char('e') => self.set_status(Status::Escalated),
                    KeyCode::Char('f') => self.set_status(Status::FalsePositive),
                    KeyCode::Char('s') => {
                        self.sort = self.sort.next();
                        self.selected = 0;
                    }
                    KeyCode::Char('o') => {
                        self.only_open = !self.only_open;
                        self.clamp();
                    }
                    KeyCode::Char('1'..='4') => {
                        let c = if let KeyCode::Char(c) = k.code {
                            c
                        } else {
                            '0'
                        };
                        let s = [
                            Severity::Low,
                            Severity::Medium,
                            Severity::High,
                            Severity::Critical,
                        ][c as usize - '1' as usize];
                        self.min_sev = if self.min_sev == Some(s) {
                            None
                        } else {
                            Some(s)
                        };
                        self.selected = 0;
                    }
                    KeyCode::Char('/') => self.mode = Mode::Filter,
                    KeyCode::Char(' ') => self.paused = !self.paused,
                    KeyCode::Char('?') | KeyCode::F(1) => self.mode = Mode::Help,
                    KeyCode::Esc => {
                        self.filter.clear();
                        self.min_sev = None;
                        self.selected = 0;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent {
            code: c,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn app_with(n: usize) -> App {
        let mut a = App::live(5);
        while a.alerts.len() < n {
            a.tick();
        }
        a
    }

    #[test]
    fn tick_adds_alerts_and_pause_stops_time() {
        let mut a = app_with(10);
        assert!(a.alerts.len() >= 10 && a.clock > 0);
        a.handle_key(key(KeyCode::Char(' ')));
        let (n, clock) = (a.alerts.len(), a.clock);
        for _ in 0..5 {
            a.tick();
        }
        assert_eq!((a.alerts.len(), a.clock), (n, clock));
    }

    #[test]
    fn navigation_is_bounded() {
        let mut a = app_with(12);
        a.handle_key(key(KeyCode::Char('k')));
        assert_eq!(a.selected, 0);
        for _ in 0..50 {
            a.handle_key(key(KeyCode::Char('j')));
        }
        let last = a.visible().len() - 1;
        assert_eq!(a.selected, last);
        a.handle_key(key(KeyCode::Char('g')));
        a.handle_key(key(KeyCode::Char('G')));
        assert_eq!(a.selected, last);
        a.handle_key(key(KeyCode::PageUp));
        assert_eq!(a.selected, last.saturating_sub(10));
        a.handle_key(key(KeyCode::Home));
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn triage_actions_change_status_log_and_hide_closed_alerts() {
        let mut a = app_with(8);
        let first = a.selected_alert().unwrap().id;
        a.handle_key(key(KeyCode::Char('f')));
        assert_eq!(
            a.alerts.iter().find(|x| x.id == first).unwrap().status,
            Status::FalsePositive
        );
        assert!(
            !a.visible().iter().any(|&i| a.alerts[i].id == first),
            "closed alerts leave the queue"
        );
        assert!(a.log.last().unwrap().contains("false+"));
        a.handle_key(key(KeyCode::Char('o')));
        assert!(
            a.visible().iter().any(|&i| a.alerts[i].id == first),
            "toggle shows closed ones"
        );
        let id = a.selected_alert().unwrap().id;
        a.handle_key(key(KeyCode::Char('e')));
        assert_eq!(
            a.alerts.iter().find(|x| x.id == id).unwrap().status,
            Status::Escalated
        );
    }

    #[test]
    fn actions_on_an_empty_queue_do_nothing() {
        let mut a = App::from_alerts(vec![], 0);
        for c in ['a', 'e', 'f', 'j', 'k', 'G'] {
            a.handle_key(key(KeyCode::Char(c)));
        }
        assert!(a.selected_alert().is_none() && a.selected == 0);
    }

    #[test]
    fn sorting_modes_order_correctly() {
        let mut a = app_with(40);
        let v = a.visible();
        let scores: Vec<u32> = v.iter().map(|&i| a.score_of(&a.alerts[i])).collect();
        assert!(scores.windows(2).all(|w| w[0] >= w[1]));
        a.handle_key(key(KeyCode::Char('s')));
        assert_eq!(a.sort, Sort::Time);
        let ts: Vec<u32> = a.visible().iter().map(|&i| a.alerts[i].ts).collect();
        assert!(ts.windows(2).all(|w| w[0] >= w[1]));
        a.handle_key(key(KeyCode::Char('s')));
        let sev: Vec<Severity> = a.visible().iter().map(|&i| a.alerts[i].severity).collect();
        assert!(sev.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn severity_filter_toggles_and_text_filter_matches_fields() {
        let mut a = app_with(60);
        a.handle_key(key(KeyCode::Char('4')));
        assert!(a
            .visible()
            .iter()
            .all(|&i| a.alerts[i].severity == Severity::Critical));
        a.handle_key(key(KeyCode::Char('4')));
        assert!(a.min_sev.is_none());
        a.handle_key(key(KeyCode::Char('/')));
        assert_eq!(a.mode, Mode::Filter);
        for c in "SSH".chars() {
            a.handle_key(key(KeyCode::Char(c)));
        }
        assert!(
            !a.visible().is_empty()
                && a.visible().iter().all(|&i| a.alerts[i].rule.contains("SSH")
                    || a.alerts[i].detail.to_lowercase().contains("ssh"))
        );
        a.handle_key(key(KeyCode::Backspace));
        assert_eq!(a.filter, "SS");
        a.handle_key(key(KeyCode::Esc));
        assert!(a.filter.is_empty() && a.mode == Mode::Normal);
    }

    #[test]
    fn filter_input_is_capped_and_ignores_control_chords() {
        let mut a = app_with(3);
        a.handle_key(key(KeyCode::Char('/')));
        for _ in 0..100 {
            a.handle_key(key(KeyCode::Char('x')));
        }
        assert_eq!(a.filter.chars().count(), 40);
        let mut ctl = key(KeyCode::Char('c'));
        ctl.modifiers = KeyModifiers::CONTROL;
        a.handle_key(ctl);
        assert!(!a.filter.ends_with('c'));
    }

    #[test]
    fn quit_keys_and_help_mode() {
        let mut a = app_with(1);
        a.handle_key(key(KeyCode::Char('?')));
        assert_eq!(a.mode, Mode::Help);
        a.handle_key(key(KeyCode::Char('q')));
        assert!(!a.quit, "any key just closes help");
        let mut ctl = key(KeyCode::Char('c'));
        ctl.modifiers = KeyModifiers::CONTROL;
        a.handle_key(ctl);
        assert!(a.quit);
        let mut b = app_with(1);
        b.handle_key(key(KeyCode::Char('q')));
        assert!(b.quit);
    }

    #[test]
    fn key_release_events_are_ignored() {
        let mut a = app_with(1);
        let mut k = key(KeyCode::Char('q'));
        k.kind = KeyEventKind::Release;
        a.handle_key(k);
        assert!(!a.quit);
    }

    #[test]
    fn memory_is_bounded() {
        let mut a = App::live(1);
        for _ in 0..MAX_ALERTS * 3 {
            a.tick();
        }
        assert_eq!(a.alerts.len(), MAX_ALERTS);
        assert_eq!(a.rate.len(), BUCKETS);
        for i in 0..MAX_LOG + 50 {
            a.log(format!("{i}"));
        }
        assert_eq!(a.log.len(), MAX_LOG);
    }
}
