use crate::app::{App, Mode};
use crate::model::{Severity, Status};
use crate::triage::score;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Sparkline,
    Table, TableState, Wrap,
};
use ratatui::Frame;

const BG: Color = Color::Rgb(13, 17, 23);
const PANEL: Color = Color::Rgb(22, 27, 34);
const BORDER: Color = Color::Rgb(48, 54, 61);
const TEXT: Color = Color::Rgb(201, 209, 217);
const MUTE: Color = Color::Rgb(125, 133, 144);
const ACCENT: Color = Color::Rgb(88, 166, 255);
const GREEN: Color = Color::Rgb(63, 185, 80);

pub fn sev_color(s: Severity) -> Color {
    match s {
        Severity::Low => Color::Rgb(86, 156, 214),
        Severity::Medium => Color::Rgb(227, 179, 65),
        Severity::High => Color::Rgb(240, 136, 62),
        Severity::Critical => Color::Rgb(248, 81, 73),
    }
}

fn block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(BORDER))
        .style(Style::new().bg(PANEL).fg(TEXT))
        .title(Span::styled(
            format!(" {title} "),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn clock(secs: u32) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::new().bg(BG)), area);
    let [header, body, bottom, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(9),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(f, header, app);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(body);
    draw_queue(f, left, app);
    draw_detail(f, right, app);
    let [sev, rate, log] = Layout::horizontal([
        Constraint::Percentage(30),
        Constraint::Percentage(30),
        Constraint::Percentage(40),
    ])
    .areas(bottom);
    draw_sev(f, sev, app);
    draw_rate(f, rate, app);
    draw_log(f, log, app);
    draw_footer(f, footer, app);
    if app.mode == Mode::Help {
        draw_help(f, area);
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let state = if app.paused {
        Span::styled(
            " PAUSED ",
            Style::new()
                .bg(Color::Rgb(227, 179, 65))
                .fg(BG)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " LIVE ",
            Style::new().bg(GREEN).fg(BG).add_modifier(Modifier::BOLD),
        )
    };
    let crit_open = app.count_sev(Severity::Critical);
    let line = Line::from(vec![
        Span::styled(
            " TERMINAL SOC ",
            Style::new().bg(ACCENT).fg(BG).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        state,
        Span::styled(
            format!("  shift {}", clock(app.clock)),
            Style::new().fg(MUTE),
        ),
        Span::styled(
            format!("   open {}", app.open_count()),
            Style::new().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("   critical {crit_open}"),
            Style::new()
                .fg(if crit_open > 0 {
                    sev_color(Severity::Critical)
                } else {
                    MUTE
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("   sort: {}", app.sort.label()),
            Style::new().fg(MUTE),
        ),
        Span::styled(
            app.min_sev
                .map(|s| format!("   min: {}", s.label()))
                .unwrap_or_default(),
            Style::new().fg(MUTE),
        ),
        Span::styled(
            if app.filter.is_empty() {
                String::new()
            } else {
                format!("   filter: {}", app.filter)
            },
            Style::new().fg(ACCENT),
        ),
    ]);
    f.render_widget(Paragraph::new(line).style(Style::new().bg(BG)), area);
}

fn draw_queue(f: &mut Frame, area: Rect, app: &App) {
    let vis = app.visible();
    let rows: Vec<Row> = vis
        .iter()
        .map(|&i| {
            let a = &app.alerts[i];
            let s = score(a, &app.alerts);
            let col = sev_color(a.severity);
            let st = match a.status {
                Status::New => Style::new().fg(TEXT),
                Status::Ack => Style::new().fg(MUTE),
                _ => Style::new().fg(MUTE).add_modifier(Modifier::CROSSED_OUT),
            };
            Row::new(vec![
                Cell::from(format!("{:>3}", s.value))
                    .style(Style::new().fg(col).add_modifier(Modifier::BOLD)),
                Cell::from(s.priority()).style(Style::new().fg(col)),
                Cell::from(a.severity.label()).style(Style::new().fg(col)),
                Cell::from(a.rule.clone()).style(st),
                Cell::from(a.host.clone()).style(st),
                Cell::from(a.technique.clone()).style(Style::new().fg(MUTE)),
                Cell::from(clock(a.ts)).style(Style::new().fg(MUTE)),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(4),
        Constraint::Length(3),
        Constraint::Length(5),
        Constraint::Min(18),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(["SCR", "PRI", "SEV", "RULE", "HOST", "TECH", "TIME"])
                .style(Style::new().fg(MUTE).add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(
            Style::new()
                .bg(Color::Rgb(33, 48, 74))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▌")
        .block(block(&format!("Alert queue ({})", vis.len())));
    let mut st = TableState::default();
    if !vis.is_empty() {
        st.select(Some(app.selected.min(vis.len() - 1)));
    }
    f.render_stateful_widget(table, area, &mut st);
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App) {
    let b = block("Alert detail");
    let Some(a) = app.selected_alert() else {
        f.render_widget(
            Paragraph::new("No alerts match the current view.")
                .style(Style::new().fg(MUTE))
                .block(b),
            area,
        );
        return;
    };
    let s = score(a, &app.alerts);
    let col = sev_color(a.severity);
    let label = |k: &str| Span::styled(format!("{k:<10}"), Style::new().fg(MUTE));
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", a.severity.label()),
                Style::new().bg(col).fg(BG).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}", a.rule),
                Style::new().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::raw(""),
        Line::from(vec![
            label("risk"),
            Span::styled(
                format!("{} / 100  {}", s.value, s.priority()),
                Style::new().fg(col).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            label("MITRE"),
            Span::styled(
                format!("{} {}", a.technique, a.tactic),
                Style::new().fg(ACCENT),
            ),
        ]),
        Line::from(vec![
            label("host"),
            Span::raw(format!("{} (criticality {}/5)", a.host, a.criticality)),
        ]),
        Line::from(vec![label("user"), Span::raw(a.user.clone())]),
        Line::from(vec![
            label("source"),
            Span::raw(a.src_ip.clone()),
            Span::styled(
                if a.intel_hit {
                    "  threat intel hit"
                } else {
                    ""
                },
                Style::new().fg(sev_color(Severity::Critical)),
            ),
        ]),
        Line::from(vec![label("status"), Span::raw(a.status.label())]),
        Line::raw(""),
        Line::styled(
            "What happened",
            Style::new().fg(MUTE).add_modifier(Modifier::BOLD),
        ),
        Line::raw(a.detail.clone()),
        Line::raw(""),
        Line::styled(
            "Why this score",
            Style::new().fg(MUTE).add_modifier(Modifier::BOLD),
        ),
    ];
    lines.extend(
        s.reasons
            .iter()
            .map(|r| Line::styled(format!(" {r}"), Style::new().fg(TEXT))),
    );
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Playbook",
        Style::new().fg(MUTE).add_modifier(Modifier::BOLD),
    ));
    lines.extend(a.playbook.iter().enumerate().map(|(i, p)| {
        Line::from(vec![
            Span::styled(format!(" {}. ", i + 1), Style::new().fg(GREEN)),
            Span::raw(p.clone()),
        ])
    }));
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(b),
        area,
    );
}

fn draw_sev(f: &mut Frame, area: Rect, app: &App) {
    let bars: Vec<Bar> = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .iter()
    .map(|&s| {
        Bar::default()
            .value(app.count_sev(s))
            .label(Line::from(s.label()))
            .style(Style::new().fg(sev_color(s)))
            .value_style(Style::new().fg(BG).bg(sev_color(s)))
    })
    .collect();
    let chart = BarChart::default()
        .block(block("Open by severity"))
        .data(BarGroup::default().bars(&bars))
        .bar_width(5)
        .bar_gap(1)
        .label_style(Style::new().fg(MUTE));
    f.render_widget(chart, area);
}

fn draw_rate(f: &mut Frame, area: Rect, app: &App) {
    let spark = Sparkline::default()
        .block(block("Arrivals per tick"))
        .data(app.rate.clone())
        .style(Style::new().fg(ACCENT));
    f.render_widget(spark, area);
}

fn draw_log(f: &mut Frame, area: Rect, app: &App) {
    let h = area.height.saturating_sub(2) as usize;
    let start = app.log.len().saturating_sub(h);
    let lines: Vec<Line> = app.log[start..]
        .iter()
        .map(|l| {
            Line::from(vec![
                Span::styled("› ", Style::new().fg(GREEN)),
                Span::raw(l.clone()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block("Analyst log")), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hint = if app.mode == Mode::Filter {
        " type to filter   Enter apply   Esc clear ".to_string()
    } else {
        " j/k move   a ack   e escalate   f false+   / filter   1-4 min severity   s sort   o closed   space pause   ? help   q quit ".to_string()
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::new().fg(MUTE).bg(BG)),
        area,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let w = 56.min(area.width);
    let h = 16.min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    let text = vec![
        Line::styled(
            "Triage",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Line::raw(" a  acknowledge     e  escalate     f  false positive"),
        Line::raw(""),
        Line::styled(
            "Navigate",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Line::raw(" j/k or arrows, g/G top and bottom, PgUp/PgDn"),
        Line::raw(""),
        Line::styled("View", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Line::raw(" /  filter text (host, rule, user, IP, technique)"),
        Line::raw(" 1-4  minimum severity (press again to clear)"),
        Line::raw(" s  cycle sort     o  show closed     Esc  reset"),
        Line::raw(" space  pause the feed"),
        Line::raw(""),
        Line::styled("Any key closes this help", Style::new().fg(MUTE)),
    ];
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Left)
            .block(block("Help")),
        r,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    pub fn render(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn app() -> App {
        let mut a = App::live(11);
        while a.alerts.len() < 60 {
            a.tick();
        }
        a
    }

    #[test]
    fn full_layout_shows_every_panel() {
        let t = render(&app(), 140, 40);
        for s in [
            "TERMINAL SOC",
            "LIVE",
            "Alert queue",
            "Alert detail",
            "Why this score",
            "Playbook",
            "Open by severity",
            "Arrivals per tick",
            "Analyst log",
            "j/k move",
        ] {
            assert!(t.contains(s), "missing {s}");
        }
    }

    #[test]
    fn never_panics_on_tiny_or_huge_terminals() {
        let a = app();
        for (w, h) in [
            (0, 0),
            (1, 1),
            (10, 3),
            (20, 5),
            (40, 12),
            (80, 24),
            (300, 90),
        ] {
            render(&a, w, h);
        }
    }

    #[test]
    fn empty_queue_and_help_overlay_render() {
        let mut a = App::from_alerts(vec![], 0);
        assert!(render(&a, 100, 30).contains("No alerts match"));
        a.mode = Mode::Help;
        let t = render(&a, 100, 30);
        assert!(t.contains("false positive") && t.contains("Any key closes"));
        render(&a, 30, 8);
    }

    #[test]
    fn paused_and_filter_state_are_visible() {
        let mut a = app();
        a.paused = true;
        a.filter = "ssh".into();
        let t = render(&a, 140, 40);
        assert!(t.contains("PAUSED") && t.contains("filter: ssh"));
    }
}
