//! Renders one frame off-screen and exports it as HTML, so a README can show the TUI.

use crate::app::App;
use crate::ui;
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

fn css(c: Color) -> Option<String> {
    match c {
        Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")),
        _ => None,
    }
}

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn to_html(app: &App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).expect("test backend");
    t.draw(|f| ui::draw(f, app)).expect("draw");
    let buf = t.backend().buffer().clone();
    let mut out = String::from("<!doctype html><meta charset=utf-8><title>Terminal SOC</title><body style=\"margin:0;background:#0d1117\"><pre style=\"margin:0;padding:12px;font:14px/1.25 'DejaVu Sans Mono',Menlo,monospace;color:#c9d1d9\">");
    for y in 0..h {
        for x in 0..w {
            let c = &buf[(x, y)];
            let mut style = String::new();
            if let Some(v) = css(c.fg) {
                style.push_str(&format!("color:{v};"));
            }
            if let Some(v) = css(c.bg) {
                style.push_str(&format!("background:{v};"));
            }
            if c.modifier.contains(Modifier::BOLD) {
                style.push_str("font-weight:bold;");
            }
            if c.modifier.contains(Modifier::CROSSED_OUT) {
                style.push_str("text-decoration:line-through;");
            }
            out.push_str(&format!(
                "<span style=\"{style}\">{}</span>",
                escape(c.symbol())
            ));
        }
        out.push('\n');
    }
    out.push_str("</pre>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_contains_text_colors_and_is_escaped() {
        let mut a = App::live(2);
        while a.alerts.len() < 20 {
            a.tick();
        }
        let h = to_html(&a, 120, 36);
        assert!(h.contains("T</span><span") && h.contains("#58a6ff") && h.contains("<pre"));
        assert_eq!(escape("<a&b>"), "&lt;a&amp;b&gt;");
        assert!(!h.contains("<script"));
    }
}
