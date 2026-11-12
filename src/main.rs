use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::time::{Duration, Instant};
use terminal_soc::{app::App, model::parse_jsonl, snapshot, ui};

struct Args {
    seed: u64,
    input: Option<String>,
    snapshot: Option<String>,
    ticks: u32,
    size: (u16, u16),
    pick: usize,
}

fn usage() -> ! {
    eprintln!("usage: terminal-soc [--seed N] [--input alerts.jsonl] [--snapshot out.html [--ticks N] [--select N]]");
    std::process::exit(2)
}

fn parse() -> Args {
    let mut a = Args {
        seed: 42,
        input: None,
        snapshot: None,
        ticks: 80,
        size: (150, 44),
        pick: 0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match f.as_str() {
            "--seed" => a.seed = val().parse().unwrap_or_else(|_| usage()),
            "--input" => a.input = Some(val()),
            "--snapshot" => a.snapshot = Some(val()),
            "--ticks" => a.ticks = val().parse().unwrap_or_else(|_| usage()),
            "--select" => a.pick = val().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    a
}

fn build_app(a: &Args) -> App {
    match &a.input {
        Some(p) => {
            let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
                eprintln!("cannot read {p}: {e}");
                std::process::exit(1)
            });
            let (alerts, bad) = parse_jsonl(&text);
            App::from_alerts(alerts, bad)
        }
        None => App::live(a.seed),
    }
}

fn main() -> io::Result<()> {
    let args = parse();
    let mut app = build_app(&args);
    if let Some(out) = &args.snapshot {
        for _ in 0..args.ticks {
            app.tick();
        }
        // Show the analyst log doing something: triage the top three alerts.
        for c in ['a', 'e', 'f'] {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.selected = args.pick;
        std::fs::write(out, snapshot::to_html(&app, args.size.0, args.size.1))?;
        println!("wrote {out}");
        return Ok(());
    }
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        hook(i);
    }));
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut last = Instant::now();
    let res = (|| -> io::Result<()> {
        while !app.quit {
            term.draw(|f| ui::draw(f, &app))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(k) = event::read()? {
                    app.handle_key(k);
                }
            }
            if last.elapsed() >= Duration::from_millis(900) {
                app.tick();
                last = Instant::now();
            }
        }
        Ok(())
    })();
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    res
}
