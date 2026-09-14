//! Colorized, human-friendly rendering of the checklist `habitat install`
//! and `habitat run` print.
//!
//! Hand-rolled ANSI rather than a coloring crate: `main.rs`'s module doc
//! already notes Phase 1 avoids taking dependencies where hand-rolling is
//! simpler, and that holds here too -- two colors and a bold weight don't
//! justify a new dependency.
//!
//! Color is suppressed automatically when stdout isn't a terminal (e.g.
//! piped into a log file or CI) or when `NO_COLOR` is set
//! (https://no-color.org), and forced on when `CLICOLOR_FORCE` is set to
//! anything but `"0"` -- the same two env vars most CLI tools honor.

use std::io::IsTerminal;
use std::sync::OnceLock;

#[derive(Clone, Copy)]
pub struct Style {
    enabled: bool,
}

fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if let Some(v) = std::env::var_os("CLICOLOR_FORCE") {
        if v != "0" {
            return true;
        }
    }
    std::io::stdout().is_terminal()
}

/// The process-wide color decision, computed once from the environment.
pub fn style() -> Style {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    Style {
        enabled: *ENABLED.get_or_init(color_enabled),
    }
}

impl Style {
    fn wrap(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn green_bold(self, text: &str) -> String {
        self.wrap("1;32", text)
    }

    pub fn red_bold(self, text: &str) -> String {
        self.wrap("1;31", text)
    }

    pub fn bold(self, text: &str) -> String {
        self.wrap("1", text)
    }

    pub fn dim(self, text: &str) -> String {
        self.wrap("2", text)
    }
}
