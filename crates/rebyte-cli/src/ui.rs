//! Small terminal-aware presentation helpers; redirected output stays plain.

#![allow(clippy::redundant_pub_crate)]

use std::io::{self, IsTerminal as _};

pub(super) fn heading(value: &str) -> String {
    paint(value, "1;36", io::stdout().is_terminal())
}

pub(super) fn success(value: &str) -> String {
    paint(value, "1;32", io::stdout().is_terminal())
}

pub(super) fn error(value: &str) -> String {
    paint(value, "1;31", io::stderr().is_terminal())
}

fn paint(value: &str, ansi: &str, terminal: bool) -> String {
    if terminal && std::env::var_os("NO_COLOR").is_none() {
        format!("\x1b[{ansi}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}
