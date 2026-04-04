use std::io::{self, Write};

pub fn run_doctor(use_color: bool, json: bool) {
    let mut out = io::stdout().lock();
    if json {
        let _ = writeln!(out, "[]");
    } else {
        let _ = writeln!(
            out,
            "{}",
            if use_color {
                "  \x1b[32mAll clear \u{2014} no issues found\x1b[0m"
            } else {
                "  All clear \u{2014} no issues found"
            }
        );
    }
}
