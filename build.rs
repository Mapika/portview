use std::fs;
use std::path::PathBuf;

include!("src/cli.rs");

fn main() {
    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").unwrap_or_else(|_| "target/assets".to_string()));

    let cmd = <Cli as clap::CommandFactory>::command();

    // Generate man page
    let man_dir = out_dir.join("man");
    fs::create_dir_all(&man_dir).unwrap();
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::new();
    man.render(&mut buf).unwrap();
    fs::write(man_dir.join("portview.1"), buf).unwrap();

    // Generate shell completions
    let comp_dir = out_dir.join("completions");
    fs::create_dir_all(&comp_dir).unwrap();
    for shell in [
        clap_complete::Shell::Bash,
        clap_complete::Shell::Zsh,
        clap_complete::Shell::Fish,
        clap_complete::Shell::Elvish,
        clap_complete::Shell::PowerShell,
    ] {
        clap_complete::generate_to(shell, &mut cmd.clone(), "portview", &comp_dir).unwrap();
    }
}
