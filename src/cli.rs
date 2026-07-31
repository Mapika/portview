use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "portview",
    about = "See what's on your ports, then act on it.",
    version,
    after_help = "Examples:\n  portview                   Show all listening ports\n  portview 3000              Inspect port 3000 in detail\n  portview watch --docker    Interactive watch with Docker context\n  portview kill 3000 --force Force-kill process(es) on port 3000\n\nLegacy flags (--watch, --kill) are still supported."
)]
pub struct Cli {
    /// UX-first subcommands
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Port number to inspect, or 'scan' to list all
    pub target: Option<String>,

    /// Kill the process on the specified port
    #[arg(short, long, hide = true)]
    pub kill: Option<u16>,

    /// Force kill (SIGKILL instead of SIGTERM)
    #[arg(short, long)]
    pub force: bool,

    /// Show all ports including non-listening
    #[arg(short, long)]
    pub all: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Enrich output with Docker container ownership when available
    #[arg(long)]
    pub docker: bool,

    /// Don't use colors
    #[arg(long)]
    pub no_color: bool,

    /// Live-refresh the display every second
    #[arg(short, long, hide = true)]
    pub watch: bool,

    /// Don't truncate the command column (use full terminal width)
    #[arg(long)]
    pub wide: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Live-refresh the display (interactive TUI by default)
    Watch {
        /// Port number or process name filter
        target: Option<String>,
        /// Show all ports including non-listening
        #[arg(short, long)]
        all: bool,
        /// Output as JSON (streaming in watch mode)
        #[arg(long)]
        json: bool,
        /// Enable Docker ownership context
        #[arg(long)]
        docker: bool,
        /// Force kill (default for d in TUI / kill prompts)
        #[arg(short, long)]
        force: bool,
        /// Don't truncate the command column
        #[arg(long)]
        wide: bool,
        /// Disable all colors
        #[arg(long)]
        no_color: bool,
        /// Default sort column (port, proto, pid, address, user, process, uptime, mem, command)
        #[arg(short, long)]
        sort: Option<String>,
    },
    /// Kill process(es) bound to a port
    Kill {
        /// Port to kill
        port: u16,
        /// Force kill (SIGKILL / TerminateProcess)
        #[arg(short, long)]
        force: bool,
        /// Show Docker ownership context before killing
        #[arg(long)]
        docker: bool,
        /// Disable all colors
        #[arg(long)]
        no_color: bool,
    },
    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, elvish, powershell)
        shell: clap_complete::Shell,
    },
    /// Diagnose common port problems
    Doctor {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Disable all colors
        #[arg(long)]
        no_color: bool,
    },
    /// Run as an MCP server over stdio (for AI agents)
    Mcp {
        /// Withhold the kill_port tool, exposing read-only tools only
        #[arg(long)]
        read_only: bool,
    },
    /// Inspect ports on a remote host via SSH
    Ssh {
        /// SSH destination (user@host or host)
        destination: String,
        /// Remote subcommand and arguments (e.g. "watch", "3000", "doctor")
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        remote_args: Vec<String>,
        /// Extra SSH options (e.g. "-p 2222")
        #[arg(long)]
        ssh_opt: Vec<String>,
        /// Don't use the remote portview; collect via ss/ps over SSH instead
        #[arg(long)]
        agentless: bool,
        /// Disable all colors
        #[arg(long)]
        no_color: bool,
    },
}
