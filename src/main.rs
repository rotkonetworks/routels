mod bird;
mod debian;
mod deep;
mod diag;
mod eos;
mod filter;
mod frr;
mod haproxy;
mod lsp;
mod lsp_docs;
mod mikrotik;
mod nft;
mod rules;
mod sysctl;
mod vyos;
mod wireguard;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use diag::{Diagnostic, Format, Severity};
use filter::Pipeline;

#[derive(Parser)]
#[command(
    name = "routels",
    version,
    about = "Fast offline linter for network configs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Output format
    #[arg(long, value_enum, global = true, default_value_t = Fmt::Text)]
    format: Fmt,

    /// Exit non-zero only on errors (ignore warnings)
    #[arg(long, global = true)]
    errors_only: bool,

    /// Also shell out to the platform's own validator (vtysh -C, nft -c, ...)
    #[arg(long, global = true)]
    deep: bool,

    /// Drop diagnostics below the given severity (error|warning|info|hint)
    #[arg(long, value_enum, global = true)]
    severity_min: Option<Sev>,

    /// Drop diagnostics with this code; repeatable (e.g. --ignore-code BIR040)
    #[arg(long, global = true, action = ArgAction::Append)]
    ignore_code: Vec<String>,

    /// Collapse exact (file,line,col,code,message) duplicates
    #[arg(long, global = true)]
    dedup: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum Sev {
    Error,
    Warning,
    Info,
    Hint,
}

impl From<Sev> for Severity {
    fn from(s: Sev) -> Self {
        match s {
            Sev::Error => Severity::Error,
            Sev::Warning => Severity::Warning,
            Sev::Info => Severity::Info,
            Sev::Hint => Severity::Hint,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum Fmt {
    Text,
    Json,
    Sarif,
}

impl From<Fmt> for Format {
    fn from(f: Fmt) -> Self {
        match f {
            Fmt::Text => Format::Text,
            Fmt::Json => Format::Json,
            Fmt::Sarif => Format::Sarif,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Lint Arista EOS / cEOS running-config style
    Eos { files: Vec<PathBuf> },
    /// Lint FRR (vtysh) config
    Frr { files: Vec<PathBuf> },
    /// Lint VyOS config (set-style or curly auto-detected)
    Vyos { files: Vec<PathBuf> },
    /// Lint MikroTik RouterOS .rsc export
    Mikrotik { files: Vec<PathBuf> },
    /// Lint BIRD 2.x config
    Bird { files: Vec<PathBuf> },
    /// Lint nftables (.nft) or iptables-save (auto-detect)
    Nft { files: Vec<PathBuf> },
    /// Lint Debian /etc/network/interfaces
    Debian { files: Vec<PathBuf> },
    /// Lint WireGuard wg-quick config
    Wireguard { files: Vec<PathBuf> },
    /// Lint HAproxy haproxy.cfg
    Haproxy { files: Vec<PathBuf> },
    /// Lint sysctl.conf / sysctl.d/*.conf
    Sysctl { files: Vec<PathBuf> },
    /// Run as a Language Server (stdio); served to editors via tower-lsp
    Lsp,
    /// List all diagnostic codes routels can emit
    ListRules,
    /// Print the description of a single diagnostic code
    Explain { code: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let format: Format = cli.format.into();

    if matches!(cli.cmd, Cmd::Lsp) {
        lsp::run();
        return ExitCode::SUCCESS;
    }
    if matches!(cli.cmd, Cmd::ListRules) {
        rules::list_rules();
        return ExitCode::SUCCESS;
    }
    if let Cmd::Explain { code } = &cli.cmd {
        match rules::explain(code) {
            Some(r) => {
                println!("{} ({}): {}", r.code, r.platform, r.description);
                return ExitCode::SUCCESS;
            }
            None => {
                eprintln!(
                    "routels: unknown code `{}` (try `routels list-rules`)",
                    code
                );
                return ExitCode::from(2);
            }
        }
    }

    type Linter = fn(&str, &str) -> Vec<Diagnostic>;
    let (files, linter, platform): (&Vec<PathBuf>, Linter, deep::Platform) = match &cli.cmd {
        Cmd::Eos { files } => (files, eos::lint, deep::Platform::Eos),
        Cmd::Frr { files } => (files, frr::lint, deep::Platform::Frr),
        Cmd::Vyos { files } => (files, vyos::lint, deep::Platform::Vyos),
        Cmd::Mikrotik { files } => (files, mikrotik::lint, deep::Platform::Mikrotik),
        Cmd::Bird { files } => (files, bird::lint, deep::Platform::Bird),
        Cmd::Nft { files } => (files, nft::lint, deep::Platform::Nft),
        Cmd::Debian { files } => (files, debian::lint, deep::Platform::Debian),
        Cmd::Wireguard { files } => (files, wireguard::lint, deep::Platform::Wireguard),
        Cmd::Haproxy { files } => (files, haproxy::lint, deep::Platform::Haproxy),
        Cmd::Sysctl { files } => (files, sysctl::lint, deep::Platform::Sysctl),
        Cmd::Lsp | Cmd::ListRules | Cmd::Explain { .. } => unreachable!(),
    };

    let mut all = Vec::new();
    let inputs = if files.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        files.clone()
    };

    for path in &inputs {
        let (name, src) = match read_input(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("routels: {}: {}", path.display(), e);
                return ExitCode::from(2);
            }
        };
        all.extend(linter(&name, &src));
        if cli.deep {
            all.extend(deep::check(platform, path));
        }
    }

    let mut pipeline = Pipeline::new();
    if let Some(min) = cli.severity_min {
        pipeline = pipeline.and_then(filter::severity_min(min.into()));
    }
    if !cli.ignore_code.is_empty() {
        pipeline = pipeline.and_then(filter::ignore_codes(cli.ignore_code.clone()));
    }
    if cli.dedup {
        pipeline = pipeline.and_then(filter::dedup());
    }
    let all = pipeline.run(all);

    if let Err(e) = diag::emit(&all, format) {
        eprintln!("routels: write error: {}", e);
        return ExitCode::from(2);
    }

    let has_error = all.iter().any(|d| d.severity == Severity::Error);
    let has_warn = all.iter().any(|d| d.severity == Severity::Warning);
    if has_error || (!cli.errors_only && has_warn) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn read_input(path: &PathBuf) -> io::Result<(String, String)> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        Ok(("<stdin>".to_string(), s))
    } else {
        let s = fs::read_to_string(path)?;
        Ok((path.display().to_string(), s))
    }
}
