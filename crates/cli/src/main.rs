mod explain;
mod markdown;
mod render;
mod run;
mod snapshots;
mod style;

use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use insite_core::collect::http::ACCEPT_ENCODING_VALUE;
use insite_core::collect::proxy::ProxyConfig;
use insite_core::collect::{Fetch, Options};
use insite_core::report::Selection;
use insite_core::snapshot::RequestProfile;

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Bumped with each Chrome stable release so the hybrid and chrome profiles do
/// not look outdated.
const CHROME_MAJOR: u32 = 157;

/// Full X-ray of a website from the terminal: network, TLS, DNS, stack,
/// security, SEO and weight.
#[derive(Parser)]
#[command(name = "insite", version, about, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    args: Args,
}

#[derive(Subcommand)]
enum Command {
    /// Explain a finding and how to fix it; without an id, list them all
    Explain {
        /// A finding id such as sec.hsts.missing, or a prefix such as sec.
        id: Option<String>,
    },
}

#[derive(clap::Args)]
struct Args {
    /// URLs or domains to analyze (https:// is assumed). Without any, they are
    /// read from standard input, one per line.
    urls: Vec<String>,

    /// Modules to run, comma-separated: network,tls,dns,infra,security,stack,seo,weight
    #[arg(short, long, value_name = "LIST")]
    modules: Option<String>,

    /// Print the report as JSON (an array with several sites)
    #[arg(short, long, conflicts_with_all = ["ndjson", "md"])]
    json: bool,

    /// Print one JSON report per line, as each site finishes
    #[arg(long, conflicts_with = "md")]
    ndjson: bool,

    /// Print the report as Markdown, ready for an e-mail or a proposal
    #[arg(long)]
    md: bool,

    /// Deadline for each site, in seconds
    #[arg(short, long, default_value_t = 5.0, value_name = "SECONDS")]
    timeout: f64,

    /// Show every section in full, with evidence
    #[arg(short, long)]
    verbose: bool,

    /// Save the raw snapshot (one JSON per line; gzip when the name ends in .gz)
    #[arg(long, value_name = "FILE", conflicts_with = "from")]
    save: Option<PathBuf>,

    /// Analyze snapshots saved with --save, without touching the network
    #[arg(long, value_name = "FILE", conflicts_with = "urls")]
    from: Option<PathBuf>,

    /// User-Agent: hybrid (Chrome string plus insite), chrome, honest, or any text
    #[arg(long, default_value = "hybrid", value_name = "PROFILE")]
    ua: String,

    /// Accept-Language to send (default: from the system locale)
    #[arg(long, value_name = "TAG")]
    lang: Option<String>,

    /// Validate certificates against the system trust store instead of the
    /// embedded Mozilla roots (needed behind corporate TLS inspection)
    #[arg(long)]
    native_roots: bool,

    /// Sites analyzed in parallel in batch mode
    #[arg(short, long, default_value_t = 8, value_name = "N")]
    concurrency: usize,
}

/// How reports are printed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Terminal { color: bool, verbose: bool, width: usize },
    Json { pretty: bool },
    Ndjson,
    Markdown,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(Command::Explain { id }) = cli.command {
        return explain::run(id.as_deref());
    }
    let args = cli.args;

    let selection = match args.modules.as_deref().map(Selection::parse).transpose() {
        Ok(s) => s.unwrap_or_else(Selection::all),
        Err(e) => return usage_error(&e),
    };
    let stdout_tty = std::io::stdout().is_terminal();
    let format = if args.json {
        Format::Json { pretty: stdout_tty }
    } else if args.ndjson {
        Format::Ndjson
    } else if args.md {
        Format::Markdown
    } else {
        Format::Terminal {
            color: stdout_tty && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
            verbose: args.verbose,
            width: style::terminal_width(),
        }
    };

    if let Some(path) = &args.from {
        return snapshots::analyze_saved(path, selection, format);
    }

    if !(args.timeout.is_finite() && args.timeout > 0.0) {
        return usage_error("--timeout must be a positive number of seconds");
    }
    if args.concurrency == 0 {
        return usage_error("--concurrency must be at least 1");
    }
    let inputs = if args.urls.is_empty() {
        if std::io::stdin().is_terminal() {
            return usage_error("give at least one URL, or a list on standard input (see --help)");
        }
        match read_list(std::io::stdin().lock()) {
            Ok(list) if !list.is_empty() => list,
            Ok(_) => return usage_error("standard input had no URLs"),
            Err(e) => return usage_error(&format!("could not read standard input: {e}")),
        }
    } else {
        args.urls.clone()
    };

    let mut opts = Options::new(RequestProfile {
        user_agent: user_agent(&args.ua),
        accept_language: args.lang.clone().unwrap_or_else(accept_language_from_env),
        accept_encoding: ACCEPT_ENCODING_VALUE.to_owned(),
    });
    opts.timeout = Duration::from_secs_f64(args.timeout);
    opts.fetch = Fetch::for_modules(selection);
    opts.proxy = match proxy_from_env() {
        Ok(p) => p,
        Err(e) => return usage_error(&e),
    };
    run::run(run::Plan {
        inputs,
        opts,
        selection,
        format,
        save: args.save,
        native_roots: args.native_roots,
        concurrency: args.concurrency,
    })
}

pub fn usage_error(message: &str) -> ExitCode {
    eprintln!("insite: {message}");
    ExitCode::from(2)
}

/// One URL per line; blank lines and `#` comments are skipped.
fn read_list(input: impl BufRead) -> std::io::Result<Vec<String>> {
    let mut list = Vec::new();
    for line in input.lines() {
        let line = line?;
        let entry = line.split('#').next().unwrap_or_default().trim();
        if !entry.is_empty() {
            list.push(entry.to_owned());
        }
    }
    Ok(list)
}

/// curl's conventions: `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, upper or lower case.
fn proxy_from_env() -> Result<ProxyConfig, String> {
    let var = |name: &str| {
        std::env::var(name)
            .or_else(|_| std::env::var(name.to_ascii_lowercase()))
            .ok()
    };
    ProxyConfig::from_values(
        var("HTTPS_PROXY").as_deref(),
        var("HTTP_PROXY").as_deref(),
        var("NO_PROXY").as_deref(),
    )
}

fn user_agent(profile: &str) -> String {
    let chrome = format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
    );
    match profile {
        "hybrid" => format!("{chrome} insite/{VERSION}"),
        "chrome" => chrome,
        "honest" => format!("insite/{VERSION}"),
        custom => custom.to_owned(),
    }
}

/// `pt_BR.UTF-8` becomes `pt-BR,pt;q=0.9,en;q=0.8`. Without a usable locale, English.
fn accept_language_from_env() -> String {
    let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .find(|v| !v.is_empty())
        .unwrap_or_default();
    accept_language(&locale)
}

fn accept_language(locale: &str) -> String {
    let base = locale.split(['.', '@']).next().unwrap_or_default();
    let mut parts = base.split(['_', '-']);
    let lang = parts.next().unwrap_or_default().to_ascii_lowercase();
    let region = parts.next().map(str::to_ascii_uppercase);
    if lang.len() < 2 || !lang.chars().all(|c| c.is_ascii_alphabetic()) || lang == "c" || lang == "posix" {
        return "en-US,en;q=0.9".to_owned();
    }
    let primary = match region {
        Some(r) if !r.is_empty() => format!("{lang}-{r},{lang};q=0.9"),
        _ => lang.clone(),
    };
    if lang == "en" {
        primary
    } else {
        format!("{primary},en;q=0.8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_language_from_locales() {
        assert_eq!(accept_language("pt_BR.UTF-8"), "pt-BR,pt;q=0.9,en;q=0.8");
        assert_eq!(accept_language("en_GB.UTF-8"), "en-GB,en;q=0.9");
        assert_eq!(accept_language("de"), "de,en;q=0.8");
        assert_eq!(accept_language("C.UTF-8"), "en-US,en;q=0.9");
        assert_eq!(accept_language(""), "en-US,en;q=0.9");
    }

    #[test]
    fn user_agent_profiles() {
        assert!(user_agent("hybrid").ends_with(&format!("insite/{VERSION}")));
        assert!(user_agent("hybrid").starts_with("Mozilla/5.0"));
        assert!(!user_agent("chrome").contains("insite"));
        assert_eq!(user_agent("honest"), format!("insite/{VERSION}"));
        assert_eq!(user_agent("my-bot/1.0"), "my-bot/1.0");
    }

    #[test]
    fn lists_skip_comments_and_blanks() {
        let list = read_list("a.com\n\n  # comment\nb.com # trailing\n".as_bytes()).unwrap();
        assert_eq!(list, ["a.com", "b.com"]);
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
