mod explain;
mod markdown;
mod render;
mod run;
mod snapshots;
mod style;
mod update;

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
    /// Download the newest webappanalyzer signatures into the cache directory
    Update {
        /// Validate certificates against the system trust store
        #[arg(long)]
        native_roots: bool,
        /// Download and compile even when the signatures are up to date
        #[arg(long)]
        force: bool,
    },
}

#[derive(clap::Args)]
struct Args {
    /// URLs or domains to analyze (https:// is assumed). Without any, they are
    /// read from standard input, one per line.
    urls: Vec<String>,

    /// Modules to run, comma-separated: network,tls,dns,infra,security,stack,seo,weight,browser
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

    /// Also load the page in a headless Chrome: Core Web Vitals, every
    /// resource, console errors, and the stack JavaScript reveals
    #[arg(short, long)]
    browser: bool,

    /// Core Web Vitals comparable to Lighthouse's mobile throttling (implies --browser)
    #[arg(long)]
    throttle: bool,

    /// Emulate a desktop instead of a phone in the browser
    #[arg(long)]
    desktop: bool,

    /// Deadline for the browser, from the start (default 20 s, 60 s with --throttle)
    #[arg(long, value_name = "SECONDS")]
    browser_timeout: Option<f64>,

    /// Show every section in full, with evidence
    #[arg(short, long)]
    verbose: bool,

    /// Save the raw snapshot (one JSON per line; gzip when the name ends in .gz)
    #[arg(long, value_name = "FILE", conflicts_with = "from")]
    save: Option<PathBuf>,

    /// Analyze snapshots saved with --save, without touching the network
    #[arg(long, value_name = "FILE", conflicts_with = "urls")]
    from: Option<PathBuf>,

    /// User-Agent: honest (insite/<version>), hybrid (Chrome string plus insite),
    /// chrome, or any text
    #[arg(long, default_value = "honest", value_name = "PROFILE")]
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
    // Signatures from `insite update` and the user's own, when present.
    insite_core::detect::use_local_data(insite_core::dirs::cache_dir(), insite_core::dirs::config_dir());
    match cli.command {
        Some(Command::Explain { id }) => return explain::run(id.as_deref()),
        Some(Command::Update { native_roots, force }) => return update::run(native_roots, force),
        None => {}
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

    let timeout = match seconds("--timeout", args.timeout) {
        Ok(t) => t,
        Err(e) => return usage_error(&e),
    };
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
    opts.timeout = timeout;
    opts.fetch = Fetch::for_modules(selection);
    opts.proxy = match proxy_from_env() {
        Ok(p) => p,
        Err(e) => return usage_error(&e),
    };
    let browser_wanted = args.browser
        || args.throttle
        || args
            .modules
            .as_deref()
            .is_some_and(|m| m.split(',').any(|n| n.trim().eq_ignore_ascii_case("browser")));
    let browser = if browser_wanted {
        let timeout = args.browser_timeout.unwrap_or(if args.throttle { 60.0 } else { 20.0 });
        let timeout = match seconds("--browser-timeout", timeout) {
            Ok(t) => t,
            Err(e) => return usage_error(&e),
        };
        let (js_paths, dom_properties) = insite_core::detect::engine().browser_queries();
        Some(run::BrowserPlan {
            visit: insite_core::collect::browser::Visit {
                mobile: !args.desktop,
                throttle: args.throttle,
                user_agent_suffix: matches!(args.ua.as_str(), "hybrid" | "honest").then(|| format!("insite/{VERSION}")),
                accept_language: opts.request.accept_language.clone(),
                js_paths,
                dom_properties,
            },
            timeout,
            proxy: browser_proxy(),
        })
    } else {
        None
    };
    run::run(run::Plan {
        inputs,
        opts,
        selection,
        format,
        save: args.save,
        native_roots: args.native_roots,
        concurrency: args.concurrency,
        browser,
    })
}

/// The longest timeout accepted: a year. Beyond it, `Instant` arithmetic can overflow.
const MAX_TIMEOUT_SECS: f64 = 365.0 * 86_400.0;

/// A flag's seconds as a `Duration`, or the usage error to print.
fn seconds(flag: &str, value: f64) -> Result<Duration, String> {
    if value.is_finite() && value > 0.0 && value <= MAX_TIMEOUT_SECS {
        Duration::try_from_secs_f64(value).map_err(|e| format!("{flag}: {e}"))
    } else {
        Err(format!(
            "{flag} must be a positive number of seconds, at most {MAX_TIMEOUT_SECS:.0}"
        ))
    }
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
pub fn proxy_from_env() -> Result<ProxyConfig, String> {
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

/// The proxy for the browser, from `HTTPS_PROXY`. Chrome takes no credentials
/// on the command line, so a proxy that needs them is left out, with a warning.
fn browser_proxy() -> Option<String> {
    let value = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.contains('@') {
        eprintln!("insite: the browser cannot use a proxy with credentials; it connects directly");
        return None;
    }
    Some(value.to_owned())
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
    fn timeouts_are_checked_instead_of_panicking() {
        assert_eq!(seconds("--timeout", 2.5), Ok(Duration::from_millis(2500)));
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e300, 1e19, MAX_TIMEOUT_SECS + 1.0] {
            let err = seconds("--timeout", bad).unwrap_err();
            assert!(
                err.starts_with("--timeout must be a positive number of seconds"),
                "{bad}: {err}"
            );
        }
    }

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
