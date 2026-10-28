mod render;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use insite_core::analyze;
use insite_core::collect::dns::Resolver;
use insite_core::collect::http::ACCEPT_ENCODING_VALUE;
use insite_core::collect::proxy::ProxyConfig;
use insite_core::collect::target::Target;
use insite_core::collect::tls::Tls;
use insite_core::collect::{Collector, Options};
use insite_core::snapshot::RequestProfile;

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Bumped with each Chrome stable release so the hybrid and chrome profiles do
/// not look outdated.
const CHROME_MAJOR: u32 = 157;

/// Full X-ray of a website from the terminal.
#[derive(Parser)]
#[command(name = "insite", version, about)]
struct Args {
    /// URL or domain to analyze (https:// is assumed)
    url: String,

    /// Print the report as JSON
    #[arg(short, long)]
    json: bool,

    /// Deadline for the whole analysis, in seconds
    #[arg(short, long, default_value_t = 5.0, value_name = "SECONDS")]
    timeout: f64,

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
}

fn main() -> ExitCode {
    let args = Args::parse();
    // Build the signature engine while the network works.
    insite_core::detect::warm_up();
    let target = match Target::parse(&args.url) {
        Ok(t) => t,
        Err(e) => return usage_error(&e),
    };
    if !(args.timeout.is_finite() && args.timeout > 0.0) {
        return usage_error("--timeout must be a positive number of seconds");
    }

    let mut opts = Options::new(RequestProfile {
        user_agent: user_agent(&args.ua),
        accept_language: args.lang.clone().unwrap_or_else(accept_language_from_env),
        accept_encoding: ACCEPT_ENCODING_VALUE.to_owned(),
    });
    opts.timeout = Duration::from_secs_f64(args.timeout);
    opts.proxy = match proxy_from_env() {
        Ok(p) => p,
        Err(e) => return usage_error(&e),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let report = runtime.block_on(async {
        let collector = Collector::with(Resolver::from_system()?, Tls::new(&[], args.native_roots)?);
        let snapshot = collector.collect(&target, &opts).await;
        Ok::<_, String>(analyze::analyze(&snapshot))
    });
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("insite: {e}");
            return ExitCode::from(2);
        }
    };

    let stdout = std::io::stdout();
    let tty = stdout.is_terminal();
    let output = if args.json {
        let json = if tty {
            serde_json::to_string_pretty(&report)
        } else {
            serde_json::to_string(&report)
        };
        json.expect("reports always serialize") + "\n"
    } else {
        let color = tty && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
        render::terminal(&report, color)
    };
    let _ = stdout.lock().write_all(output.as_bytes());
    ExitCode::from(report.outcome.exit_code() as u8)
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("insite: {message}");
    ExitCode::from(2)
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
}
