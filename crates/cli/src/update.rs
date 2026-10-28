//! `insite update`: newer webappanalyzer signatures, compiled with the same code
//! as the build and kept in the cache directory. The engine uses them when they
//! are newer than the embedded ones and of the same index format.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use insite_core::collect::dns::Resolver;
use insite_core::collect::http::ACCEPT_ENCODING_VALUE;
use insite_core::collect::target::Target;
use insite_core::collect::tls::Tls;
use insite_core::collect::{Collector, Fetch, Options};
use insite_core::snapshot::RequestProfile;

const REPO: &str = "enthec/webappanalyzer";
const DOWNLOAD_LIMIT: usize = 32 << 20;

pub fn run(native_roots: bool, force: bool) -> ExitCode {
    let Some(cache) = insite_core::dirs::cache_dir() else {
        eprintln!("insite: no cache directory (is HOME set?)");
        return ExitCode::FAILURE;
    };
    let proxy = match crate::proxy_from_env() {
        Ok(p) => p,
        Err(e) => return crate::usage_error(&e),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(async {
        let collector = Collector::with(Resolver::from_system()?, Tls::new(&[], native_roots)?);
        let mut opts = Options::new(RequestProfile {
            user_agent: format!("insite/{} (update)", crate::VERSION),
            accept_language: "en".into(),
            accept_encoding: ACCEPT_ENCODING_VALUE.into(),
        });
        opts.timeout = Duration::from_secs(60);
        opts.body_limit = DOWNLOAD_LIMIT;
        opts.proxy = proxy;
        opts.fetch = Fetch {
            http_check: false,
            dns_records: false,
            asn: false,
            robots_and_sitemap: false,
            security_txt: false,
        };
        update(&collector, &opts, &cache.join("signatures"), force).await
    });
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("insite: update failed: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn update(collector: &Collector, opts: &Options, dir: &Path, force: bool) -> Result<String, String> {
    // The git endpoint names the newest commit without the GitHub API and its
    // rate limit. The date recorded is today's: main as of now.
    let refs = download(
        collector,
        opts,
        &format!("https://github.com/{REPO}.git/info/refs?service=git-upload-pack"),
    )
    .await?;
    let refs = String::from_utf8_lossy(&refs);
    let sha = head_commit(&refs).ok_or("GitHub did not name the newest commit")?;
    let today = insite_core::analyze::rfc3339(std::time::SystemTime::now());
    let date = &today[..10];

    let (source, current_date) = insite_core::detect::engine().source();
    if source.ends_with(sha) && !force {
        return Ok(format!("Signatures are up to date ({source}, {current_date})."));
    }

    // Everything goes to a temporary directory first, so a failed update
    // leaves the current signatures in place.
    let staging = dir.with_extension("new");
    let _ = std::fs::remove_dir_all(&staging);
    let src = staging.join("src");
    std::fs::create_dir_all(src.join("technologies")).map_err(|e| format!("{}: {e}", src.display()))?;
    let raw = format!("https://raw.githubusercontent.com/{REPO}/{sha}/src");
    let mut files = vec!["categories.json".to_owned()];
    files.extend(
        std::iter::once('_')
            .chain('a'..='z')
            .map(|c| format!("technologies/{c}.json")),
    );
    let mut downloads = tokio::task::JoinSet::new();
    for file in &files {
        let (collector, opts, url, file) = (collector.clone(), opts.clone(), format!("{raw}/{file}"), file.clone());
        downloads.spawn(async move { (file, download(&collector, &opts, &url).await) });
    }
    while let Some(joined) = downloads.join_next().await {
        let (file, body) = joined.map_err(|e| e.to_string())?;
        std::fs::write(src.join(&file), body?).map_err(|e| format!("{file}: {e}"))?;
    }
    let meta = format!(
        "source = \"{REPO}@{sha}\"\ndate = \"{date}\"\nurl = \"https://github.com/{REPO}\"\nlicense = \"GPL-3.0\"\n"
    );
    std::fs::write(src.join("SOURCE.toml"), meta).map_err(|e| e.to_string())?;

    let (index, report) = insite_sigc::compile_dir(&src)?;
    // Building the engine proves the index loads before it replaces anything.
    let techs = index.techs.len();
    let json = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    insite_core::detect::Engine::new(index);
    std::fs::write(staging.join("index.json"), json).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&staging, dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(format!(
        "Updated to {REPO}@{} ({date}): {techs} technologies, {} patterns ({} dropped). Saved in {}.",
        &sha[..7],
        report.patterns,
        report.dropped.len(),
        dir.display()
    ))
}

/// The commit `main` points to, from a git `info/refs` advertisement.
fn head_commit(refs: &str) -> Option<&str> {
    [" refs/heads/main", " HEAD\0"].iter().find_map(|marker| {
        let at = refs.find(marker)?;
        let sha = refs.get(at.checked_sub(40)?..at)?;
        sha.bytes().all(|b| b.is_ascii_hexdigit()).then_some(sha)
    })
}

async fn download(collector: &Collector, opts: &Options, url: &str) -> Result<Vec<u8>, String> {
    let target = Target::parse(url)?;
    let snapshot = collector.collect(&target, opts).await;
    match (snapshot.chain.last(), snapshot.page) {
        (Some(hop), Some(page)) if hop.status == 200 && !page.truncated => Ok(page.body),
        (Some(hop), _) => Err(format!("{url}: HTTP {}", hop.status)),
        _ => Err(snapshot
            .failure
            .map_or_else(|| format!("{url}: no response"), |f| f.message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_head_commit() {
        let refs = "001e# service=git-upload-pack\n00000159d91f7e510e93457041bea874e8a9ffb011e3e4fe HEAD\0multi_ack \
                    symref=HEAD:refs/heads/main\n003fd91f7e510e93457041bea874e8a9ffb011e3e4fe refs/heads/main\n0000";
        assert_eq!(head_commit(refs), Some("d91f7e510e93457041bea874e8a9ffb011e3e4fe"));
        assert_eq!(head_commit("0000"), None);
    }
}
