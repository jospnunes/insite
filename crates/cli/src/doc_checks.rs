//! Checks that the reference docs keep up with the command line: every long
//! flag is named in `docs/usage.md`, and every example command in the docs
//! parses with the real clap definition.

use clap::{Command, CommandFactory};

use crate::Cli;

const USAGE: &str = include_str!("../../../docs/usage.md");
const METHODOLOGY: &str = include_str!("../../../docs/methodology.md");
const README: &str = include_str!("../../../README.md");
const README_PT: &str = include_str!("../../../README.pt-BR.md");

const DEMO_GIF: &str = "https://raw.githubusercontent.com/jospnunes/insite/main/assets/demo.gif";

/// Words the copy rules ban from the READMEs (matched case-insensitively).
const BANNED_WORDS: &[&str] = &[
    "blazingly",
    "powerful",
    "seamless",
    "robust",
    "cutting-edge",
    "comprehensive",
    "effortless",
];

/// Every link and image target outside fenced code blocks: the part inside
/// `](...)`, and the value of `src="..."` and `href="..."`.
fn link_targets(markdown: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut in_block = false;
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block {
            continue;
        }
        let mut rest = line;
        while let Some(start) = rest.find("](") {
            rest = &rest[start + 2..];
            match rest.find(')') {
                Some(end) => {
                    targets.push(rest[..end].to_owned());
                    rest = &rest[end + 1..];
                }
                None => break,
            }
        }
        for attr in ["src=\"", "href=\""] {
            let mut rest = line;
            while let Some(start) = rest.find(attr) {
                rest = &rest[start + attr.len()..];
                if let Some(end) = rest.find('"') {
                    targets.push(rest[..end].to_owned());
                    rest = &rest[end..];
                }
            }
        }
    }
    targets
}

/// Every `--long` name in `command` and its subcommands, without `--help`,
/// `--version` and arguments hidden from `--help`.
fn collect_flags(command: &Command, found: &mut Vec<String>) {
    for arg in command.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        if let Some(long) = arg.get_long()
            && long != "help"
            && long != "version"
            && !found.iter().any(|f| f == long)
        {
            found.push(long.to_owned());
        }
    }
    for sub in command.get_subcommands() {
        collect_flags(sub, found);
    }
}

pub(crate) fn long_flags() -> Vec<String> {
    let mut found = Vec::new();
    collect_flags(&Cli::command(), &mut found);
    found
}

/// A `<name>` token: a placeholder to fill in, not a redirect.
fn has_placeholder(line: &str) -> bool {
    line.match_indices('<').any(|(start, _)| {
        let rest = &line[start + 1..];
        match rest.find('>') {
            Some(end) => {
                let name = &rest[..end];
                !name.is_empty() && !name.contains(char::is_whitespace)
            }
            None => false,
        }
    })
}

/// The commands shown in fenced code blocks: every line that starts with
/// `insite ` or `$ insite ` (at the start of the line, so indented sample
/// output is not read as a command), cut at the first `|`, `<`, `>` or `#` and split on
/// whitespace. Lines with a `<placeholder>` or `...` are not complete commands
/// and are skipped.
pub(crate) fn insite_commands(markdown: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut in_block = false;
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if !in_block {
            continue;
        }
        let command = line.strip_prefix("$ ").unwrap_or(line);
        if !command.starts_with("insite ") {
            continue;
        }
        if has_placeholder(command) || command.contains("...") {
            continue;
        }
        let end = command.find(['|', '<', '>', '#']).unwrap_or(command.len());
        let words: Vec<String> = command[..end].split_whitespace().map(str::to_owned).collect();
        if !words.is_empty() {
            commands.push(words);
        }
    }
    commands
}

fn assert_commands_parse(name: &str, markdown: &str) {
    use clap::Parser;
    for cmd in insite_commands(markdown) {
        if let Err(err) = Cli::try_parse_from(&cmd) {
            panic!("{name}: `{}` does not parse: {err}", cmd.join(" "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_usage_names_every_flag() {
        for f in long_flags() {
            assert!(
                USAGE.contains(&format!("--{f}")),
                "docs/usage.md does not mention --{f}"
            );
        }
    }

    #[test]
    fn docs_usage_commands_parse() {
        assert_commands_parse("docs/usage.md", USAGE);
    }

    #[test]
    fn docs_methodology_commands_parse() {
        assert_commands_parse("docs/methodology.md", METHODOLOGY);
    }

    #[test]
    fn readme_targets_are_absolute() {
        for (name, readme) in [("README.md", README), ("README.pt-BR.md", README_PT)] {
            for target in link_targets(readme) {
                assert!(
                    target.starts_with("https://") || target.starts_with('#'),
                    "{name}: `{target}` is neither an https:// URL nor an in-page anchor"
                );
            }
        }
    }

    #[test]
    fn readme_commands_parse() {
        assert_commands_parse("README.md", README);
        assert_commands_parse("README.pt-BR.md", README_PT);
    }

    #[test]
    fn readme_has_no_banned_words() {
        for (name, readme) in [("README.md", README), ("README.pt-BR.md", README_PT)] {
            let lower = readme.to_lowercase();
            for word in BANNED_WORDS {
                assert!(!lower.contains(word), "{name} uses the banned word `{word}`");
            }
        }
    }

    #[test]
    fn readme_shows_the_demo() {
        assert!(README.contains(DEMO_GIF), "README.md does not show the demo GIF");
        assert!(
            README_PT.contains(DEMO_GIF),
            "README.pt-BR.md does not show the demo GIF"
        );
    }

    #[test]
    fn link_targets_reads_links_images_and_attributes() {
        let md = "\
[a](https://x.test/a) and ![b](docs/b.png) and <img src=\"c.gif\">

```
[not](a/link)
```
";
        assert_eq!(link_targets(md), vec!["https://x.test/a", "docs/b.png", "c.gif"]);
    }

    #[test]
    fn long_flags_lists_real_flags_only() {
        let flags = long_flags();
        for expected in ["modules", "browser", "force", "native-roots", "from"] {
            assert!(flags.iter().any(|f| f == expected), "missing --{expected}");
        }
        assert!(!flags.iter().any(|f| f == "help" || f == "version"));
    }

    #[test]
    fn insite_commands_extracts_complete_commands() {
        let md = "\
insite a.com outside a block

```
$ insite --json a.com | jq .   # pipe and comment are cut
insite explain <id>
insite a.com ...
insite < sites.txt
  insite output indented in a sample screen
other-tool --json
```
";
        assert_eq!(
            insite_commands(md),
            vec![vec!["insite", "--json", "a.com"], vec!["insite"],]
        );
    }
}
