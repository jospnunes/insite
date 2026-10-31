//! Checks that the reference docs keep up with the command line: every long
//! flag is named in `docs/usage.md`, and every example command in the docs
//! parses with the real clap definition.

use clap::{Command, CommandFactory};

use crate::Cli;

const USAGE: &str = include_str!("../../../docs/usage.md");
const METHODOLOGY: &str = include_str!("../../../docs/methodology.md");

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
