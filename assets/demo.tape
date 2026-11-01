# Regenerate with: vhs assets/demo.tape (needs a release build: cargo build --release -p insite)
Output assets/demo.gif

Set Shell bash
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 15
Set Width 1000
Set Height 650
Set Padding 18
Set Framerate 25
Set TypingSpeed 80ms
Set Theme { "name": "insite", "background": "#0d1117", "foreground": "#f0f6fc", "cursor": "#f0f6fc", "selection": "#21262d", "black": "#21262d", "red": "#f85149", "green": "#3fb950", "yellow": "#d29922", "blue": "#58a6ff", "magenta": "#bc8cff", "cyan": "#39c5cf", "white": "#f0f6fc", "brightBlack": "#8b949e", "brightRed": "#f85149", "brightGreen": "#3fb950", "brightYellow": "#d29922", "brightBlue": "#58a6ff", "brightMagenta": "#bc8cff", "brightCyan": "#39c5cf", "brightWhite": "#f0f6fc" }

Env COLORTERM truecolor
Env LANG pt_BR.utf8

Hide
Type "export PATH=$PWD/target/release:$PATH PS1='$ ' && clear"
Enter
Sleep 500ms
Show

Sleep 2500ms
Type "insite wordpress.org"
Sleep 500ms
Enter
Sleep 4500ms
