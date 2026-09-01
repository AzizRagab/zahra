# Pentest Swarm AI — the flashy demo.
# Regenerate with:   vhs docs/demo-flashy.tape
#
# Runs `pentestswarm demo` — a fully scripted, network-free walkthrough
# of a simulated campaign. ASCII banner, progress bars with spinners,
# colored severity stream, attack-chain execution, final summary.
# No API key required; no packets go out.

Output docs/demo-flashy.gif

Set Shell "zsh"
Set FontSize 13
Set Width 1280
Set Height 820
Set Theme "Dracula"
Set TypingSpeed 30ms
Set PlaybackSpeed 1.0
Set WindowBar Colorful
Set Margin 20
Set MarginFill "#674EFF"
Set BorderRadius 10
Set LineHeight 1.15
Set LetterSpacing 0.5

# ---- Put pentestswarm on PATH ----
Hide
Type `export PATH="$(pwd)/bin:$PATH"`
Enter
Type "clear"
Enter
Show

Type "pentestswarm demo --target acme.corp"
Sleep 600ms
Enter

# Let the demo run. Tool bars + event stream + summary together are ~20s
# at normal tempo. Pad a touch at the end so the final summary lingers.
Sleep 22s
