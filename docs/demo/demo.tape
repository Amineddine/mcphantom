# Renders docs/demo/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Run from the repository root after `npm ci && npm run build && npm link`:
#   vhs docs/demo/demo.tape
# CI renders it the same way on ubuntu with pinned VHS/ttyd: .github/workflows/demo-gif.yml.

Output docs/demo/demo.gif

Require npm
Require mcphantom

Set Shell bash
Set FontSize 15
Set Width 1260
Set Height 560
Set Padding 16
Set TypingSpeed 35ms
Set Theme "Builtin Dark"

# Fixed state directory so the trace command below is reproducible.
Hide
Type "export MCPHANTOM_HOME=/tmp/mcphantom-demo PS1='$ ' && rm -rf /tmp/mcphantom-demo && clear"
Enter
Show

Type "npm run demo --silent"
Sleep 400ms
Enter
Wait+Screen@120s /Inspect the full taint trace/
Sleep 7s

Type "clear && mcphantom trace --last --data-dir /tmp/mcphantom-demo/data/demo"
Sleep 400ms
Enter
Wait+Screen@30s /evidence/
Sleep 6s
