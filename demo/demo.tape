# Render with: go build -o dist/agentleaks ./cmd/agentleaks && vhs demo/demo.tape
# The scan runs against a throwaway home built by demo/setup.sh, so no real
# history is shown and every key is fake.

Output demo/demo.gif

Set Shell zsh
Set FontSize 15
Set Width 1180
Set Height 640
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "export PATH=$PWD/dist:$PATH && export AGENTLEAKS_HOME=$(bash demo/setup.sh) && clear"
Enter
Sleep 1s
Show

Type "agentleaks scan"
Enter
Sleep 5s

Type "clear"
Enter
Type "agentleaks fix --yes"
Enter
Sleep 4.5s

Type "clear"
Enter
Type "agentleaks guard"
Enter
Sleep 4s
