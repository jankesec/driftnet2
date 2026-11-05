Output "docs/demo.gif"

Set Shell "zsh"
Set Theme "Pro"
Set FontSize 14
Set Width 1200
Set Height 840
Set Padding 20
Set WindowBar Colorful
Set BorderRadius 10
Set LineHeight 1.25
Set TypingSpeed 28ms
Set CursorBlink true

Hide
Type "export PS1='%F{cyan}security@workstation%f %F{magenta}~/driftnet2%f %# '; clear"
Enter
Show

Sleep 600ms
Type "./driftnet2 -pcap examples/demo.pcap -output demo-creds.json -audit"
Sleep 200ms
Enter
Sleep 6s

Type "jq '.credentials[0:2]' demo-creds.json"
Sleep 200ms
Enter
Sleep 3.8s

Hide
Type "rm -f demo-creds.json"
Enter
