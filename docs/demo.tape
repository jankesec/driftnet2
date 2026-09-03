Output "docs/demo.gif"
Set Theme "TokyoNight"
Set FontSize 13
Set Width 920
Set Height 640
Set Padding 22
Set WindowBar "Colorful"
Set BorderRadius 10

Hide
Type "clear"
Enter
Show

Type "./driftnet2 -pcap examples/demo.pcap -output creds.json -audit"
Sleep 0.5s
Enter
Sleep 8.5s

Type "cat creds.json | jq '.credentials[0:2]'"
Sleep 0.5s
Enter
Sleep 4.5s
