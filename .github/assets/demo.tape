# Wingman AGY demo. Render with: vhs .github/assets/demo.tape
# Every command below runs for real against a live Antigravity app and the Gemini API.
Output .github/assets/demo.gif

Set Shell bash
Set FontFamily "IBM Plex Mono"
Set FontSize 15
Set Width 1200
Set Height 640
Set Padding 28
Set TypingSpeed 28ms
Set Theme { "name": "DEViance", "background": "#050505", "foreground": "#F0EDE4", "cursor": "#FF4A1F", "selection": "#242424", "black": "#111111", "red": "#FF4A1F", "green": "#9FD6A3", "yellow": "#E8C07D", "blue": "#2349D8", "magenta": "#B83817", "cyan": "#8CC8D8", "white": "#F0EDE4", "brightBlack": "#85847F", "brightRed": "#FF6B45", "brightGreen": "#B7E3BA", "brightYellow": "#F0D29A", "brightBlue": "#4F6FE8", "brightMagenta": "#D0532E", "brightCyan": "#A6D8E4", "brightWhite": "#FFFFFF" }

Hide
Type `export PS1='› '; agy(){ command agy "$@" 2>&1 | sed "s#$HOME#~#g"; }; clear`
Enter
Show

Type "agy --version"
Enter
Wait@10s /›$/
Sleep 0.8s

Type "agy models | head -8"
Enter
Wait@30s /›$/
Sleep 2.5s

Type "agy ask 'In one sentence: why should a coding agent hand long reads to a second model?'"
Enter
Wait@60s /›$/
Sleep 3s

Type "agy new --yes --model gemini-4-hydrogen-high 'Write a haiku about two AIs pair programming. Reply with only the haiku.' | grep 'ran:'"
Enter
Wait@120s /›$/
Sleep 3s

Hide
Type "sleep 15; id=$(command agy ledger | tail -1 | awk '{print $1}'); clear"
Enter
Wait@60s /›$/
Show

Type "agy tail $id -n 3"
Enter
Wait@30s /›$/
Sleep 5s
