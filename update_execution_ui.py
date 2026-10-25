from pathlib import Path
path = Path('/home/ubuntu/agentbreaker/client/src/pages/Home.tsx')
text = path.read_text()
old = 'detail={`${item.analysis.category} · ${fmtTime(item.startedAt)} · ${fmtDuration(item.durationMs)}`}'
new = 'detail={`${item.agentName} · ${item.analysis.category} · ${fmtTime(item.startedAt)} · ${fmtDuration(item.durationMs)}`}'
if old not in text:
    raise SystemExit('execution detail marker not found')
path.write_text(text.replace(old, new, 1))
