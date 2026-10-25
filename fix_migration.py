import json
from pathlib import Path

root = Path('/home/ubuntu/agentbreaker')
journal_path = root / 'drizzle/meta/_journal.json'
data = json.loads(journal_path.read_text())
data['entries'] = [entry for entry in data['entries'] if entry.get('tag') not in {'0002_absent_jubilee', '0003_opposite_leo'}]
for idx, entry in enumerate(data['entries']):
    entry['idx'] = idx
journal_path.write_text(json.dumps(data, indent=2) + '\n')
for name in ('0002_absent_jubilee.sql', '0003_opposite_leo.sql', '0002_snapshot.json', '0003_snapshot.json'):
    path = root / 'drizzle' / ('meta/' if name.endswith('.json') else '') / name
    if path.exists():
        path.unlink()
