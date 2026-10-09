"""Validate legacy migration without changing user passwords or unrelated YAML."""
import json
import os
from pathlib import Path
import re
import sqlite3
import sys


def prepare(text, users):
    lines = text.splitlines()
    # Repair only the exact orphan produced by the old updater.
    if 'trafficStats:' not in lines:
        matches = [i for i, line in enumerate(lines[:-1])
                   if line == '  listen: 127.0.0.1:9999'
                   and lines[i + 1].startswith('  secret: ')]
        if len(matches) != 1:
            raise ValueError('Statistics section missing; refusing unsafe migration')
        lines.insert(matches[0], 'trafficStats:')
    starts = [i for i, line in enumerate(lines) if line == 'auth:']
    if len(starts) != 1:
        raise ValueError('Expected one auth section')
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines))
                if lines[i] and not lines[i][0].isspace()
                and not lines[i].startswith('#')), len(lines))
    block = lines[start + 1:end]
    port = int(os.environ.get('HYSTERIA_AUTH_PORT', '9998'))
    if '  type: userpass' in block:
        if '  userpass:' not in block:
            raise ValueError('Missing userpass block')
        credentials = {}
        for line in block[block.index('  userpass:') + 1:]:
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'    ([A-Za-z0-9_-]{1,32}):[ \t]*(.*)', line)
            if not match:
                raise ValueError('Unrecognized legacy auth format')
            value = match[2].strip()
            if value.startswith('"'):
                value = json.loads(value)
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1].replace("''", "'")
            credentials[match[1]] = value
        enabled = {name: password for name, password, active in users if active}
        if not credentials or credentials != enabled:
            raise ValueError('VPN and database credentials differ; refusing to change subscriptions')
        lines[start + 1:end] = ['  type: http', '  http:',
                               f'    url: http://127.0.0.1:{port}/auth']
    elif ('  type: http' not in block or
          f'    url: http://127.0.0.1:{port}/auth' not in block):
        raise ValueError('Unrecognized auth backend; refusing to replace it')
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    output = Path(sys.argv[1])
    config = Path(os.environ.get('HYSTERIA_CONFIG', '/etc/hysteria/config.yaml'))
    database = Path(os.environ.get('PANEL_DB', '/var/lib/hysteria-control/panel.db'))
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True) as connection:
        users = connection.execute('select username,password,enabled from users').fetchall()
    output.write_text(prepare(config.read_text(), users), encoding='utf-8')
