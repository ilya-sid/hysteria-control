"""Generate a secret-free browser fixture with many users."""
import importlib.util
import os
from pathlib import Path
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    os.environ.update(PANEL_DOMAIN='localhost', PANEL_SECRET='fixture',
                      PANEL_DB=str(Path(temp, 'panel.db')))
    spec = importlib.util.spec_from_file_location('fixture', root / 'app.py')
    panel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(panel)
    c = panel.conn()
    c.executemany('insert into users values(?,?,1)',
                  [(f'User{i:03}', 'fixture-not-a-real-key') for i in range(60)])
    c.commit()
    c.close()
    with panel.app.test_request_context('/'):
        panel.session.update(ok=True, auth_version=panel.auth_version())
        response = panel.home()
        Path('/private/tmp/hc-browser-fixture.html').write_bytes(response.data)
