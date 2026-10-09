import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class PanelTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.environ.update(PANEL_DOMAIN='localhost', PANEL_SECRET='test-secret',
                          PANEL_DB=str(Path(self.temp.name, 'panel.db')),
                          HYSTERIA_DYNAMIC_AUTH='1')
        spec = importlib.util.spec_from_file_location('panel_test', ROOT / 'app.py')
        self.panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.panel)
        c = self.panel.conn()
        c.executemany('insert into users values(?,?,?)',
                      [('TestUser1', 'secret', 1), ('Disabled2', 'secret2', 0)])
        c.commit()
        c.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_online_and_unknown_are_distinct(self):
        p = self.panel
        with patch.object(p, 'api_get', side_effect=lambda path:
                          {'TestUser1': 1} if path == '/online' else {}):
            self.assertEqual(p.vpn_state()['online']['TestUser1'], 1)
            self.assertTrue(p.vpn_state()['service'])
        p.vpn_cache['sampled'] = 0
        with patch.object(p, 'api_get', side_effect=OSError('unavailable')):
            self.assertIsNone(p.vpn_state()['online'])
            self.assertIsNone(p.vpn_state()['service'])

    def test_traffic_concurrent_samples_and_counter_reset(self):
        p = self.panel
        threads = [threading.Thread(target=p.record_traffic,
                                    args=({'TestUser1': {'tx': 100, 'rx': 200}},))
                   for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=3)
        p.record_traffic({'TestUser1': {'tx': 100, 'rx': 200}})
        p.record_traffic({'TestUser1': {'tx': 10, 'rx': 20}})
        c = p.conn()
        self.assertEqual(tuple(c.execute('select tx,rx from usage').fetchone()), (110, 220))
        c.close()

    def test_cache_prevents_duplicate_api_requests(self):
        with patch.object(self.panel, 'api_get', return_value={}) as api:
            for _ in range(20): self.panel.vpn_state()
            self.assertEqual(api.call_count, 2)

    def test_add_delete_preserve_other_credentials_and_skip_restart(self):
        p = self.panel
        client = p.app.test_client()
        with client.session_transaction() as session:
            session.update(ok=True, auth_version=p.auth_version(), csrf='token')
        with patch.object(p, 'record_traffic'), patch.object(p, 'kick_user'), \
             patch.object(p.subprocess, 'run') as process:
            self.assertEqual(client.post('/add', data={'u':'NewUser3', 'csrf':'token'}).status_code, 302)
            self.assertEqual(client.post('/delete', data={'u':'NewUser3', 'csrf':'token'}).status_code, 302)
            process.assert_not_called()
        c = p.conn()
        self.assertEqual(c.execute('select password from users where username="TestUser1"').fetchone()[0], 'secret')
        c.close()


class MigrationTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('maintenance', ROOT / 'maintenance.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.tail = 'trafficStats:\n  listen: 127.0.0.1:9999\n  secret: test\nmasquerade:\n  type: proxy\n'
        self.legacy = 'listen: :443\nauth:\n  type: userpass\n  userpass:\n    TestUser1: secret\n' + self.tail

    def test_preserves_top_level_statistics_and_credentials(self):
        result = self.module.prepare(self.legacy, [('TestUser1', 'secret', 1)])
        self.assertTrue(result.endswith(self.tail))
        self.assertIn('type: http', result)
        self.assertEqual(self.module.prepare(result, []), result)

    def test_mismatched_credentials_abort(self):
        with self.assertRaises(ValueError):
            self.module.prepare(self.legacy, [('TestUser1', 'different', 1)])

    def test_repair_known_orphan_statistics(self):
        cfg = 'auth:\n  type: http\n  http:\n    url: http://127.0.0.1:9998/auth\n' + self.tail
        self.assertEqual(self.module.prepare(cfg.replace('trafficStats:\n', ''), []), cfg)


if __name__ == '__main__':
    unittest.main()
