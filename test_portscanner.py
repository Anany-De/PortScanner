import queue
import socket
import threading
import unittest
from unittest.mock import patch
from portscanner import App, parse_ports, scan


class ScannerTests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(parse_ports('443,22,80-82,80'), [22, 80, 81, 82, 443])
        for value in ['', '0', '65536', '8-2', 'abc', '1-2-3']:
            with self.assertRaises(ValueError):
                parse_ports(value)

    def test_real_loopback(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            events = queue.Queue()
            scan('127.0.0.1', [port], .2, threading.Event(), events)
            messages = list(events.queue)
            self.assertEqual([v[0] for k, v in messages if k == 'open'], [port])
            self.assertIn(('progress', 1), messages)
            self.assertEqual(messages[-1], ('done', False))

    def test_cancel(self):
        stop = threading.Event()
        stop.set()
        events = queue.Queue()
        scan('127.0.0.1', [80], .1, stop, events)
        self.assertEqual(list(events.queue)[-1], ('done', True))
        self.assertFalse(any(k == 'open' for k, _ in list(events.queue)))

    def test_resolution_error(self):
        events = queue.Queue()
        with patch('socket.getaddrinfo', side_effect=socket.gaierror('test failure')):
            scan('invalid', [80], .1, threading.Event(), events)
        self.assertEqual([k for k, _ in list(events.queue)], ['error', 'progress', 'done'])

    def test_pending_timeout_and_active_stop(self):
        import time
        from unittest.mock import MagicMock
        for cancel in (False, True):
            sock = MagicMock()
            sock.connect_ex.return_value = 10035
            stop = threading.Event()
            events = queue.Queue()
            def waiting(*args):
                time.sleep(.01)
                return [], [], []
            timer = threading.Timer(.04, stop.set) if cancel else None
            with patch('socket.socket', return_value=sock), patch('select.select', side_effect=waiting):
                if timer:
                    timer.start()
                started = time.monotonic()
                scan('127.0.0.1', [80], .15, stop, events)
                elapsed = time.monotonic() - started
            if timer:
                timer.join()
            sock.close.assert_called_once()
            self.assertFalse(any(k == 'open' for k, _ in list(events.queue)))
            self.assertEqual(list(events.queue)[-1], ('done', cancel))
            if cancel:
                self.assertLess(elapsed, .14)
            else:
                self.assertGreaterEqual(elapsed, .15)
                self.assertIn(('progress', 1), list(events.queue))

    def test_inventory(self):
        from local_inventory import listener_ports, inventory
        with socket.socket() as listener, socket.socket() as closed:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            closed.bind(('127.0.0.1', 0))
            self.assertIn(listener.getsockname()[1], listener_ports('127.0.0.1'))
            self.assertNotIn(closed.getsockname()[1], listener_ports('127.0.0.1'))
            events = queue.Queue()
            inventory('127.0.0.1', [listener.getsockname()[1]], .5, threading.Event(), events)
            self.assertIsNone(next(v for k, v in list(events.queue) if k == 'open')[2])
        for target in ['192.0.2.1', '::1', 'localhost']:
            with self.assertRaises(ValueError):
                listener_ports(target)

    def test_resource_failure_is_reported(self):
        from unittest.mock import MagicMock
        sock = MagicMock()
        sock.connect_ex.return_value = 10055
        events = queue.Queue()
        with patch('socket.socket', return_value=sock):
            scan('127.0.0.1', [80], .5, threading.Event(), events)
        self.assertTrue(any(k == 'error' for k, _ in list(events.queue)))
        self.assertIn(('progress', 0), list(events.queue))

    def test_gui_scan(self):
        app = App()
        try:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                app.ports.set(str(listener.getsockname()[1]))
                app.start()
                import time
                deadline = time.monotonic() + 5
                while app.running and time.monotonic() < deadline:
                    app.update()
                    time.sleep(.02)
                self.assertFalse(app.running)
                self.assertEqual(len(app.tree.get_children()), 1)
                self.assertEqual(str(app.export_button['state']), 'normal')
        finally:
            app.close()


if __name__ == '__main__':
    unittest.main()
