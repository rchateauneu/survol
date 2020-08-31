#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
import unittest

# Otherwise the supervisor will not be loaded in pytest.
os.environ["START_DAEMON_FACTORY"] = "1"

# This is used by HTTP servers only.
from scripts import daemon_factory

class SupervisorTest(unittest.TestCase):

    def test_supervisor_startup(self):
        try:
            supervisor_pid = daemon_factory.supervisor_startup()
        except Exception as exc:
            self.fail(exc)

        self.assertIsNotNone(supervisor_pid)

        status_stop = daemon_factory.supervisor_stop()
        self.assertTrue(status_stop)

    def test_supervisor_running(self):
        try:
            supervisor_pid = daemon_factory.supervisor_startup()
        except Exception as exc:
            self.fail(exc)

        self.assertIsNotNone(supervisor_pid)

        try:
            status_running = daemon_factory.is_supervisor_running()
        except:
            pass
        else:
            self.assertTrue(status_running)
        finally:
            status_stop = daemon_factory.supervisor_stop()
            self.assertTrue(status_stop)


class UserProcessTest(unittest.TestCase):

    def setUp(self):
        daemon_factory.supervisor_startup()

    def tearDown(self):
        daemon_factory.supervisor_stop()

    def test_start_user_process(self):
        process_name = "test_start_user_process_%d" % os.getpid()
        python_command = '"%s" -c "import time;print(123456);time.sleep(2)"' % sys.executable
        status_started = daemon_factory.start_user_process(process_name, python_command)
        self.assertTrue(status_started)

    def test_generic_process_present(self):
        process_name = "test_generic_process_present_%d" % os.getpid()
        python_command = '"%s" -c "import time;print(123456);time.sleep(2)"' % sys.executable
        sys.stderr.write("python_command=%s\n" % python_command)
        status_started = daemon_factory.start_user_process(process_name, python_command)
        self.assertTrue(status_started)

        status_running = daemon_factory.is_user_process_running(process_name)
        self.assertTrue(status_running)


if __name__ == '__main__':
    unittest.main()

