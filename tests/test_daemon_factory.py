#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import time
import psutil
import unittest
import tempfile

# Otherwise the supervisor will not be loaded in pytest.
os.environ["START_DAEMON_FACTORY"] = "1"

# This is used by HTTP servers only.
from scripts import daemon_factory

from init import *

class SupervisorTest(unittest.TestCase):

    def test_supervisor_startup(self):
        try:
            supervisor_pid = daemon_factory.supervisor_startup()
        except Exception as exc:
            print("Caught:", exc)
            supervisor_pid = None
            # self.fail(exc)

        self.assertTrue(supervisor_pid is not None)
        self.assertTrue(psutil.pid_exists(supervisor_pid))

        status_stop = daemon_factory.supervisor_stop()
        self.assertTrue(status_stop)
        # Give it a bit of time so the process vanishes.
        time.sleep(0.5)
        self.assertFalse(psutil.pid_exists(supervisor_pid))

    def test_supervisor_running(self):
        sys.stdout.write("Before supervisor_startup\n")
        #sys.stdout.write("daemon_factory._xmlrpc_server_proxy=%s\n" % daemon_factory._xmlrpc_server_proxy)
        try:
            supervisor_pid = daemon_factory.supervisor_startup()
        except Exception as exc:
            raise
            print("Caught:", exc)
            supervisor_pid = None
            # self.fail(exc)

        self.assertTrue(supervisor_pid is not None)
        self.assertTrue(psutil.pid_exists(supervisor_pid))

        try:
            status_running = daemon_factory.is_supervisor_running()
        except:
            pass
        else:
            self.assertTrue(status_running)
        finally:
            status_stop = daemon_factory.supervisor_stop()
            self.assertTrue(status_stop)
        self.assertFalse(psutil.pid_exists(supervisor_pid))


class UserProcessTest(unittest.TestCase):

    def setUp(self):
        daemon_factory.supervisor_startup()

    def tearDown(self):
        daemon_factory.supervisor_stop()

    def test_start_user_process(self):
        """Starts a process and checks that its PID is there."""
        process_name = "test_start_user_process_%d" % os.getpid()
        python_command = '"%s" -c "import time;print(123456);time.sleep(10)"' % sys.executable
        created_process_id = daemon_factory.start_user_process(process_name, python_command)
        self.assertTrue(created_process_id)
        self.assertTrue(psutil.pid_exists(created_process_id))

    def test_generic_process_present(self):
        """Starts a process and checks that its PID is there, and that it can be detected."""
        process_name = "test_generic_process_present_%d" % os.getpid()
        python_command = '"%s" -c "import time;print(123456);time.sleep(10)"' % sys.executable
        sys.stderr.write("python_command=%s\n" % python_command)
        created_process_id = daemon_factory.start_user_process(process_name, python_command)
        self.assertTrue(created_process_id)
        self.assertTrue(psutil.pid_exists(created_process_id))

        status_running = daemon_factory.is_user_process_running(process_name)
        self.assertTrue(status_running)

    def test_generic_process_output_present(self):
        """Starts a process and checks that its PID is there, and that its output can be detected."""
        process_name = "test_generic_process_output_present_%d" % os.getpid()
        secret_string = "This is a secret string written in a file. pid=%d" % os.getpid()
        temporary_output_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_output_file.close()
        temporary_python_file = tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False)
        script_content = """
import time
with open(r"%s", "w") as output_file:
    output_file.write("%s")
    output_file.close()
# So it gives the illusion to be running a long time.
time.sleep(1)
        """ % (temporary_output_file.name, secret_string)
        temporary_python_file.write(script_content)
        temporary_python_file.close()

        python_command = '"%s" "%s"' % (sys.executable, temporary_python_file.name)
        sys.stderr.write("python_command=%s\n" % python_command)
        created_process_id = daemon_factory.start_user_process(process_name, python_command)

        # Wait until the process leave.
        if created_process_id is None:
            while psutil.pid_exists(created_process_id):
                time.sleep(1)
        else:
            print("Could not start python_command=%s\n" % python_command)

        with open(temporary_output_file.name) as input_file:
            file_content = "".join(input_file.readlines())

        self.assertEqual(file_content, secret_string)


if __name__ == '__main__':
    unittest.main()

