#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
#import atexit
import unittest
from init import *

update_test_path()

# This is used by CGI scripts only.
import lib_util
import lib_daemon

# This is used by HTTP servers only.
from scripts import daemon_factory


def setUpModule():
    daemon_factory.supervisor_startup()

def tearDownModule():
    daemon_factory.supervisor_stop()

# Always stop the supervisor when leaving, otherwise they accumulate.
# atexit.register(tearDownModule)

class CgiScriptTest(unittest.TestCase):
    # This is just a helper.
    url_prefix = "http://vps516494.ovh.net/Survol/survol/sources_types/"

    def test_is_events_generator_daemon_not_running(self):
        test_url = self.url_prefix + "non_existent_url.py?arg=%d" % os.getpid()
        status_running = lib_daemon.is_events_generator_daemon_running(test_url)
        self.assertTrue(not status_running)

    def test_start_events_generator_daemon(self):
        # http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.
        test_url = self.url_prefix + "events_generator_one_tick_per_second.py?parama=%d&paramb=START" % os.getpid()
        created_process_id = lib_daemon.start_events_generator_daemon(test_url)

        # PYTEST_CURRENT_TEST= tests/test_lib_daemon.py::CgiScriptTest::test_start_events_generator_daemon
        print("PYTEST_CURRENT_TEST=", os.environ["PYTEST_CURRENT_TEST"])

        self.assertTrue(created_process_id)

        status_running = lib_daemon.is_events_generator_daemon_running(test_url)
        self.assertTrue(status_running)
        time.sleep(1)
        self.assertTrue(psutil.pid_exists(created_process_id))

        status_stopped = lib_daemon.stop_events_generator_daemon(test_url)
        self.assertTrue(status_stopped)

        self.assertFalse(psutil.pid_exists(created_process_id))


    # def test_stop_events_generator_daemon(self):
    #     # http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.
    #     test_url = self.url_prefix + "events_generator_one_tick_per_second.py?parama=%d&paramb=STOP" % os.getpid()
    #     created_process_id = lib_daemon.start_events_generator_daemon(test_url)
    #     self.assertTrue(created_process_id)
    #     self.assertTrue(psutil.pid_exists(created_process_id))
    #
    #     status_stopped = lib_daemon.stop_events_generator_daemon(test_url)
    #     self.assertTrue(status_stopped)

    def test_url_to_process_name(self):
        test_url_a = self.url_prefix + "this_url_does_not_exist.py?arg=%d" % (os.getpid() + 1)
        process_name_a = lib_daemon._url_to_process_name(test_url_a)

        test_url_b = self.url_prefix + "this_url_does_not_exist.py?arg=%d" % (os.getpid() + 2)
        process_name_b = lib_daemon._url_to_process_name(test_url_b)
        self.assertTrue(process_name_a != process_name_b)


if __name__ == '__main__':
    unittest.main()

