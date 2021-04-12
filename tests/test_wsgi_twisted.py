#!/usr/bin/env python

from __future__ import print_function

"""This starts a local WSGI server and runs several queries and tests that the results are the same."""

import cgitb
import unittest

from init import *

update_test_path()

import lib_client

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")

def start_twisted_wsgiserver(agent_port, output_log):
    agent_url = "http://%s:%d" % (CurrentMachine, agent_port)

    returned_exception = check_existing_server(agent_url)
    if returned_exception is None:
        logging.info("Agent already started at %s" & agent_url)
        return None, agent_url

    try:
        # Running the tests scripts from PyCharm is from the current directory.
        os.environ["PYCHARM_HELPERS_DIR"]
        current_dir = ".."
    except KeyError:
        current_dir = ""
    logging.info("current_dir=%s", current_dir)
    logging.info("sys.path=%s", str(sys.path))

    # "-n": Not started in daemon mode so the behaviour is the same on Windows and Linux.
    cmd = ["twistd", "web", "--listen=tcp:%d" % agent_port,
           "--logfile=%s" % output_log,
           "-n",
           "--wsgi=scripts.wsgi_survol.application"]
           #"--wsgi=survol.scripts.wsgi_survol.application"]
    logging.debug("cmd=%s", " ".join(cmd))
    logging.debug("Cwd=%s", os.getcwd())

    my_env = os.environ.copy()
    my_env["PYTHONPATH"] = ".;survol"

    sub_proc = subprocess.Popen(cmd,
                                #shell=True,
                                env=my_env,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    if sub_proc is None:
        raise Exception("Could not start WSGI twisted process")
    print("Started twistd process is:%d\n" % sub_proc.pid)

    time.sleep(2.0)

    return sub_proc, agent_url


def stop_twisted_wsgiserver(sub_proc):
    assert isinstance(sub_proc, subprocess.Popen)

    # Maybe the twisted server exited with an error.
    if psutil.pid_exists(sub_proc.pid):
        print("Twisted WSGI process %d still running" % sub_proc.pid)
    else:
        print("Twisted WSGI process %d has exited" % sub_proc.pid)
        twisted_out, twisted_err = sub_proc.communicate()
        if twisted_err:
            for one_line in twisted_out.split(b'\n'):
                logging.debug("twisted_out=%s", one_line)
            for one_line in twisted_err.split(b'\n'):
                logging.debug("twisted_err=%s", one_line)

    print("Terminating Twisted WSGI process %d" % sub_proc.pid)
    sub_proc.terminate()


@unittest.skipIf(not pkgutil.find_loader('twisted'), "twisted must be installed.")
@unittest.skipIf(not check_program_exists("twistd"), "twistd executable must be available.")
class WsgiTwistedTest(unittest.TestCase):
    _output_log = "survol_twistd.log"
    def setUp(self):
        self.m_remote_wsgi_agent_process, self.m_remote_wsgi_test_agent = start_twisted_wsgiserver(
            RemoteTwistedWsgi1TestServerPort, self._output_log)
        logging.info("Agent=%s", self.m_remote_wsgi_test_agent)
        logging.info("Agent process=%d", self.m_remote_wsgi_agent_process.pid)

    def tearDown(self):
        if self.m_remote_wsgi_agent_process:
            logging.info("Stopping: %s", self.m_remote_wsgi_test_agent)
            stop_twisted_wsgiserver(self.m_remote_wsgi_agent_process)
            with open(self._output_log) as output_fd:
                print("Twistd server output start")
                for one_line in output_fd.readlines():
                    sys.stdout.write("%s" % one_line)
                print("Twistd server output end")
        else:
            logging.info("Was already started: %s", self.m_remote_wsgi_test_agent)

    def test_twisted_wsgi_file_directory(self):
        my_source_file_stat_remote = lib_client.SourceRemote(
            self.m_remote_wsgi_test_agent + "/survol/sources_types/CIM_Directory/file_directory.py",
            "CIM_Directory",
            Name=always_present_dir)
        triple_file_stat_remote = my_source_file_stat_remote.get_triplestore()
        print("Len triple_file_stat_remote=", len(triple_file_stat_remote))
        # This should not be empty.
        self.assertTrue(len(triple_file_stat_remote) >= 1)


if __name__ == '__main__':
    unittest.main()
