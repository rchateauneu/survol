# This is needed to avoid the message:
# "Hint: make sure your test modules/packages have valid Python names"
# Confusing and incomplete explanation here:
# https://stackoverflow.com/questions/41748464/pytest-cannot-import-module-while-python-can

import os
import sys
import socket
import psutil

CurrentMachine = socket.gethostname().lower()
try:
    CurrentUsername = os.environ["USERNAME"]
    # The class of users is different on Linux and Windows.
    CurrentUserPath = "Win32_UserAccount.Name=%s,Domain=localhost" % CurrentUsername
except KeyError:
    # This is for Linux.
    CurrentUsername = os.environ["USER"]
    CurrentUserPath = "LMI_Account.Name=%s,Domain=localhost" % CurrentUsername

CurrentPid = os.getpid()
CurrentProcessPath = 'CIM_Process.Handle=%d' % CurrentPid
CurrentParentPid = psutil.Process().ppid()

# For example /usr/bin/python2.7
# Typical situation of symbolic links:
# /usr/bin/python => python2 => python2.7
# Several Python scripts return this executable as a node.
execPath = os.path.realpath( sys.executable )
if sys.platform.startswith("win"):
    execPath = execPath.replace("\\","/"),
CurrentExecutablePath = 'CIM_DataFile.Name=%s' % execPath

# https://stackoverflow.com/questions/46978624/python-multiprocessing-process-to-use-virtualenv
print(__file__+" sys.executable=%s"%sys.executable)
print(__file__+" sys.exec_prefix=%s"%sys.exec_prefix)
