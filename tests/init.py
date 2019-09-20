# This is needed to avoid the message:
# "Hint: make sure your test modules/packages have valid Python names"
# Confusing and incomplete explanation here:
# https://stackoverflow.com/questions/41748464/pytest-cannot-import-module-while-python-can

import os
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
