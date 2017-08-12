#!/usr/bin/python

import re
import sys
import psutil
import cgi

import lib_util
import lib_common
from sources_types import CIM_Process

print ("""Content-Type: text/html

<html>
<head>
<title>Subtasks control and management</title>
</head>
<body>
""")

# If not a cleanup, then normal display.

print('<form action="task_control.py" method="post">')

def MakeProcDictWindows():
	procDict = dict()

	for proc in psutil.process_iter():
		procName = CIM_Process.PsutilProcToName(proc)
		# procName = proc.name

		# OK pour le process creer par httpd, sous Windows.
		# C:\Python\3.2.3-0.3\pythonw.exe -u D:/Projects/Divers/Reverse/PythonStyle/survol/task_control.py
		#if procName != "pythonw.exe":
		#	continue

		# Might be different depending on the Python interpreter.
		if procName != "python.exe":
			continue

		# With a real subtask:
		# python.exe	18980	24656	C:\Python\3.2.3-0.3\python.exe	C:\Python\3.2.3-0.3\python.exe -c from multiprocessing.forking import main; main() --multiprocessing-fork 788
		# python.exe	24656	14680	C:\Python\3.2.3-0.3\python.exe	python D:/Projects/Divers/Reverse/PythonStyle/survol/sources_top/psutil_processes_perf.py run

		procCmd = CIM_Process.PsutilProcToCmdline(proc)

		pid = proc.pid
		parent_pid = CIM_Process.PsutilProcToPPid(proc)

		# This differentiates between the feeder and the sub-server.
		# This test but get better, but it is OK for the moment.
		mtch_task = re.match( ".*/survol/(.*) run", procCmd )
		if mtch_task:
			subDct = { 'parentPid':parent_pid, 'script': mtch_task.group(1) }
			try:
				procDict[ pid ].update( subDct.items() )
			except KeyError:
				procDict[ pid ] = subDct
			continue

		if re.match( ".*multiprocessing.forking.*", procCmd ):
			subDct = { 'subPid':pid, 'subScript': procCmd }
			try:
				procDict[ parent_pid ].update( subDct.items() )
			except KeyError:
				procDict[ parent_pid ] = subDct
			continue
	return procDict

def MakeProcDictLinux():
	procDict = dict()

	for proc in psutil.process_iter():

		procName = proc.name

		# BEWARE: It depends on the interpreter.
		if procName != "python":
			continue

		# With a real subtask:
		# apache    8423     1  0 12:36 ?        00:00:00 python /home/rchateau/public_html/RevPython/survol/sources_top/tcpdump.py run
		# apache    8426  8423  0 12:36 ?        00:00:00 python /home/rchateau/public_html/RevPython/survol/sources_top/tcpdump.py run

		procCmd = CIM_Process.PsutilProcToCmdline(proc)

		pid = proc.pid
		parent_pid = CIM_Process.PsutilProcToPPid(proc)

		# This differentiates between the feeder and the sub-server.
		# This test but get better, but it is OK for the moment.
		mtch_task = re.match( ".*/survol/(.*) run", procCmd )
		if mtch_task:
			if parent_pid == 1:
				subDct = { 'parentPid':parent_pid, 'script': mtch_task.group(1) }
				try:
					procDict[ pid ].update( subDct.items() )
				except KeyError:
					procDict[ pid ] = subDct
			else:
				subDct = { 'subPid':pid, 'subScript': procCmd }
				try:
					procDict[ parent_pid ].update( subDct.items() )
				except KeyError:
					procDict[ parent_pid ] = subDct
			continue
	return procDict

# It would be better to have these processes register themselves globally.
# But by directly listing the processes, we are safe from a bug in registering
# logic. Also it helps debugging sub-servers.
def MakeProcDict():
	if lib_util.isPlatformWindows:
		return MakeProcDictWindows()
	else:
		return MakeProcDictLinux()

procDict = MakeProcDict()



arguments = cgi.FieldStorage()
try:
	valAct = arguments.getvalue('submit_stop')
	checkPids = arguments.getlist('checkpid')
except KeyError:
	valAct = ""

if valAct == "Stop":
	print("Stop<br>")
	for pid in checkPids:
		print("<br>Killing process " + pid)

		lib_common.KillProc(int(pid))

		try:
			# Maybe the process disappeared.
			subTask = procDict[int(pid)]
		except KeyError:
			continue

		try:
			subPid = subTask['subPid']
			lib_common.KillProc(subPid)

			print(" sub=" + str(subPid) )
		except KeyError:
			pass

	print("<br>")

	# The list has changed because some processes were killed.
	procDict = MakeProcDict()
else:
	print("Display only<br>")

# Now this makes a second independent pass to get the port number.
# This starts each script in 'info' mode so that the subtask is not created.
for pid in procDict:
	subTask = procDict[pid]
	script = subTask['script']
	full_url = lib_util.uriRoot + "/" + script
	dictInfo = "MUST USE __doc__"
	sys.stderr.write("dictInfo=%s\n" % str(dictInfo) )
	try:
		subTask['PortNum'] = str(dictInfo['port_number'])
	except KeyError:
		pass


print('<table border=1 width="100%">')
print("<tr><td width=20></td><td width=80>Pid</td><td>Name</td><td width=80>PPid</td><td width=80>SubPid</td><td width=80>Port</td><td>Feeder command</td></tr>")

for pid in procDict:
	subTask = procDict[pid]

	# Different on Linux
	# OK pour le process creer par httpd, sous Windows.
	# C:\Python\3.2.3-0.3\pythonw.exe -u D:/Projects/Divers/Reverse/PythonStyle/survol/task_control.py
	#if procName != "pythonw.exe":
	#	continue

	print("<tr>")
	print('<td><input type="checkbox" name="checkpid" value="'+str(pid)+'" >'+"</td>")

	print("<td>"+str(pid)+"</td>")
	print("<td>"+subTask['script']+"</td>")
	print("<td>"+str(subTask['parentPid'])+"</td>")

	try:
		print("<td>"+str(subTask['subPid'])+"</td>")
	except KeyError:
		print("<td></td>")

	try:
		portNum = subTask['PortNum']
		url = "http://127.0.0.1:" + portNum + "/infoqueues"
		print("<td><a href='" + url + "'>" + portNum + "</a></td>")
	except KeyError:
		print("<td></td>")

	try:
		print("<td>"+subTask['subScript']+"</td>")
	except KeyError:
		print("<td></td>")

	print("</tr>")



print("</table>")


print("""
<br>
<br>
<input type="submit" name="submit_stop" value="Stop">
<input type="submit" name="submit_refresh" value="Refresh">
</form>
""")



print("""
<br>
<a href="../index.htm">Home</a>
</body>
</html>
""")
