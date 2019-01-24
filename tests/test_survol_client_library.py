from __future__ import print_function

import cgitb
import unittest
import subprocess
import sys
import os
import time
import socket
import platform

# This does basically the same tests as a Jupyter notebook test_client_library.ipynb

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# TODO: Remove this hard-code.
filRoot = "C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\survol"
if sys.path[0] != filRoot:
	sys.path.insert(0,filRoot)
	# print(sys.path)

CurrentUsername = os.environ["USERNAME"]
# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"

# TODO: This should be a parameter. This is an Apache server pointing on the current directory.
# This should behave exactly like the CGI server. It needs the default HTTP port.
RemoteTestApacheAgent = "http://192.168.0.14:80/Survol"

isVerbose = ('-v' in sys.argv) or ('--verbose' in sys.argv)

# This deletes the module so we can reload them each time.
# Problem: survol modules are not detectable.
# We could as well delete all modules except sys.
allModules = [ modu for modu in sys.modules if modu.startswith("survol") or modu.startswith("lib_")]

for modu in allModules:
	# sys.stderr.write("Deleting %s\n"%modu)
	del sys.modules[modu]

import lib_client
import lib_properties

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")

# TODO: Prefix of url samples should be a parameter.

class SurvolLocalTest(unittest.TestCase):
	"""These tests do not need a Survol agent"""

	def test_create_source_local(self):
		mySourceFileStatLocal = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		print("qryFileStatLocal=%s"%mySourceFileStatLocal.UrlQuery())
		print("jsonFileStatLocal=%s ..."%str(mySourceFileStatLocal.content_json())[:30])
		print("rdfFileStatLocal=%s ..."%str(mySourceFileStatLocal.content_rdf())[:30])

	def test_local_triplestore(self):
		mySourceFileStatLocal = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		tripleFileStatLocal = mySourceFileStatLocal.GetTriplestore()
		print("Len triple store local=",len(tripleFileStatLocal.m_triplestore))

	def test_local_instances(self):
		mySourceFileStatLocal = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")

		import lib_common
		lib_common.globalErrorMessageEnabled = False

		tripleFileStatLocal = mySourceFileStatLocal.GetTriplestore()
		print("Len tripleFileStatLocal=",len(tripleFileStatLocal))

		# Typical output:
		# 	Win32_Group.Domain=NT SERVICE,Name=TrustedInstaller
		# 	CIM_Directory.Name=C:/
		# 	CIM_Directory.Name=C:/Windows
		# 	CIM_DataFile.Name=C:/Windows/explorer.exe
		instancesFileStatLocal = tripleFileStatLocal.GetInstances()

		lenInstances = len(instancesFileStatLocal)
		sys.stdout.write("Len tripleFileStatLocal=%s\n"%lenInstances)
		for oneInst in instancesFileStatLocal:
			sys.stdout.write("    %s\n"%str(oneInst))
		# This file should be there on any Windows machine.
		self.assertTrue(lenInstances>=1)

	def test_local_json(self):
		# Test merge of heterogeneous data sources.
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")

		content1 = mySource1.content_json()
		print( "content1=",str(content1.keys()))

	def test_merge_add_local(self):
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceLocal(
			"sources_types/win32/enumerate_Win32_Product.py")

		mySrcMergePlus = mySource1 + mySource2
		print("Merge plus:",str(mySrcMergePlus.content_rdf())[:30])
		triplePlus = mySrcMergePlus.GetTriplestore()
		print("Len triplePlus:",len(triplePlus))

		lenSource1 = len(mySource1.GetTriplestore().GetInstances())
		lenSource2 = len(mySource2.GetTriplestore().GetInstances())
		lenPlus = len(triplePlus.GetInstances())
		# In the merged link, there cannot be more instances than in the input sources.
		self.assertTrue(lenPlus <= lenSource1 + lenSource2)

	def test_merge_sub_local(self):
		try:
			import win32net
		except ImportError:
			print("Module win32net is not available so this test is not applicable")
			return

		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceLocal(
			"sources_types/win32/win32_local_groups.py")

		mySrcMergeMinus = mySource1 - mySource2
		print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
		tripleMinus = mySrcMergeMinus.GetTriplestore()
		print("Len tripleMinus:",len(tripleMinus))

		lenSource1 = len(mySource1.GetTriplestore().GetInstances())
		lenMinus = len(tripleMinus.GetInstances())
		# There cannot be more instances after removal.
		self.assertTrue(lenMinus <= lenSource1 )

	def test_merge_duplicate(self):
		try:
			import win32api
		except ImportError:
			print("Module win32api is not available so this test is not applicable")
			return

		mySourceDupl = lib_client.SourceLocal(
			"sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py",
			"Win32_UserAccount",
			Domain=CurrentMachine,
			Name=CurrentUsername)
		tripleDupl = mySourceDupl.GetTriplestore()
		print("Len tripleDupl=",len(tripleDupl.GetInstances()))

		mySrcMergePlus = mySourceDupl + mySourceDupl
		triplePlus = mySrcMergePlus.GetTriplestore()
		print("Len triplePlus=",len(triplePlus.GetInstances()))
		# No added node.
		self.assertEqual(len(triplePlus.GetInstances()), len(tripleDupl.GetInstances()))

		mySrcMergeMinus = mySourceDupl - mySourceDupl
		tripleMinus = mySrcMergeMinus.GetTriplestore()
		print("Len tripleMinus=",len(tripleMinus.GetInstances()))
		self.assertEqual(len(tripleMinus.GetInstances()), 0)

	# http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui


	def test_exception_bad_source(self):
		# This tests if errors are properly displayed.
		mySourceBad = lib_client.SourceLocal(
			"xxx/yyy/zzz.py",
			"this-will-raise-an-exception")
		try:
			tripleBad = mySourceBad.GetTriplestore()
		except Exception as exc:
			print("Error detected:",exc)

		mySourceBroken = lib_client.SourceRemote(
			RemoteTestAgent + "/xxx/yyy/zzz/ttt.py",
			"wwwww")
		try:
			tripleBroken = mySourceBroken.GetTriplestore()
			excRaised = False
		except Exception as exc:
			excRaised = True
		self.assertTrue(excRaised)

	def test_instance_filter(self):
		# Filter from a triple store by creating a mask like:
		# inst = lib_client.CMI_DataFile
		print("TODO: test_instance_filter not implemented yet")


	def test_sparql(self):
		# https://en.wikipedia.org/wiki/SPARQL
		# PREFIX foaf: <http://xmlns.com/foaf/0.1/>
		# SELECT ?name
		# 	   ?email
		# WHERE
		#   {
		# 	?person  a          foaf:Person .
		# 	?person  foaf:name  ?name .
		# 	?person  foaf:mbox  ?email .
		#   }
		#
		# TODO: Use rdflib implementation:
		# https://rdflib.readthedocs.io/en/3.4.0/intro_to_sparql.html
		print("TODO: test_sparql not implemented yet")

	def test_wql(self):
		# SELECT * FROM meta_class WHERE NOT __class < "win32"="" and="" not="" __this="" isa="">
		# "Select * from win32_Process where name like '[H-N]otepad.exe'"
		print("TODO: test_wql not implemented yet")

	def test_local_scripts_UserAccount(self):
		"""Returns all scripts accessible from current user account."""

		myInstancesLocal = lib_client.Agent().Win32_UserAccount(
			Domain=CurrentMachine,
			Name=CurrentUsername)

		listScripts = myInstancesLocal.GetScripts()
		if isVerbose:
			sys.stdout.write("Scripts:\n")
			for oneScr in listScripts:
				sys.stdout.write("    %s\n"%oneScr)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_grep_string(self):
		"""Searches for printable strings in a file"""

		sampleFile = os.path.join( os.path.dirname(__file__), "SampleDir", "SampleFile.txt" ).replace("\\","/")

		mySourceGrep = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/grep_text_strings.py",
			"CIM_DataFile",
			Name=sampleFile)

		tripleGrep = mySourceGrep.GetTriplestore()
		assert(len(tripleGrep.m_triplestore)==190)

		matchingTriples = tripleGrep.GetMatchingStringsTriples("[Pp]ellentesque")

		lstStringsOnly = sorted( [ trpObj.value for trpSubj,trpPred,trpObj in matchingTriples ] )

		assert( lstStringsOnly == [u'Pellentesque;14;94', u'Pellentesque;6;36', u'Pellentesque;8;50', u'pellentesque;10;66', u'pellentesque;14;101'])


	def test_local_scripts_from_local_source(self):
		"""Loads the scripts of instances displayed by an initial script"""

		try:
			import win32net
		except ImportError:
			print("Module win32net is not available so this test is not applicable")
			return

		# This is a top-level script.
		mySourceTopLevelLocal = lib_client.SourceLocal(
			"sources_types/win32/win32_local_groups.py")

		tripleTopLevelLocal = mySourceTopLevelLocal.GetTriplestore()
		instancesTopLevelLocal = tripleTopLevelLocal.GetInstances()

		if isVerbose:
			for oneInst in instancesTopLevelLocal:
				sys.stdout.write("    Scripts: %s\n"%str(oneInst))
				listScripts = oneInst.GetScripts()
				for oneScr in listScripts:
					sys.stdout.write("        %s\n"%oneScr)

	def test_scripts_of_local_instance(self):
		"""This loads scripts of a local instance"""

		try:
			import win32service
		except ImportError:
			print("Module win32service is not available so this test is not applicable")
			return

		# The service "PlugPlay" should be available on all Windows machines.
		myInstanceLocal = lib_client.Agent().Win32_Service(
			Name="PlugPlay")

		listScripts = myInstanceLocal.GetScripts()

		if isVerbose:
			sys.stdout.write("Scripts:\n")
			for oneScr in listScripts:
				sys.stdout.write("    %s\n"%oneScr)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_instances_cache(self):
		instanceA = lib_client.Agent().CIM_Directory( Name="C:/Windows")
		instanceB = lib_client.Agent().CIM_Directory( Name="C:/Windows")
		instanceC = lib_client.CreateCIMClass(None,"CIM_Directory",Name="C:/Windows")
		if isVerbose:
			sys.stdout.write("Class=%s\n"%instanceC.__class__.__name__)
			sys.stdout.write("Module=%s\n"%instanceC.__module__)
			sys.stdout.write("Dir=%s\n\n"%str(dir(lib_client)))
			sys.stdout.write("Dir=%s\n"%str(sorted(globals())))

		assert( instanceA is instanceB )
		assert( instanceA is instanceC )
		assert( instanceC is instanceB )

	# This searches the content of a file which contains SQL queries.
	def test_regex_sql_query_file(self):
		"""Searches for SQL queries in one file only."""

		try:
			import sqlparse
		except ImportError:
			print("Module sqlparse is not available so this test is not applicable")
			return

		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

		mySourceSqlQueries = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/grep_sql_queries.py",
			"CIM_DataFile",
			Name=sqlPathName)

		tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
		if isVerbose:
			print("Len tripleSqlQueries=",len(tripleSqlQueries.m_triplestore))
		assert( len(tripleSqlQueries.m_triplestore)==3 )

		matchingTriples = tripleSqlQueries.GetAllStringsTriples()

		lstQueriesOnly = sorted( [ trpObj.value for trpSubj,trpPred,trpObj in matchingTriples ] )

		if isVerbose:
			print("lstQueriesOnly:",lstQueriesOnly)

		# TODO: Eliminate the last double-quote.
		assert( lstQueriesOnly[0] == u'select * from \'AnyTable\'"')
		assert( lstQueriesOnly[1] == u'select A.x,B.y from AnyTable A, OtherTable B"')
		assert( lstQueriesOnly[2] == u'select a,b,c from \'AnyTable\'"')

		assert( len(lstQueriesOnly) == 3 )

	# This searches the content of a process memory which contains a SQL memory.
	def test_regex_sql_query_from_batch_process(self):
		print("test_regex_sql_query_from_batch_process: Broken")
		return

		try:
			if 'win' in sys.platform:
				import win32con
		except ImportError:
			print("Module win32con is not available so this test is not applicable")
			return

		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "CommandExample.bat" )

		execList = [ sqlPathName ]

		# Runs this process: It allocates a variable containing a SQL query, then it waits.
		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

		print("Started process:",execList," pid=",procOpen.pid)

		(child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)

		#print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

		mySourceSqlQueries = lib_client.SourceLocal(
			"sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
		print(len(tripleSqlQueries))
		assert(len(tripleSqlQueries.m_triplestore)==190)

		lstMatches = list(tripleSqlQueries.GetInstances("[Pp]ellentesque"))
		print("Matches:",lstMatches)
		assert( len(lstMatches) == 5 )

		# Any string will do.
		child_stdin.write("Stop")
		#procOpen.kill()
		#procOpen.communicate()
		#child_stdin.close()
		#child_stdout_and_stderr.close()

		print(lstMatches)

	# This searches the content of a process memory which contains a SQL memory.
	def test_regex_sql_query_from_python_process(self):
		print("test_regex_sql_query_from_python_process: Broken")
		return

		try:
			if 'win' in sys.platform:
				import win32con
		except ImportError:
			print("Module win32con is not available so this test is not applicable")
			return

		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

		execList = [ sys.executable, sqlPathName ]
		#execList = [ '"' + sys.executable + '"', sqlPathName ]
		# execList = [ '"python.exe"', sqlPathName ]
		#execList = '"' + sys.executable + '" "' + sqlPathName + '"'

		# Runs this process: It allocates a variable containing a SQL query, then it waits.
		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

		print("Started process:",execList," pid=",procOpen.pid)

		# Reading from procOpen.stdout is buffered and one cannot get data until trhe process leaves, or so.
		#print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

		mySourceSqlQueries = lib_client.SourceLocal(
			"sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
		print("len(tripleSqlQueries)=",len(tripleSqlQueries))

		matchingTriples = list(tripleSqlQueries.GetAllStringsTriples())
		print("mmm=",matchingTriples)

		# (child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)
		child_stdin = procOpen.stdin
		( child_stdout_content, child_stderr_content ) = procOpen.communicate()

		print("Read:",child_stdout_content)
		sys.stdout.flush()

		# This ensures that the suprocess is correctly started.
		assert(child_stdout_content.startswith(b"Starting subprocess"))

		print("procOpen.returncode=",procOpen.returncode)
		assert(procOpen.returncode == 123)
		#assert(len(tripleSqlQueries.m_triplestore)==190)

	# This searches the content of a process memory which contains a SQL memory.
	def test_regex_sql_query_from_perl_process(self):
		print("test_regex_sql_query_from_perl_process: Broken")
		return

		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SamplePerlScript.pl" )

		execList = [ "perl", sqlPathName ]
		#execList = [ '"' + sys.executable + '"', sqlPathName ]
		# execList = [ '"python.exe"', sqlPathName ]
		#execList = '"' + sys.executable + '" "' + sqlPathName + '"'

		# Runs this process: It allocates a variable containing a SQL query, then it waits.
		# procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

		print("Started process:",execList," pid=",procOpen.pid)

		# Reading from procOpen.stdout is buffered and one cannot get data until trhe process leaves, or so.
		#print("child_stdout_and_stderr=",child_stdout_and_stderr.readline())

		mySourceSqlQueries = lib_client.SourceLocal(
			"sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
		print("len(tripleSqlQueries)=",len(tripleSqlQueries))

		matchingTriples = list(tripleSqlQueries.GetAllStringsTriples())
		print("mmm=",matchingTriples)

		# (child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)
		child_stdin = procOpen.stdin
		( child_stdout_content, child_stderr_content ) = procOpen.communicate()

		print("Read:",child_stdout_content)
		sys.stdout.flush()

		# This ensures that the suprocess is correctly started.
		assert(child_stdout_content.startswith(b"Starting subprocess"))

		print("procOpen.returncode=",procOpen.returncode)
		assert(procOpen.returnCode == 123)
		#assert(len(tripleSqlQueries.m_triplestore)==190)

	def test_open_files_from_python_process(self):
		"""Files open by a Python process"""
		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

		execList = [ sys.executable, sqlPathName ]

		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

		print("Started process:",execList," pid=",procOpen.pid)

		mySourceSqlQueries = lib_client.SourceLocal(
			"sources_types/CIM_Process/process_open_files.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleSqlQueries = mySourceSqlQueries.GetTriplestore()
		lstInstances = tripleSqlQueries.GetInstances()
		strInstances = sorted([str(oneInst) for oneInst in lstInstances ])

		print("Instances=",strInstances)
		if sys.platform.startswith("win"):
			assert( strInstances ==
				[
					"CIM_DataFile.Name=C:/Windows/System32/cmd.exe",
					"CIM_Process.Handle=%d"%procOpen.pid,
					"Win32_UserAccount.Name=%s,Domain=localhost" % CurrentUsername
				])
		else:
			print("Linux case: Not implemented yet")
			assert(False)

		( child_stdout_content, child_stderr_content ) = procOpen.communicate()

		# This ensures that the subprocess is correctly started and finished.
		assert(child_stdout_content.startswith(b"Starting subprocess"))
		assert(procOpen.returncode == 123)

	def test_sub_parent_from_python_process(self):
		"""Sub and parent processes a Python process"""
		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

		execList = [ sys.executable, sqlPathName ]

		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

		print("Started process:",execList," pid=",procOpen.pid)

		mySourceProcesses = lib_client.SourceLocal(
			"sources_types/CIM_Process/single_pidstree.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleProcesses = mySourceProcesses.GetTriplestore()

		lstInstances = tripleProcesses.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		print("Instances=",strInstancesSet)

		# TODO: Check the presence of sys.executable ?

		# Some instances are required.
		if sys.platform.startswith("win"):
			for oneStr in [
					"CIM_DataFile.Name=C:/Windows/System32/cmd.exe",
					"CIM_Process.Handle=%d"%os.getpid(), # This is the parent process.
					"CIM_Process.Handle=%d"%procOpen.pid,
					"Win32_UserAccount.Name=%s,Domain=localhost" % CurrentUsername ]:
				assert( oneStr in strInstancesSet)
		else:
			print("Linux case: Not implemented yet")
			assert(False)

		( child_stdout_content, child_stderr_content ) = procOpen.communicate()

		# This ensures that the suprocess is correctly started and finished.
		assert(child_stdout_content.startswith(b"Starting subprocess"))
		assert(procOpen.returncode == 123)

	def test_memory_maps_from_python_process(self):
		"""Sub and parent processes a Python process"""
		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

		execList = [ sys.executable, sqlPathName ]

		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

		print("Started process:",execList," pid=",procOpen.pid)

		# Give a bit of time so the process is fully init.
		time.sleep(1)

		mySourceMemMaps = lib_client.SourceLocal(
			"sources_types/CIM_Process/process_memmaps.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleMemMaps = mySourceMemMaps.GetTriplestore()

		lstInstances = tripleMemMaps.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# print("Instances=",strInstancesSet)

		# Some instances are required.
		if sys.platform.startswith("win"):
			# This is common to Windows 7 and Windows 8.
			for oneStr in [
				'CIM_Process.Handle=%s'%procOpen.pid,
				'memmap.Id=C:/Windows/Globalization/Sorting/SortDefault.nls',
				'memmap.Id=C:/Windows/System32/kernel32.dll',
				'memmap.Id=C:/Windows/System32/locale.nls',
				'memmap.Id=C:/Windows/System32/ntdll.dll',
				'memmap.Id=C:/Windows/System32/KernelBase.dll',
				'memmap.Id=C:/Windows/System32/msvcrt.dll',
				'memmap.Id=C:/Windows/System32/cmd.exe',
				]:
				assert( oneStr in strInstancesSet)
		else:
			print("Linux case: Not implemented yet")
			assert(False)

		( child_stdout_content, child_stderr_content ) = procOpen.communicate()

		# This ensures that the suprocess is correctly started and finished.
		assert(child_stdout_content.startswith(b"Starting subprocess"))
		assert(procOpen.returncode == 123)

	def test_environment_from_batch_process(self):
		"""Tests that we can read a process'environment variables"""

		try:
			import psutil
		except ImportError:
			print("Module psutil is not available so this test is not applicable")
			return


		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "CommandExample.bat" )

		execList = [ sqlPathName ]

		# Runs this process: It allocates a variable containing a SQL query, then it waits.
		procOpen = subprocess.Popen(execList, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

		print("Started process:",execList," pid=",procOpen.pid)

		(child_stdin, child_stdout_and_stderr) = (procOpen.stdin, procOpen.stdout)

		mySourceEnvVars = lib_client.SourceLocal(
			"sources_types/CIM_Process/environment_variables.py",
			"CIM_Process",
			Handle=procOpen.pid)

		tripleEnvVars = mySourceEnvVars.GetTriplestore()

		matchingTriples = tripleEnvVars.GetAllStringsTriples()

		# The environment variables are returned in various ways,
		# but it is garanteed that some of them are alwasy present.
		setEnvVars = set( [ trpObj.value for trpSubj,trpPred,trpObj in matchingTriples ] )

		if 'win' in sys.platform:
			mandatoryEnvVars = ['COMPUTERNAME','OS','PATH']
		else:
			mandatoryEnvVars = ['HOSTNAME','PATH']

		for oneVar in mandatoryEnvVars:
			assert( oneVar in setEnvVars )

		print("lstQueriesOnly:",setEnvVars)

		# Any string will do: This stops the subprocess which is waiting for an input.
		child_stdin.write("Stop".encode())

	def test_python_package_information(self):
		"""Tests Python package information"""

		mySourcePythonPackage = lib_client.SourceLocal(
			"entity.py",
			"python/package",
			Id="rdflib")

		triplePythonPackage = mySourcePythonPackage.GetTriplestore()

		lstInstances = triplePythonPackage.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		DEBUG("strInstancesSet=%s",strInstancesSet)

		# Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
		for oneStr in [
			'CIM_ComputerSystem.Name=localhost',
			'python/package.Id=isodate',
			'python/package.Id=pyparsing',
			'python/package.Id=rdflib',
			'Win32_UserAccount.Name=%s,Domain=localhost' % CurrentUsername]:
			DEBUG("oneStr=%s",oneStr)
			assert( oneStr in strInstancesSet)

	def test_python_current_script(self):
		"""Examines a running Python process"""

		# This creates a process running in Python, because it does not work with the current process.
		sqlPathName = os.path.join( os.path.dirname(__file__), "AnotherSampleDir", "SampleSqlFile.py" )

		execList = [ sys.executable, sqlPathName ]

		# On Windows, psutil.Process.cmdline() is not very reliable, if the process is started with cmd.exe and Shell=True:
		#Python 2, psutil.__version__=5.2.2
		# Shell=1 argvArray=['C:\\windows\\system32\\cmd.exe', '/c', 'C:\\Python27\\python.exe AnotherSampleDir\\SampleSqlFile.py']
		# Shell=0 argvArray=['C:\\Python27\\python.exe', 'AnotherSampleDir\\SampleSqlFile.py']
		#
		#Python 3, psutil.__version__=5.4.7
		# Shell=1 argvArray=['C:\\windows\\system32\\cmd.exe', '/c', 'C:\\Program', 'Files', '(x86)\\Microsoft', 'Visual', 'Studio\\Shared\\Python36_64\\python.exe AnotherSampleDir\\SampleSqlFile.py']
		# Shell=0 argvArray=['C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\Python36_64\\python.exe', 'AnotherSampleDir\\SampleSqlFile.py']
		#
		#Python 2, psutil.__version__=5.4.3
		# argvArray=['python', 'toto space.py']
		procOpen = subprocess.Popen(execList, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

		print("Started process:",execList," pid=",procOpen.pid)

		# Give a bit of time so the process is fully init.
		time.sleep(1)

		mySourcePyScript = lib_client.SourceLocal(
			"sources_types/CIM_Process/languages/python/current_script.py",
			"CIM_Process",
			Handle=procOpen.pid)

		triplePyScript = mySourcePyScript.GetTriplestore()

		lstInstances = triplePyScript.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		DEBUG("strInstancesSet=%s",str(strInstancesSet))
		print("lstInstances=",lstInstances)

		sqlPathNameAbsolute = os.path.abspath(sqlPathName)
		sqlPathNameClean = sqlPathNameAbsolute.replace("\\","/")

		# This checks the presence of the current process and the Python file being executed.
		listRequired = [
			'CIM_Process.Handle=%s' % procOpen.pid,
			'CIM_DataFile.Name=%s' % sqlPathNameClean,
		]

		for oneStr in listRequired:
			print(oneStr)
			assert( oneStr in strInstancesSet )

		( child_stdout_content, child_stderr_content ) = procOpen.communicate()

		# This ensures that the suprocess is correctly started and finished.
		assert(child_stdout_content.startswith(b"Starting subprocess"))
		assert(procOpen.returncode == 123)

	def test_enumerate_users(self):
		"""List detectable users. Security might hide some of them"""

		# http://rchateau-hp:8000/survol/sources_types/enumerate_user.py?xid=.
		mySourceUsers = lib_client.SourceLocal(
			"sources_types/enumerate_user.py")

		tripleUsers = mySourceUsers.GetTriplestore()
		instancesUsers = tripleUsers.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in instancesUsers ])

		# At least the current user must be found.
		for oneStr in [
			'Win32_UserAccount.Name=%s,Domain=localhost' % CurrentUsername]:
			assert( oneStr in strInstancesSet)

class SurvolLocalWindowsTest(unittest.TestCase):
	"""These tests do not need a Survol agent. They apply to Windows machines only"""

	def test_win32_services(self):
		"""List of Win32 services"""

		mySourceWin32Services = lib_client.SourceLocal(
			"sources_types/win32/enumerate_Win32_Service.py")

		tripleWin32Services = mySourceWin32Services.GetTriplestore()

		lstInstances = tripleWin32Services.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# print(strInstancesSet)
		# Some services must be on any Windpws machine.
		assert('Win32_Service.Name=nsi' in strInstancesSet)
		assert('Win32_Service.Name=LanmanWorkstation' in strInstancesSet)

	def test_wmi_process_info(self):
		"""WMI information about current process"""

		try:
			import wmi
		except ImportError as exc:
			print("Test is not applicable:%s",str(exc))
			return

		mySourceWMIInfo = lib_client.SourceLocal(
			"sources_types/CIM_Process/wmi_process_info.py",
			"CIM_Process",
			Handle=os.getpid())

		tripleWMIInfo = mySourceWMIInfo.GetTriplestore()

		lstInstances = tripleWMIInfo.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# This checks the presence of the current process and its parent.
		assert('CIM_Process.Handle=%s' % os.getpid() in strInstancesSet)
		if sys.version_info >= (3,):
			# Checks the parent's presence also. Not for 2.7.10
			assert('CIM_Process.Handle=%s' % os.getppid() in strInstancesSet)

	def test_win_process_modules(self):
		"""Windows process modules"""

		try:
			import wmi
		except ImportError:
			print("Module win32net is not available so this test is not applicable")
			return

		mySourceProcModules = lib_client.SourceLocal(
			"sources_types/CIM_Process/win_process_modules.py",
			"CIM_Process",
			Handle=os.getpid())

		tripleProcModules = mySourceProcModules.GetTriplestore()

		lstInstances = tripleProcModules.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# This checks the presence of the current process and its parent.
		listRequired = [
			'CIM_Process.Handle=%s' % os.getpid(),
			"Win32_UserAccount.Name=%s,Domain=localhost" % CurrentUsername,
			'CIM_DataFile.Name=%s' % sys.executable.replace("\\","/"),
		]

		# Some nodes are in Py2 or Py3.
		if sys.version_info >= (3,):
			if platform.release() == '7':
				listOption = [
				'CIM_DataFile.Name=C:/windows/system32/kernel32.dll',
				]
			elif platform.release() == '10':
				# 'C:\\Users\\rchat\\AppData\\Local\\Programs\\Python\\Python36\\python.exe'
				# 'C:/Users/rchat/AppData/Local/Programs/Python/Python36/DLLs/_ctypes.pyd'
				filCTypes = os.path.dirname(sys.executable).replace("\\","/") + '/DLLs/_ctypes.pyd'
				listOption = [
					'CIM_DataFile.Name=%s' % sys.executable.replace("\\","/"),
					'CIM_DataFile.Name=%s' % filCTypes,
				]
		else:
			listOption = [
			'CIM_DataFile.Name=C:/windows/SYSTEM32/ntdll.dll',
			]

		for oneStr in listRequired + listOption:
			assert( oneStr in strInstancesSet )

		# Detection if a specific bug is fixed.
		assert(not 'CIM_DataFile.Name=' in strInstancesSet)


class SurvolPyODBCTest(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		super(SurvolPyODBCTest, self).__init__(*args, **kwargs)
		try:
			import pyodbc
		except ImportError:
			raise Exception("Module pyodbc is not available so these tests are not applicable")

	def test_local_scripts_odbc_dsn(self):
		"""This instantiates an instance of a subclass"""

		try:
			import pyodbc
		except ImportError:
			print("Module pyodbc is not available so this test is not applicable")
			return

		# The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
		instanceLocalODBC = lib_client.Agent().odbc.dsn(
			Dsn="DSN~MS%20Access%20Database")

		listScripts = instanceLocalODBC.GetScripts()
		if isVerbose:
			sys.stdout.write("Scripts:\n")
			for oneScr in listScripts:
				sys.stdout.write("    %s\n"%oneScr)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_pyodbc_sqldatasources(self):
		"""Tests ODBC data sources"""

		mySourceSqlData = lib_client.SourceLocal(
			"sources_types/Databases/win32_sqldatasources_pyodbc.py")\

		tripleSqlData = mySourceSqlData.GetTriplestore()

		lstInstances = list(tripleSqlData.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# At least these instances must be present.
		for oneStr in [
			'CIM_ComputerSystem.Name=localhost',
			'odbc/dsn.Dsn=DSN~Excel Files',
			'odbc/dsn.Dsn=DSN~MS Access Database',
			'odbc/dsn.Dsn=DSN~MyNativeSqlServerDataSrc',
			'odbc/dsn.Dsn=DSN~MyOracleDataSource',
			'odbc/dsn.Dsn=DSN~OraSysDataSrc',
			'odbc/dsn.Dsn=DSN~SysDataSourceSQLServer',
			'odbc/dsn.Dsn=DSN~dBASE Files',
			'odbc/dsn.Dsn=DSN~mySqlServerDataSource',
			'odbc/dsn.Dsn=DSN~SqlSrvNativeDataSource']:
			assert( oneStr in strInstancesSet)


	def test_pyodbc_dsn_tables(self):
		"""Tests ODBC data sources"""

		mySourceDsnTables = lib_client.SourceLocal(
			"sources_types/odbc/dsn/odbc_dsn_tables.py",
			"odbc/dsn",
			Dsn="DSN~SysDataSourceSQLServer")

		tripleDsnTables = mySourceDsnTables.GetTriplestore()

		lstInstances = list(tripleDsnTables.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		#print("Instances:",strInstancesSet)

		# Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
		for oneStr in [
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=all_columns',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=assembly_files',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=change_tracking_tables',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_broker_queue_monitors',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_hadr_availability_group_states',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_hadr_database_replica_cluster_states',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_hadr_instance_node_map',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=server_audit_specifications',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=server_audits',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=sysusers',
			]:
			assert( oneStr in strInstancesSet)


	def test_pyodbc_dsn_one_table_columns(self):
		"""Tests ODBC table columns"""

		mySourceTableColumns = lib_client.SourceLocal(
			"sources_types/odbc/table/odbc_table_columns.py",
			"odbc/table",
			Dsn="DSN~SysDataSourceSQLServer",
			Table="dm_os_windows_info")

		tripleTableColumns = mySourceTableColumns.GetTriplestore()

		lstInstances = list(tripleTableColumns.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		#print("Instances:",strInstancesSet)

		# Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
		for oneStr in [
			'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_service_pack_level',
			'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=os_language_version',
			'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_release',
			'odbc/column.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info,Column=windows_sku',
			'odbc/table.Dsn=DSN~SysDataSourceSQLServer,Table=dm_os_windows_info'
		]:
			assert( oneStr in strInstancesSet)


	def test_pyodbc_dsn_procedures(self):
		"""Tests ODBC data sources"""
		print("No script yet for ODBC procedures. Test not applicable.")



class SurvolSocketsTest(unittest.TestCase):
	"""Test involving remote Survol agents: The scripts executes scripts on remote machines
	and examines the result. It might merge the output with local scripts or
	scripts on different machines."""

	def test_netstat_windows_sockets(self):
		import socket

		print("")

		# Not many web sites in HTTP these days. This one is very stable.
		# http://w2.vatican.va/content/vatican/it.html is on port 80=http
		httpHostName = 'w2.vatican.va'

		sockHost = socket.gethostbyname(httpHostName)
		print("gethostbyname(%s)=%s"%(httpHostName,sockHost))

		# This opens a connection to a specific machine, then checks that the socket can be found.
		if sys.version_info >= (3,):
			import http.client
			connHttp = http.client.HTTPConnection(httpHostName, 80, timeout=60)
		else:
			import httplib
			connHttp = httplib.HTTPConnection(httpHostName, 80, timeout=60)
		print("Connection to %s OK"%httpHostName)
		connHttp.request("GET", "/content/vatican/it.html")
		resp = connHttp.getresponse()
		if resp.status != 200 or resp.reason != "OK":
			raise Exception("Hostname %s not ok for test. Status=%d, reason=%s."%(httpHostName, resp.status, resp.reason))
		peerName = connHttp.sock.getpeername()
		peerHost = peerName[0]

		print("Peer name of connection socket:",connHttp.sock.getpeername())

		mySourceNetstatWindowsSockets = lib_client.SourceLocal(
			"sources_types/win32/tcp_sockets_windows.py")

		tripleNetstatWindowsSockets = mySourceNetstatWindowsSockets.GetTriplestore()

		lstInstances = list(tripleNetstatWindowsSockets.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		#print("Instances:",strInstancesSet)
		addrExpected = "addr.Id=%s:80" % (peerHost)
		print("addrExpected=",addrExpected)
		assert( addrExpected in strInstancesSet )

		connHttp.close()

	def test_enumerate_sockets(self):
		"""List of sockets opened on the host machine"""
		import socket

		# httpHostName = 'www.root-servers.org'
		# This site was registered on September the 18th, 1986.
		httpHostName = 'itcorp.com'

		print("")
		sockHost = socket.gethostbyname(httpHostName)
		print("gethostbyname(%s)=%s"%(httpHostName,sockHost))

		# This opens a connection to a specific machine, then checks that the socket can be found.
		if sys.version_info >= (3,):
			import http.client
			connHttp = http.client.HTTPConnection(httpHostName, 80, timeout=60)
		else:
			import httplib
			connHttp = httplib.HTTPConnection(httpHostName, 80, timeout=60)
		print("Connection to %s OK"%httpHostName)

		#connHttp.request(method="GET", url="/", headers={"Connection" : "Keep-alive"})
		print("Requesting content")
		#connHttp.request(method="GET", url="/content/vatican/it.html")
		connHttp.request(method="GET", url="/")
		print("Peer name of connection socket:",connHttp.sock.getpeername())

		resp = connHttp.getresponse()

		if resp.status != 200 or resp.reason != "OK":
			raise Exception("Hostname %s not ok for test. Status=%d, reason=%s."%(httpHostName, resp.status, resp.reason))
		peerName = connHttp.sock.getpeername()
		peerHost = peerName[0]

		mySourceEnumerateSockets = lib_client.SourceLocal(
			"sources_types/enumerate_socket.py")

		tripleEnumerateSockets = mySourceEnumerateSockets.GetTriplestore()

		lstInstances = list(tripleEnumerateSockets.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		addrExpected = "addr.Id=%s:80" % (peerHost)

		#print("Instances:",strInstancesSet)
		print("sockHost=",sockHost)
		print("addrExpected=",addrExpected)
		#assert( addrExpected in strInstancesSet)

		print("test_enumerate_sockets: Does not work yet. Only testing execution.")

		if False:
			# For debugging purpose only.
			def DispIp(oneInst):
				if oneInst.startswith("addr") and oneInst.find("127.0.0.1") < 0:
					# addr.Id=iwc2-31.catholica.va:http
					addrOnly = oneInst[ oneInst.find("=") +1: oneInst.find(":") ]
					try:
						addrHost = socket.gethostbyname(addrOnly)
						print(oneInst,addrHost)
					except:
						print(oneInst,"===",addrOnly)

			for oneInst in sorted(strInstancesSet):
				DispIp(oneInst)
				if oneInst.find(addrExpected)>= 0:
					print("OK. Found %s in %s "%(addrExpected,oneInst))
					break

		connHttp.close()


	def test_socket_connected_processes(self):
		"""List of processes connected to a given socket"""
		import socket

		httpHostName = 'root-servers.org'

		print("")
		sockHost = socket.gethostbyname(httpHostName)
		print("gethostbyname(%s)=%s"%(httpHostName,sockHost))

		# This opens a connection to a specific machine, then checks that the socket can be found.
		if sys.version_info >= (3,):
			import http.client
			connHttp = http.client.HTTPConnection(httpHostName, 80, timeout=60)
		else:
			import httplib
			connHttp = httplib.HTTPConnection(httpHostName, 80, timeout=60)
		print("Connection to %s OK"%httpHostName)
		connHttp.request("GET", "")
		resp = connHttp.getresponse()
		if resp.status != 200 or resp.reason != "OK":
			raise Exception("Hostname %s not ok for test. Status=%d, reason=%s."%(httpHostName, resp.status, resp.reason))
		peerName = connHttp.sock.getpeername()
		peerHost = peerName[0]

		print("Peer name of connection socket:",connHttp.sock.getpeername())

		mySourceConnectedProcesses = lib_client.SourceLocal(
			"sources_types/addr/socket_connected_processes.py",
			"addr",
			Id="%s:80"%peerHost)

		tripleConnectedProcesses = mySourceConnectedProcesses.GetTriplestore()

		lstInstances = list(tripleConnectedProcesses.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# Because the current process has created this socket,
		# it must be found in the socket's connected processes.

		addrExpected = "addr.Id=%s:80" % peerHost
		hostExpected =  "CIM_Process.Handle=%d" % os.getpid()

		print("addrExpected=",addrExpected)
		print("hostExpected=",hostExpected)

		assert( addrExpected in strInstancesSet)
		assert( hostExpected in hostExpected)

		connHttp.close()


	def test_net_use(self):
		"""Just test that the command NET USE runs"""

		# This does not really test the content, because nothing is sure.
		# However, at least it tests that the script can be called.
		mySourceNetUse = lib_client.SourceLocal(
			"sources_types/SMB/net_use.py")

		tripleNetUse = mySourceNetUse.GetTriplestore()

		lstInstances = list(tripleNetUse.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		print(strInstancesSet)
		# Typical content:
		# 'CIM_DataFile.Name=//192.168.0.15/public:',
		# 'CIM_DataFile.Name=//192.168.0.15/rchateau:',
		# 'smbshr.Id=\\\\192.168.0.15\\public',
		# 'CIM_DataFile.Name=//localhost/IPC$:',
		# 'smbshr.Id=\\\\192.168.0.15\\rchateau',
		# 'smbshr.Id=\\\\localhost\\IPC$'

		# TODO: localhost should be replaced by the IP address.

		# These elements are nto there after booting a machine.
		#assert( 'CIM_DataFile.Name=//localhost/IPC$:' in strInstancesSet )
		#assert( 'smbshr.Id=\\\\localhost\\IPC$' in strInstancesSet )

	def test_windows_network_devices(self):
		"""Loads network devices on a Windows network"""

		mySourceWindowsNetworkDevices = lib_client.SourceLocal(
			"sources_types/win32/windows_network_devices.py")

		tripleWindowsNetworkDevices = mySourceWindowsNetworkDevices.GetTriplestore()

		lstInstances = list(tripleWindowsNetworkDevices.GetInstances())
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		print(strInstancesSet)

		# Typical content:
		#   'CIM_ComputerSystem.Name=192.168.0.15',
		#   'smbshr.Id=//192.168.0.15/rchateau',
		#   'CIM_DataFile.Name=Y:',
		#   'CIM_DataFile.Name=Z:',
		#   'smbshr.Id=//192.168.0.15/public'
		#
		# Some sanity checks of the result.
		set_ip_addresses = set()
		smbshr_disk = set()
		for oneInst in strInstancesSet:
			( the_class,dummy_dot, the_entity_id) = oneInst.partition(".")
			if the_class == "CIM_ComputerSystem":
				(pred_Name,dummy_equal,ip_address) = the_entity_id.partition("=")
				set_ip_addresses.add(ip_address)
			elif  the_class == "smbshr":
				(pred_Name,dummy_equal,disk_name) = the_entity_id.partition("=")
				smbshr_disk.add(disk_name)

		# Check that all machines hosting a disk have their
		for disk_name in smbshr_disk:
			# For example, "//192.168.0.15/public"
			host_name = disk_name.split("/")[2]
			assert( host_name in set_ip_addresses )

class SurvolRemoteTest(unittest.TestCase):
	"""Test involving remote Survol agents: The scripts executes scripts on remote machines
	and examines the result. It might merge the output with local scripts or
	scripts on different machines."""

	# This is executed after each test. No special reason for a delay, except perf measures, possibly.
	# https://stackoverflow.com/questions/2648329/python-unit-test-how-to-add-some-sleeping-time-between-test-cases
	def tearDown(self):
		time.sleep(0.01)  # sleep time in seconds

	def test_InstanceUrlToAgentUrl(selfself):
		assert( lib_client.InstanceUrlToAgentUrl("http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=addr.Id=127.0.0.1:427") == None )
		assert( lib_client.InstanceUrlToAgentUrl(RemoteTestAgent + "/survol/sources_types/java/java_processes.py") == RemoteTestAgent )

	def test_create_source_url(self):
		# http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
		mySourceFileStatRemote = lib_client.SourceRemote(
			RemoteTestAgent + "/survol/sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		print("urlFileStatRemote=",mySourceFileStatRemote.Url())
		print("qryFileStatRemote=",mySourceFileStatRemote.UrlQuery())
		print("jsonFileStatRemote=%s  ..." % str(mySourceFileStatRemote.content_json())[:30])
		print("rdfFileStatRemote=%s ..." % str(mySourceFileStatRemote.content_rdf())[:30])

	def test_remote_triplestore(self):
		mySourceFileStatRemote = lib_client.SourceRemote(
			RemoteTestAgent + "/survol/sources_types/CIM_Directory/file_directory.py",
			"CIM_Directory",
			Name="C:\\Windows")
		tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
		print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
		# This should not be empty.
		self.assertTrue(len(tripleFileStatRemote)>=1)

	# This does not work yet.
	def test_remote_scripts_exception(self):
		myAgent = lib_client.Agent(RemoteTestAgent)

		try:
			mySourceInvalid = myAgent.CIM_LogicalDisk(WrongProperty="D:")
			scriptsInvalid = mySourceInvalid.GetScripts()
			excRaised = False
			print("No exception is raised (This is a problem)")
		except Exception as exc:
			# Should print: "No JSON object could be decoded"
			print("An exception is raised (As expected):",exc)
			excRaised = True
		self.assertTrue(excRaised)

	def test_remote_instances_python_package(self):
		"""This loads a specific Python package"""
		mySourcePythonPackageRemote = lib_client.SourceRemote(
			RemoteTestAgent + "/survol/entity.py",
			"python/package",
			Id="rdflib")
		triplePythonPackageRemote = mySourcePythonPackageRemote.GetTriplestore()

		instancesPythonPackageRemote = triplePythonPackageRemote.GetInstances()
		lenInstances = len(instancesPythonPackageRemote)
		# This Python module must be there because it is needed by Survol.
		self.assertTrue(lenInstances>=1)

	def test_remote_instances_java(self):
		"""Loads Java processes. There is at least one Java process, the one doing the test"""
		mySourceJavaRemote = lib_client.SourceRemote(
			RemoteTestAgent + "/survol/sources_types/java/java_processes.py")
		tripleJavaRemote = mySourceJavaRemote.GetTriplestore()
		print("Len tripleJavaRemote=",len(tripleJavaRemote))

		instancesJavaRemote = tripleJavaRemote.GetInstances()
		numJavaProcesses = 0
		for oneInstance in instancesJavaRemote:
			if oneInstance.__class__.__name__ == "CIM_Process":
				print("Found one Java process:",oneInstance)
				numJavaProcesses += 1
		print("Remote Java processes=",numJavaProcesses)
		self.assertTrue(numJavaProcesses>=1)

	def test_remote_instances_arp(self):
		"""Loads machines visible with ARP. There must be at least one CIM_ComputerSystem"""
		mySourceArpRemote = lib_client.SourceRemote(
			RemoteTestAgent + "/survol/sources_types/neighborhood/cgi_arp_async.py")
		tripleArpRemote = mySourceArpRemote.GetTriplestore()
		print("Len tripleArpRemote=",len(tripleArpRemote))

		instancesArpRemote = tripleArpRemote.GetInstances()
		numComputers = 0
		for oneInstance in instancesArpRemote:
			if oneInstance.__class__.__name__ == "CIM_ComputerSystem":
				print("Test remote ARP: Found one machine:",oneInstance)
				numComputers += 1
		print("Remote hosts number=",numComputers)
		self.assertTrue(numComputers>=1)

	def test_merge_add_mixed(self):
		"""Merges local data triples and remote Survol agent's"""
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceRemote(RemoteTestAgent + "/survol/sources_types/win32/tcp_sockets_windows.py")

		mySrcMergePlus = mySource1 + mySource2
		print("Merge plus:",str(mySrcMergePlus.content_rdf())[:30])
		triplePlus = mySrcMergePlus.GetTriplestore()
		print("Len triplePlus:",len(triplePlus))

		lenSource1 = len(mySource1.GetTriplestore().GetInstances())
		lenSource2 = len(mySource2.GetTriplestore().GetInstances())
		lenPlus = len(triplePlus.GetInstances())
		# There is a margin because some instances could be created in the mean time.
		errorMargin = 20
		# In the merged link, there cannot be more instances than in the input sources.
		self.assertTrue(lenPlus <= lenSource1 + lenSource2 + errorMargin)

	def test_merge_sub_mixed(self):
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceRemote(RemoteTestAgent + "/survol/sources_types/win32/win32_local_groups.py")

		mySrcMergeMinus = mySource1 - mySource2
		print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
		tripleMinus = mySrcMergeMinus.GetTriplestore()
		print("Len tripleMinus:",len(tripleMinus))

		lenSource1 = len(mySource1.GetTriplestore().GetInstances())
		lenMinus = len(tripleMinus.GetInstances())
		# There cannot be more instances after removal.
		self.assertTrue(lenMinus <= lenSource1 )

	def test_remote_scripts_CIM_LogicalDisk(self):
		myAgent = lib_client.Agent(RemoteTestAgent)

		myInstancesRemoteDisk = myAgent.CIM_LogicalDisk(DeviceID="D:")
		listScriptsDisk = myInstancesRemoteDisk.GetScripts()
		# No scripts yet.
		self.assertTrue(len(listScriptsDisk) == 0)

	def test_remote_scripts_CIM_Directory(self):
		myAgent = lib_client.Agent(RemoteTestAgent)

		myInstancesRemoteDir = myAgent.CIM_Directory(Name="D:")
		listScriptsDir = myInstancesRemoteDir.GetScripts()

		if isVerbose:
			for keyScript in listScriptsDir:
				sys.stdout.write("    %s\n"%keyScript)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScriptsDir) > 0)

	def test_remote_agents(self):
		"""Gets agents accessible of remote host, then accesses them one by one"""
		print("TODO: test_remote_agents not implemented yet")

class SurvolAzureTest(unittest.TestCase):
	"""Testing Azure discovery"""

	def decorator_azure_subscription(test_func):
		"""Returns first available Azure subscription from Credentials file"""

		try:
			import azure
		except ImportError:
			print("Module azure is not available so this test is not applicable")
			return None

		mySourceAzureSubscriptions = lib_client.SourceLocal(
			"sources_types/Azure/enumerate_subscription.py")

		tripleAzureSubscriptions = mySourceAzureSubscriptions.GetTriplestore()

		# ['Azure/subscription.Subscription=Visual Studio Professional', 'CIM_ComputerSystem.Name=localhost']
		instancesAzureSubscriptions = tripleAzureSubscriptions.GetInstances()
		for oneInst in instancesAzureSubscriptions:
			# This returns the first subscription found.
			if oneInst.__class__.__name__ == "Azure/subscription":
				def wrapper(self):
					test_func(self,oneInst.Subscription)
				return wrapper

		print("No Azure subscription available")
		return None

	@decorator_azure_subscription
	def test_azure_subscriptions(self,azureSubscription):
		print("Azure subscription:",azureSubscription)

	@decorator_azure_subscription
	def test_azure_locations(self,azureSubscription):
		"""This checks Azure locations."""

		mySourceAzureLocations = lib_client.SourceLocal(
			"sources_types/Azure/subscription/subscription_locations.py",
			"Azure/subscription",
			Subscription=azureSubscription)

		tripleAzureLocations = mySourceAzureLocations.GetTriplestore()

		lstInstances = tripleAzureLocations.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# Some locations are very common.
		for locationName in [
				'UK South',
				'West Central US',
				'West Europe' ]:
			entitySubscription = 'Azure/location.Subscription=%s,Location=%s' % ( azureSubscription, locationName )
			assert( entitySubscription in strInstancesSet)

	@decorator_azure_subscription
	def _test_azure_subscription_disk(self,azureSubscription):
		"""This checks Azure disks."""

		mySourceAzureDisks = lib_client.SourceLocal(
			"sources_types/Azure/subscription/subscription_disk.py",
			"Azure/subscription",
			Subscription=azureSubscription)

		tripleAzureDisks = mySourceAzureDisks.GetTriplestore()

		lstInstances = tripleAzureDisks.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		print(strInstancesSet)

		# There should be at least one disk.
		assert( len(strInstancesSet) > 0)


class SurvolRabbitMQTest(unittest.TestCase):
	"""Testing RabbitMQ discovery"""

	# Beware that it is called anyway for each function it is applied to,
	# even if the function is not called.
	def decorator_rabbitmq_subscription(test_func):
		"""Returns first RabbitMQ subscription from Credentials file"""

		try:
			import pyrabbit
		except ImportError:
			print("Module pyrabbit is not available so this test is not applicable")
			return None

		mySourceConfigurationsRabbitMQ = lib_client.SourceLocal(
			"sources_types/rabbitmq/list_configurations.py")

		tripleConfigurationsRabbitMQ = mySourceConfigurationsRabbitMQ.GetTriplestore()

		# ['Azure/subscription.Subscription=Visual Studio Professional', 'CIM_ComputerSystem.Name=localhost']
		instancesConfigurationsRabbitMQ = tripleConfigurationsRabbitMQ.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in instancesConfigurationsRabbitMQ ])

		for oneInst in instancesConfigurationsRabbitMQ:
			# This returns the first subscription found.
			if oneInst.__class__.__name__ == "rabbitmq/manager":
				def wrapper(self):
					test_func(self,oneInst.Url)
				return wrapper

		print("No Azure subscription available")
		return None

	@decorator_rabbitmq_subscription
	def test_rabbitmq_subscriptions(self,rabbitmqManager):
		print("RabbitMQ:",rabbitmqManager)

	@decorator_rabbitmq_subscription
	def test_rabbitmq_connections(self,rabbitmqManager):
		print("RabbitMQ:",rabbitmqManager)

		mySourceRabbitMQConnections = lib_client.SourceLocal(
			"sources_types/rabbitmq/manager/list_connections.py",
			"rabbitmq/manager",
			Url=rabbitmqManager)

		tripleRabbitMQConnections = mySourceRabbitMQConnections.GetTriplestore()

		lstInstances = tripleRabbitMQConnections.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		print(strInstancesSet)

		# Typical content:
		# 'rabbitmq/manager.Url=localhost:12345',\
		# 'rabbitmq/user.Url=localhost:12345,User=guest',\
		# 'rabbitmq/connection.Url=localhost:12345,Connection=127.0.0.1:51752 -&gt; 127.0.0.1:5672',\
		# 'rabbitmq/connection.Url=localhost:12345,Connection=127.0.0.1:51641 -&gt; 127.0.0.1:5672'])

		# Typical content
		for oneStr in [
			'rabbitmq/manager.Url=%s' % rabbitmqManager,
			'rabbitmq/user.Url=%s,User=guest' % rabbitmqManager,
		]:
			assert( oneStr in strInstancesSet)

	@decorator_rabbitmq_subscription
	def test_rabbitmq_exchanges(self,rabbitmqManager):
		print("RabbitMQ:",rabbitmqManager)

		mySourceRabbitMQExchanges = lib_client.SourceLocal(
			"sources_types/rabbitmq/manager/list_exchanges.py",
			"rabbitmq/manager",
			Url=rabbitmqManager)

		tripleRabbitMQExchanges = mySourceRabbitMQExchanges.GetTriplestore()

		lstInstances = tripleRabbitMQExchanges.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		print(strInstancesSet)

		# Typical content
		for oneStr in [
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.match' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.topic' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.rabbitmq.trace' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.headers' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.rabbitmq.log' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.fanout' % rabbitmqManager,
			'rabbitmq/exchange.Url=%s,VHost=/,Exchange=amq.direct' % rabbitmqManager,
			'rabbitmq/vhost.Url=%s,VHost=/' % rabbitmqManager
		]:
			assert( oneStr in strInstancesSet)

	@decorator_rabbitmq_subscription
	def test_rabbitmq_queues(self,rabbitmqManager):
		print("RabbitMQ:",rabbitmqManager)

		mySourceRabbitMQQueues = lib_client.SourceLocal(
			"sources_types/rabbitmq/manager/list_queues.py",
			"rabbitmq/manager",
			Url=rabbitmqManager)

		tripleRabbitMQQueues = mySourceRabbitMQQueues.GetTriplestore()

		lstInstances = tripleRabbitMQQueues.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# TODO: Which queues should always be present ?

	@decorator_rabbitmq_subscription
	def test_rabbitmq_users(self,rabbitmqManager):
		print("RabbitMQ:",rabbitmqManager)

		mySourceRabbitMQUsers = lib_client.SourceLocal(
			"sources_types/rabbitmq/manager/list_users.py",
			"rabbitmq/manager",
			Url=rabbitmqManager)

		tripleRabbitMQUsers = mySourceRabbitMQUsers.GetTriplestore()

		lstInstances = tripleRabbitMQUsers.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])
		print(strInstancesSet)

		# Typical content
		for oneStr in [
			'rabbitmq/user.Url=%s,User=guest' % rabbitmqManager,
		]:
			print(oneStr)
			assert( oneStr in strInstancesSet)


class SurvolOracleTest(unittest.TestCase):
	"""Testing Oracle discovery"""

	def decorator_oracle_db(test_func):
		"""Returns first Oracle connection from Credentials file"""
		global cx_Oracle_import_ok
		try:
			# This tests only once if this module can be imported.
			return cx_Oracle_import_ok
		except NameError:
			try:
				import cx_Oracle
				cx_Oracle_import_ok = True
			except ImportError as ex:
				print("Module cx_Oracle is not available so this test is not applicable:",ex	)
				cx_Oracle_import_ok = False
				return None

		mySourceOracleDbs = lib_client.SourceLocal(
			"sources_types/Databases/oracle_tnsnames.py")

		tripleOracleDbs = mySourceOracleDbs.GetTriplestore()

		# Typical content: 'addr.Id=127.0.0.1:1521', 'oracle/db.Db=XE_WINDOWS',
		# 'oracle/db.Db=XE', 'oracle/db.Db=XE_OVH', 'addr.Id=vps516494.ovh.net:1521',
		# 'addr.Id=192.168.0.17:1521', 'oracle/db.Db=XE_FEDORA'}
		instancesOracleDbs = tripleOracleDbs.GetInstances()

		# Sorted in alphabetical order.
		strInstances = sorted([str(oneInst.Db) for oneInst in instancesOracleDbs if oneInst.__class__.__name__ == "oracle/db"])

		if strInstances:
			# This returns the first database found in the credentials file in alphabetical order.
			def wrapper(self):
				test_func(self,strInstances[0])
			wrapper.__doc__ = test_func.__doc__
			return wrapper
			# return strInstances[0]

		print("No Oracle database available")
		return None

	@decorator_oracle_db
	def test_oracle_databases(self,oracleDb):
		"""Check there is at least one connection."""
		print("Oracle:",oracleDb)

	@decorator_oracle_db
	def test_oracle_schemas(self,oracleDb):
		print("Oracle:",oracleDb)

		mySourceOracleSchemas = lib_client.SourceLocal(
			"sources_types/oracle/db/oracle_db_schemas.py",
			"oracle/db",
			Db=oracleDb)

		tripleOracleSchemas = mySourceOracleSchemas.GetTriplestore()

		lstInstances = tripleOracleSchemas.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		# Typical content:
		for oneStr in [
			'oracle/schema.Db=%s,Schema=SYSTEM' % oracleDb,
			'oracle/schema.Db=%s,Schema=ANONYMOUS' % oracleDb,
			'oracle/schema.Db=%s,Schema=SYS' % oracleDb,
		]:
			assert( oneStr in strInstancesSet)

	@decorator_oracle_db
	def test_oracle_connected_processes(self,oracleDb):
		print("Oracle:",oracleDb)

		mySourceOracleProcesses = lib_client.SourceLocal(
			"sources_types/oracle/db/oracle_db_processes.py",
			"oracle/db",
			Db=oracleDb)

		tripleOracleProcesses = mySourceOracleProcesses.GetTriplestore()

		lstInstances = tripleOracleProcesses.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		print(strInstancesSet)

		# Typical content:
		# 'CIM_Process.Handle=11772', 'oracle/db.Db=XE', 'Win32_UserAccount.Name=rchateau,Domain=rchateau-hp',
		# 'oracle/schema.Db=XE,Schema=SYSTEM', 'oracle/session.Db=XE,Session=102'
		for oneStr in [
			'CIM_Process.Handle=%s' % os.getpid(),
			'oracle/db.Db=%s' % oracleDb,
			'Win32_UserAccount.Name=%s,Domain=%s' % ( CurrentUsername, CurrentMachine),
		]:
			assert( oneStr in strInstancesSet)

	@decorator_oracle_db
	def test_oracle_running_queries(self,oracleDb):
		print("Oracle:",oracleDb)

		mySourceOracleProcesses = lib_client.SourceLocal(
			"sources_types/oracle/db/oracle_db_parse_queries.py",
			"oracle/db",
			Db=oracleDb)

		tripleOracleProcesses = mySourceOracleProcesses.GetTriplestore()

		# Typical content:
		# ['oracle/db.Db=XE_OVH', 'oracle/query.Query=ICBTRUxF... base64 ...ZGRyICA=,Db=XE_OVH']
		lstInstances = tripleOracleProcesses.GetInstances()

		for oneInst in lstInstances:
			if oneInst.__class__.__name__ == 'oracle/query':
				import sources_types.oracle.query
				print("Decoded query:",sources_types.oracle.query.EntityName( [oneInst.Query,oneInst.Db] ))

				# TODO: This is not very consistent: sources_types.oracle.query.EntityName
				# TODO: produces a nice but truncated message, and the relation between
				# TODO: oracle.query and sql.query is not obvious.
				import sources_types.sql.query
				qryDecodedFull = sources_types.sql.query.EntityName( [oneInst.Query] )
				print("Decoded query:",qryDecodedFull)
				# The query must start with a select.
				assert( qryDecodedFull.strip().upper().startswith("SELECT"))

				# TODO: Parse the query ? Or extracts its dependencies ?


	@decorator_oracle_db
	def test_oracle_schema_tables(self,oracleDb):
		print("Oracle:",oracleDb)

		mySourceOracleSchemaTables = lib_client.SourceLocal(
			"sources_types/oracle/schema/oracle_schema_tables.py",
			"oracle/db",
			Db=oracleDb,
		Schema='SYSTEM')

		tripleOracleSchemaTables = mySourceOracleSchemaTables.GetTriplestore()

		lstInstances = tripleOracleSchemaTables.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		print(strInstancesSet)

		# Various tables which should always be in 'SYSTEM' namespace:
		for oneStr in [
			'oracle/table.Db=%s,Schema=SYSTEM,Table=HELP' % oracleDb,
			#'oracle/table.Db=%s,Schema=SYSTEM,Table=REPCAT$_COLUMN_GROUP' % oracleDb,
			#'oracle/table.Db=%s,Schema=SYSTEM,Table=MVIEW$_ADV_WORKLOAD' % oracleDb,
		]:
			assert( oneStr in strInstancesSet)

	@decorator_oracle_db
	def test_oracle_schema_views(self,oracleDb):
		print("Oracle:",oracleDb)

		mySourceOracleSchemaViews = lib_client.SourceLocal(
			"sources_types/oracle/schema/oracle_schema_views.py",
			"oracle/db",
			Db=oracleDb,
			Schema='SYS')

		tripleOracleSchemaViews = mySourceOracleSchemaViews.GetTriplestore()

		lstInstances = tripleOracleSchemaViews.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		print(sorted(strInstancesSet)[:10])

		# Various tables which should always be in 'SYSTEM' namespace:
		for oneStr in [
			'oracle/view.Db=%s,Schema=SYS,View=ALL_ALL_TABLES' % oracleDb,
			#'oracle/table.Db=%s,Schema=SYSTEM,Table=REPCAT$_COLUMN_GROUP' % oracleDb,
			#'oracle/table.Db=%s,Schema=SYSTEM,Table=MVIEW$_ADV_WORKLOAD' % oracleDb,
		]:
			assert( oneStr in strInstancesSet)

	@decorator_oracle_db
	def test_oracle_view_dependencies(self,oracleDb):
		"""Dsplays dependencies of a very common view"""

		mySourceOracleViewDependencies = lib_client.SourceLocal(
			"sources_types/oracle/view/oracle_view_dependencies.py",
			"oracle/db",
			Db=oracleDb,
			Schema='SYS',
			View='ALL_ALL_TABLES')

		tripleOracleViewDependencies = mySourceOracleViewDependencies.GetTriplestore()

		lstInstances = tripleOracleViewDependencies.GetInstances()
		strInstancesSet = set([str(oneInst) for oneInst in lstInstances ])

		print(sorted(strInstancesSet)[:10])

		# The dependencies of this view should always be the same,as it does not change often.
		for oneStr in [
			'oracle/schema.Db=%s,Schema=SYS' % oracleDb,
			'oracle/synonym.Db=%s,Schema=PUBLIC,Synonym=ALL_ALL_TABLES' % oracleDb,
			'oracle/view.Db=%s,Schema=SYS,View=ALL_ALL_TABLES' % oracleDb,
			'oracle/view.Db=%s,Schema=SYS,View=ALL_OBJECT_TABLES' % oracleDb,
			'oracle/view.Db=%s,Schema=SYS,View=ALL_TABLES' % oracleDb,
		]:
			assert( oneStr in strInstancesSet)

class SurvolPEFileTest(unittest.TestCase):
	"""Testing pefile features"""
	def test_pefile_exports(self):
		"""Tests exported functions of a DLL."""

		# Very common DLL.
		dllFileName = r"C:\Windows\System32\gdi32.dll"

		mySourcePEFileExports = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/portable_executable/pefile_exports.py",
			"CIM_DataFile",
			Name=dllFileName)

		triplePEFileExports = mySourcePEFileExports.GetTriplestore()

		lstInstances = triplePEFileExports.GetInstances()
		import sources_types.linker_symbol
		namesInstance = set()

		for oneInst in lstInstances:
			if oneInst.__class__.__name__ == 'linker_symbol':
				instName = sources_types.linker_symbol.EntityName( [oneInst.Name,oneInst.File] )
				namesInstance.add(instName)

		# Some exported functiosn which should be there.
		for oneStr in [
			"CreateBitmapFromDxSurface",
			"DeleteDC",
			"GdiCreateLocalMetaFilePict",
			"ClearBitmapAttributes",
			"GetViewportOrgEx",
			"GdiDescribePixelFormat",
			"OffsetViewportOrgEx",
		]:
			assert( oneStr in namesInstance)


class SurvolSearchTest(unittest.TestCase):
	"""Testing the search engine"""
	def test_search_local_string_flat(self):
		"""Searches for a string in one file only. Two occurrences."""

		sampleFile = os.path.join( os.path.dirname(__file__), "SampleDir", "SampleFile.txt" )
		instanceOrigin = lib_client.Agent().CIM_DataFile(Name=sampleFile)

		searchTripleStore = instanceOrigin.FindStringFromNeighbour(searchString="Maecenas",maxDepth=1,filterInstances=None,filterPredicates=None)

		results = list(searchTripleStore)

		print(results)
		assert( len(results) == 2)
		# The line number and occurrence number are concatenated after the string.
		assert( str(results[0][2]).encode("utf-8").startswith( "Maecenas".encode("utf-8")) )
		assert( str(results[1][2]).encode("utf-8").startswith( "Maecenas".encode("utf-8")) )


	def test_search_local_string_one_level(self):
		"""Searches for a string in all files of one directory."""

		# There are not many files in this directory
		sampleDir = os.path.join( os.path.dirname(__file__), "SampleDir" )
		instanceOrigin = lib_client.Agent().CIM_Directory(Name=sampleDir)

		mustFind = "Drivers"

		searchTripleStore = instanceOrigin.FindStringFromNeighbour(searchString="Curabitur",maxDepth=2,filterInstances=None,filterPredicates=None)
		for tpl in searchTripleStore:
			# One occurrence is enough for this test.
			print(tpl)
			break
		tpl # To check if a result was found.

	def test_search_local_string(self):
		"""Loads instances connected to an instance by every known script"""

		# The service "PlugPlay" should be available on all Windows machines.
		instanceOrigin = lib_client.Agent().CIM_Directory(
			Name="C:/Windows")

		listInstances = {
			lib_client.Agent().CIM_Directory(Name="C:/Windows/winxs"),
			lib_client.Agent().CIM_Directory(Name="C:/windows/system32"),
			lib_client.Agent().CIM_DataFile(Name="C:/Windows/epplauncher.mif"),
			lib_client.Agent().CIM_DataFile(Name="C:/Windows/U2v243.exe"),
		}

		listPredicates = {
			lib_properties.pc.property_directory,
		}

		mustFind = "Hello"

		searchTripleStore = instanceOrigin.FindStringFromNeighbour(searchString=mustFind,maxDepth=3,filterInstances=listInstances,filterPredicates=listPredicates)
		for tpl in searchTripleStore:
			print(tpl)

# Tests an internal URL
class SurvolInternalTest(unittest.TestCase):
	def check_internal_values(self,anAgentStr):

		anAgent = lib_client.Agent(anAgentStr)
		mapInternalData = anAgent.GetInternalData()

		# http://192.168.0.14/Survol/survol/print_internal_data_as_json.py
		# http://rchateau-hp:8000/survol/print_internal_data_as_json.py

		# RootUri              http://192.168.0.14:80/Survol/survol/print_internal_data_as_json.py
		# uriRoot              http://192.168.0.14:80/Survol/survol
		# HttpPrefix           http://192.168.0.14:80
		# RequestUri           /Survol/survol/print_internal_data_as_json.py
		#
		# RootUri              http://rchateau-HP:8000/survol/print_internal_data_as_json.py
		# uriRoot              http://rchateau-HP:8000/survol
		# HttpPrefix           http://rchateau-HP:8000
		# RequestUri           /survol/print_internal_data_as_json.py

		# RootUri              http://192.168.0.14:80/Survol/survol/Survol/survol/print_internal_data_as_json.py
		# uriRoot              http://192.168.0.14:80/Survol/survol
		# HttpPrefix           http://192.168.0.14:80
		# RequestUri           /Survol/survol/print_internal_data_as_json.py
		#
		# RootUri              http://rchateau-HP:8000/survol/survol/print_internal_data_as_json.py
		# uriRoot              http://rchateau-HP:8000/survol
		# HttpPrefix           http://rchateau-HP:8000
		# RequestUri           /survol/print_internal_data_as_json.py

		print("")
		print("anAgentStr=",anAgentStr)
		print("PLUS:",anAgentStr + "/survol")
		for key in mapInternalData:
			print("%-20s %20s"%(key,mapInternalData[key]))
		assert(mapInternalData["uriRoot"] == anAgentStr + "/survol")
		assert(mapInternalData["RootUri"] == anAgentStr + "/survol/print_internal_data_as_json.py")

		#lib_client.urlparse
		#assert(mapInternalData["HttpPrefix"] == anAgentStr)
		#assert(mapInternalData["RequestUri"] == "dddd")

	def test_internal_remote(self):
		self.check_internal_values(RemoteTestAgent)

	def test_internal_apache(self):
		# http://192.168.0.14/Survol/survol/entity.py
		self.check_internal_values(RemoteTestApacheAgent)



if __name__ == '__main__':
	lenArgv = len(sys.argv)
	ix = 0
	while ix < lenArgv:
		if sys.argv[ix] in ["-l","--list"]:
			globCopy = globals().copy()
			lstGlobs = [ globCopy[clsNam] for clsNam in sorted(globCopy) ]
			# SurvolLocalTest,SurvolRemoteTest,SurvolSearchTest etc...
			lstClasses = [ oneGlob for oneGlob in lstGlobs if isinstance( oneGlob, type )]

			for cls in lstClasses:
				clsDoc = cls.__doc__
				if not clsDoc:
					clsDoc = ""
				print("%-44s: %s" % ( cls.__name__,clsDoc ) )
				for fnc in dir(cls):
					if fnc.startswith("test_"):
						fnc_code = getattr(cls,fnc)
						if isinstance(fnc_code,bool):
							tstDoc = "Cannot run"
						else:
							tstDoc = fnc_code.__doc__
						#tstDoc = str(fnc_code)
						if not tstDoc:
							tstDoc = ""
						print("    %-40s: %s" % (fnc, tstDoc))
				print("")
			exit(0)
		if sys.argv[ix] in ["-l","--debug"]:
			lib_client.SetDebugMode()
			del sys.argv[ix]
			lenArgv -= 1
			continue
		if sys.argv[ix] in ["-h","--help"]:
			print("Extra options:")
			print("  -d, --debug: Set debug mode")
			print("  -l, --list : List of tests")
		ix += 1

	unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

