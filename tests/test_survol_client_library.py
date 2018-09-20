from __future__ import print_function

import cgitb
import unittest
import sys

# This does basically the same tests as a Jupyter notebook test_client_library.ipynb

# This loads the module from the source, so no need to install it, and no need of virtualenv.
filRoot = "C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\survol"
if sys.path[0] != filRoot:
	sys.path.insert(0,filRoot)
	# print(sys.path)

# This deletes the module so we can reload them each time.
# Problem: survol modules are not detectable.
# We could as well delete all modules except sys.
allModules = [ modu for modu in sys.modules if modu.startswith("survol") or modu.startswith("lib_")]

for modu in allModules:
	# sys.stderr.write("Deleting %s\n"%modu)
	del sys.modules[modu]

import lib_client

# Otherwise, Python callstack would be displayed in HTML.
cgitb.enable(format="txt")

	# TODO: Prefix of url samples should be a parameter.

class SurvolBasicTest(unittest.TestCase):

	def test_create_source_url(self):
		# http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
		mySourceFileStatRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		print("urlFileStatRemote=",mySourceFileStatRemote.Url())
		print("qryFileStatRemote=",mySourceFileStatRemote.UrlQuery())
		print("jsonFileStatRemote=",str(mySourceFileStatRemote.content_json())[:30])
		print("rdfFileStatRemote=",str(mySourceFileStatRemote.content_rdf())[:30])

	def test_create_source_local(self):
		# This should return the same content as test_create_source_url(), but much faster.
		mySourceFileStatLocal = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		print("qryFileStatLocal=%s"%mySourceFileStatLocal.UrlQuery())
		print("jsonFileStatLocal=%s"%str(mySourceFileStatLocal.content_json())[:30])
		print("rdfFileStatLocal=%s"%str(mySourceFileStatLocal.content_rdf())[:30])

	def test_remote_triplestore(self):
		mySourceFileStatRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/sources_types/CIM_Directory/file_directory.py",
			"CIM_Directory",
			Name="C:\\Windows")
		tripleFileStatRemote = mySourceFileStatRemote.get_triplestore()
		print("Len tripleFileStatRemote=",len(tripleFileStatRemote))

	def test_remote_instances(self):
		mySourceFileStatRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/entity.py",
			"python/package",
			Id="rdflib")
		tripleFileStatRemote = mySourceFileStatRemote.get_triplestore()
		print("Len tripleFileStatRemote=",len(tripleFileStatRemote))

		instancesFileStatRemote = tripleFileStatRemote.GetInstances()
		print("Len instancesFileStatRemote=",len(instancesFileStatRemote))
		lenInstances = len(instancesFileStatRemote)
		print("Len tripleFileStatLocal=",lenInstances)
		# This Python module must be there because it is needed by Survol.
		self.assertTrue(lenInstances>=1)

	def test_local_triplestore(self):
		mySourceFileStatLocal = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		tripleFileStatLocal = mySourceFileStatLocal.get_triplestore()
		print("Len triple store local=",len(tripleFileStatLocal.m_triplestore))

	def test_local_instances(self):
		mySourceFileStatLocal = lib_client.SourceLocal(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")

		import lib_common
		lib_common.globalErrorMessageEnabled = False

		tripleFileStatLocal = mySourceFileStatLocal.get_triplestore()
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

	def test_merge_add(self):
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceRemote("http://rchateau-hp:8000/survol/sources_types/java/java_processes.py")

		mySrcMergePlus = mySource1 + mySource2
		print("Merge plus:",str(mySrcMergePlus.content_rdf())[:30])
		triplePlus = mySrcMergePlus.get_triplestore()
		print("Len triplePlus:",len(triplePlus))

		lenSource1 = len(mySource1.get_triplestore().GetInstances())
		lenSource2 = len(mySource2.get_triplestore().GetInstances())
		lenPlus = len(triplePlus.GetInstances())
		# In the merged link, there cannot be more instances than in the input sources.
		self.assertTrue(lenPlus <= lenSource1 + lenSource2)

	def test_merge_sub(self):
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceRemote("http://rchateau-hp:8000/survol/sources_types/win32/win32_local_groups.py")

		mySrcMergeMinus = mySource1 - mySource2
		print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
		tripleMinus = mySrcMergeMinus.get_triplestore()
		print("Len tripleMinus:",len(tripleMinus))

		lenSource1 = len(mySource1.get_triplestore().GetInstances())
		lenMinus = len(tripleMinus.GetInstances())
		# There cannot be more instances after removal.
		self.assertTrue(lenMinus	 <= lenSource1 )

	def test_merge_duplicate(self):
		mySourceDupl = lib_client.SourceLocal(
			"sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py",
			"Win32_UserAccount",
			Domain="rchateau-hp",
			Name="rchateau")
		tripleDupl = mySourceDupl.get_triplestore()
		print("Len tripleDupl=",len(tripleDupl.GetInstances()))

		mySrcMergePlus = mySourceDupl + mySourceDupl
		triplePlus = mySrcMergePlus.get_triplestore()
		print("Len triplePlus=",len(triplePlus.GetInstances()))
		# No added node.
		self.assertEqual(len(triplePlus.GetInstances()), len(tripleDupl.GetInstances()))

		mySrcMergeMinus = mySourceDupl - mySourceDupl
		tripleMinus = mySrcMergeMinus.get_triplestore()
		print("Len tripleMinus=",len(tripleMinus.GetInstances()))
		self.assertEqual(len(tripleMinus.GetInstances()), 0)

	# http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui


	def test_exception_bad_source(self):
		# This tests if errors are properly displayed.
		mySourceBad = lib_client.SourceLocal(
			"xxx/yyy/zzz.py",
			"this-will-raise-an-exception")
		try:
			tripleBad = mySourceBad.get_triplestore()
		except Exception as exc:
			print("Error detected:",exc)

		mySourceBroken = lib_client.SourceRemote(
			"http://rchateau-hp:8000/xxx/yyy/zzz/ttt.py",
			"wwwww")
		try:
			tripleBroken = mySourceBroken.get_triplestore()
			excRaised = False
		except Exception as exc:
			excRaised = True
		self.assertTrue(excRaised)

	def test_instance_filter(self):
		pass
		# Filter from a triple store by creating a mask like:
		# inst = lib_client.CMI_DataFile

	def test_wql(self):
		pass
		# SELECT * FROM meta_class WHERE NOT __class < "win32"="" and="" not="" __this="" isa="">
		# "Select * from win32_Process where name like '[H-N]otepad.exe'"

	def test_local_scripts_list_Win32_UserAccount(self):
		"""This returns all scripts accessible from the user account "rchateau"."""

		myInstancesLocal = lib_client.Agent().Win32_UserAccount(
			Domain="rchateau-hp",
			Name="rchateau")

		listScripts = myInstancesLocal.GetScripts()
		sys.stdout.write("Scripts:\n")
		for oneScr in listScripts:
			sys.stdout.write("    %s\n"%oneScr)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_local_scripts_list_odbc_dsn(self):
		"""The point of this test is to instantiate an instance of a subclass"""

		# The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
		instanceLocalODBC = lib_client.Agent().odbc.dsn(
			Dsn="DSN~MS%20Access%20Database")

		listScripts = instanceLocalODBC.GetScripts()
		sys.stdout.write("Scripts:\n")
		for oneScr in listScripts:
			sys.stdout.write("    %s\n"%oneScr)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)


	# This does not work yet.
	def XXX_test_remote_scripts_list_exception(self):
		myAgent = lib_client.Agent("http://rchateau-hp:8000")

		try:
			myInstancesRemote = myAgent.CIM_LogicalDisk(WrongProperty="D:")
			excRaised = False
			print("No exception is raised")
		except Exception as exc:
			print("An exception is raised")
			excRaised = True
		self.assertTrue(excRaised)

	def test_remote_scripts_list_CIM_LogicalDisk(self):
		# myInstancesRemote = lib_client.Agent("http://rchateau-hp:8000").CIM_LogicalDisk(DeviceID="D:")
		myAgent = lib_client.Agent("http://rchateau-hp:8000")

		myInstancesRemote = myAgent.CIM_LogicalDisk(DeviceID="D:")
		listScripts = myInstancesRemote.GetScripts()
		# No scripts yet.
		self.assertTrue(len(listScripts) == 0)


	def test_remote_scripts_list_CIM_Directory(self):
		# myInstancesRemote = lib_client.Agent("http://rchateau-hp:8000").CIM_Directory(Name="D:")
		myAgent = lib_client.Agent("http://rchateau-hp:8000")

		myInstancesRemote = myAgent.CIM_Directory(Name="D:")
		listScripts = myInstancesRemote.GetScripts()
		for keyScript in listScripts:
			sys.stdout.write("    %s\n"%keyScript)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_local_scripts_from_local_source(self):
		"""This loads the scripts of instances displayed by an initial script"""

		# This is a top-level script.
		mySourceTopLevelLocal = lib_client.SourceLocal(
			"sources_types/win32/win32_local_groups.py")

		tripleTopLevelLocal = mySourceTopLevelLocal.get_triplestore()
		instancesTopLevelLocal = tripleTopLevelLocal.GetInstances()

		for oneInst in instancesTopLevelLocal:
			sys.stdout.write("    Scripts: %s\n"%str(oneInst))
			listScripts = oneInst.GetScripts()
			for oneScr in listScripts:
				sys.stdout.write("        %s\n"%oneScr)

	def test_local_instances_from_local_instance(self):
		"""This loads instances connected to an instance by every known script"""

		# The service "PlugPlay" should be available on all Windows machines.
		myInstanceLocal = lib_client.Agent().Win32_Service(
			Name="PlugPlay")

		listScripts = myInstanceLocal.GetScripts()
		sys.stdout.write("Scripts:\n")
		for oneScr in listScripts:
			sys.stdout.write("    %s\n"%oneScr)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_search_local_instance(self):
		"""This loads instances connected to an instance by every known script"""

		# The service "PlugPlay" should be available on all Windows machines.
		myInstanceOrigin = lib_client.Agent().CIM_Directory(
			Name="C:\\Windows")

		myInstanceDestination = lib_client.Agent().CIM_DataFile(
			Name="C:\\Windows\\explorer.exe")

		listSteps = myInstanceOrigin.FindPathToInstance(myInstanceDestination)


if __name__ == '__main__':
	unittest.main()