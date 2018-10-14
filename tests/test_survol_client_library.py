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
import lib_properties
# from lib_properties import pc


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
		print("jsonFileStatLocal=%s"%str(mySourceFileStatLocal.content_json())[:30])
		print("rdfFileStatLocal=%s"%str(mySourceFileStatLocal.content_rdf())[:30])

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
		self.assertTrue(lenMinus	 <= lenSource1 )

	def test_merge_duplicate(self):
		mySourceDupl = lib_client.SourceLocal(
			"sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py",
			"Win32_UserAccount",
			Domain="rchateau-hp",
			Name="rchateau")
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
			"http://rchateau-hp:8000/xxx/yyy/zzz/ttt.py",
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
		print("TODO: Not implemented yet")


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
		print("TODO: Not implemented yet")

	def test_wql(self):
		# SELECT * FROM meta_class WHERE NOT __class < "win32"="" and="" not="" __this="" isa="">
		# "Select * from win32_Process where name like '[H-N]otepad.exe'"
		print("TODO: Not implemented yet")

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

	def test_local_scripts_from_local_source(self):
		"""This loads the scripts of instances displayed by an initial script"""

		# This is a top-level script.
		mySourceTopLevelLocal = lib_client.SourceLocal(
			"sources_types/win32/win32_local_groups.py")

		tripleTopLevelLocal = mySourceTopLevelLocal.GetTriplestore()
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

	def test_instances_cache(self):
		instanceA = lib_client.Agent().CIM_Directory( Name="C:/Windows")
		instanceB = lib_client.Agent().CIM_Directory( Name="C:/Windows")
		instanceC = lib_client.CreateCIMClass(None,"CIM_Directory",Name="C:/Windows")
		sys.stdout.write("Class=%s\n"%instanceC.__class__.__name__)
		sys.stdout.write("Module=%s\n"%instanceC.__module__)
		sys.stdout.write("Dir=%s\n\n"%str(dir(lib_client)))
		sys.stdout.write("Dir=%s\n"%str(sorted(globals())))

		assert( instanceA is instanceB )
		assert( instanceA is instanceC )
		assert( instanceC is instanceB )



	def test_search_local_string(self):
		"""This loads instances connected to an instance by every known script"""

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


class SurvolRemoteTest(unittest.TestCase):
	"""Test involving remote Survol agents"""

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

	def test_remote_triplestore(self):
		mySourceFileStatRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/sources_types/CIM_Directory/file_directory.py",
			"CIM_Directory",
			Name="C:\\Windows")
		tripleFileStatRemote = mySourceFileStatRemote.GetTriplestore()
		print("Len tripleFileStatRemote=",len(tripleFileStatRemote))
		# This should not be empty.
		self.assertTrue(len(tripleFileStatRemote)>=1)

	def test_remote_instances_python_package(self):
		"""This loads a specific Python package"""
		mySourcePythonPackageRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/entity.py",
			"python/package",
			Id="rdflib")
		triplePythonPackageRemote = mySourcePythonPackageRemote.GetTriplestore()
		print("Len triplePythonPackageRemote=",len(triplePythonPackageRemote))

		instancesPythonPackageRemote = triplePythonPackageRemote.GetInstances()
		print("Len instancesPythonPackageRemote=",len(instancesPythonPackageRemote))
		lenInstances = len(instancesPythonPackageRemote)
		print("Len triplePythonPackageRemote=",lenInstances)
		# This Python module must be there because it is needed by Survol.
		self.assertTrue(lenInstances>=1)

	def test_remote_instances_java(self):
		"""Loads Java processes. There should be at least Java process,
		which is the one doing the test"""
		mySourceJavaRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/sources_types/java/java_processes.py")
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
		"""Loads machines visible with ARP. There should be at least one CIM_ComputerSystem instance"""
		mySourceArpRemote = lib_client.SourceRemote(
			"http://rchateau-hp:8000/survol/sources_types/neighborhood/cgi_arp_async.py")
		tripleArpRemote = mySourceArpRemote.GetTriplestore()
		print("Len tripleArpRemote=",len(tripleArpRemote))

		instancesArpRemote = tripleArpRemote.GetInstances()
		numComputers = 0
		for oneInstance in instancesArpRemote:
			if oneInstance.__class__.__name__ == "CIM_ComputerSystem":
				print("Found one machine:",oneInstance)
				numComputers += 1
		print("Remote hosts number=",numComputers)
		self.assertTrue(numComputers>=1)

	def test_merge_add_mixed(self):
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceRemote("http://rchateau-hp:8000/survol/sources_types/win32/tcp_sockets_windows.py")

		mySrcMergePlus = mySource1 + mySource2
		print("Merge plus:",str(mySrcMergePlus.content_rdf())[:30])
		triplePlus = mySrcMergePlus.GetTriplestore()
		print("Len triplePlus:",len(triplePlus))

		lenSource1 = len(mySource1.GetTriplestore().GetInstances())
		lenSource2 = len(mySource2.GetTriplestore().GetInstances())
		lenPlus = len(triplePlus.GetInstances())
		# In the merged link, there cannot be more instances than in the input sources.
		self.assertTrue(lenPlus <= lenSource1 + lenSource2)

	def test_merge_sub_mixed(self):
		mySource1 = lib_client.SourceLocal(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceRemote("http://rchateau-hp:8000/survol/sources_types/win32/win32_local_groups.py")

		mySrcMergeMinus = mySource1 - mySource2
		print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
		tripleMinus = mySrcMergeMinus.GetTriplestore()
		print("Len tripleMinus:",len(tripleMinus))

		lenSource1 = len(mySource1.GetTriplestore().GetInstances())
		lenMinus = len(tripleMinus.GetInstances())
		# There cannot be more instances after removal.
		self.assertTrue(lenMinus	 <= lenSource1 )

	def test_remote_scripts_list_CIM_LogicalDisk(self):
		myAgent = lib_client.Agent("http://rchateau-hp:8000")

		myInstancesRemote = myAgent.CIM_LogicalDisk(DeviceID="D:")
		listScripts = myInstancesRemote.GetScripts()
		# No scripts yet.
		self.assertTrue(len(listScripts) == 0)

	def test_remote_scripts_list_CIM_Directory(self):
		myAgent = lib_client.Agent("http://rchateau-hp:8000")

		myInstancesRemote = myAgent.CIM_Directory(Name="D:")
		listScripts = myInstancesRemote.GetScripts()
		for keyScript in listScripts:
			sys.stdout.write("    %s\n"%keyScript)
		# There should be at least a couple of scripts.
		self.assertTrue(len(listScripts) > 0)

	def test_remote_agents(self):
		"""This gets a list of agents accessible from the remote host,
		then tries to access them individually"""
		print("TODO: Not implemented yet")



if __name__ == '__main__':
	unittest.main()