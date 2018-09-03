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


#Verifier les fichiers des modules
#Virer dans sys.path tout ce qui contient "survol"
#Verifier qu on ne touche pas au sys.path
#Verifier les id des variables identiques dans plusieurs modules homonymes.

# This deletes the module so we can reload them each time.
# Problem: survol modules are not detectable.
# We could as well delete all modules except sys.
allModules = [ modu for modu in sys.modules if modu.startswith("survol") or modu.startswith("lib_")]

for modu in allModules:
	# sys.stderr.write("Deleting %s\n"%modu)
	del sys.modules[modu]

#sys.stderr.write("%s\n"%__file__)
import lib_client
#sys.stderr.write("Done %s\n"%__file__)

cgitb.enable(format="txt")

# TODO: Prefix of url samples should be a parameter.

class SurvolBasicTest(unittest.TestCase):

	def test_create_source_url(self):
		# http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A%2FWindows%2Fexplorer.exe
		mySourceFileStatRemote = lib_client.SourceUrl(
			"http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		print("urlFileStatRemote=",mySourceFileStatRemote.Url())
		print("qryFileStatRemote=",mySourceFileStatRemote.UrlQuery())
		print("jsonFileStatRemote=",str(mySourceFileStatRemote.content_json())[:30])
		print("rdfFileStatRemote=",str(mySourceFileStatRemote.content_rdf())[:30])

	def test_create_source_script(self):
		# This should return the same content, but much faster.
		mySourceFileStatLocal = lib_client.SourceScript(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		print("qryFileStatLocal=%s"%mySourceFileStatLocal.UrlQuery())
		print("jsonFileStatLocal=%s"%str(mySourceFileStatLocal.content_json())[:30])
		print("rdfFileStatLocal=%s"%str(mySourceFileStatLocal.content_rdf())[:30])

	def test_remote_triplestore(self):
		mySourceFileStatRemote = lib_client.SourceUrl(
			"http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		tripleFileStatRemote = mySourceFileStatRemote.get_triplestore()

	def test_remote_instances(self):
		mySourceFileStatRemote = lib_client.SourceUrl(
			"http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		tripleFileStatRemote = mySourceFileStatRemote.get_triplestore()

		instancesFileStatRemote = tripleFileStatRemote.GetInstances()
		print("Len tripleFileStatRemote=",len(instancesFileStatRemote))

	def test_local_triplestore(self):
		mySourceFileStatLocal = lib_client.SourceScript(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		tripleFileStatLocal = mySourceFileStatLocal.get_triplestore()

	def test_local_instances(self):
		mySourceFileStatLocal = lib_client.SourceScript(
			"sources_types/CIM_DataFile/file_stat.py",
			"CIM_DataFile",
			Name="C:\\Windows\\explorer.exe")
		tripleFileStatLocal = mySourceFileStatLocal.get_triplestore()

		# Comparison
		import lib_common
		lib_common.globalErrorMessageEnabled = False
		print(tripleFileStatLocal.m_triplestore)
		instancesFileStatLocal = tripleFileStatLocal.GetInstances()
		print("Len tripleFileStatLocal=",len(instancesFileStatLocal))

	def test_merge_add(self):
		# Test merge of heterogeneous data sources.
		mySource1 = lib_client.SourceScript(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")

		content1 = mySource1.content_json()
		print( "content1=",str(content1.keys()))

		mySource2 = lib_client.SourceUrl("http://rchateau-hp:8000/survol/sources_types/java/java_processes.py")

	def test_merge_add(self):
		mySource1 = lib_client.SourceScript(
			"entity.py",
			"CIM_LogicalDisk",
			DeviceID="D:")
		mySource2 = lib_client.SourceUrl("http://rchateau-hp:8000/survol/sources_types/java/java_processes.py")

		mySrcMergePlus = self.mySource1 + self.mySource2
		print("Merge plus:",str(mySrcMergePlus.content_rdf())[:30])
		triplePlus = mySrcMergePlus.get_triplestore()
		#print("triplePlus:",triplePlus.keys()[:30])

	def test_merge_sub(self):
		mySrcMergeMinus = self.mySource1 - self.mySource2
		print("Merge Minus:",str(mySrcMergeMinus.content_rdf())[:30])
		tripleMinus = mySrcMergeMinus.get_triplestore()
		#print("tripleMinus:",triplePlus.keys()[:30])


	def test_merge_duplicate(self):
		mySourceDupl = lib_client.SourceScript(
			"sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py",
			"Win32_UserAccount",
			Domain="rchateau-hp",
			Name="rchateau")
		tripleDupl = self.mySourceDupl.get_triplestore()
		print("Len tripleDupl=",len(tripleDupl.GetInstances()))

		mySrcMergePlus = mySourceDupl + mySourceDupl
		triplePlus = mySrcMergePlus.get_triplestore()
		print("Len triplePlus=",len(triplePlus.GetInstances()))

		mySrcMergeMinus = mySourceDupl - mySourceDupl
		tripleMinus = mySrcMergeMinus.get_triplestore()
		print("Len tripleMinus=",len(tripleMinus.GetInstances()))

	def test_exception_bad_source(self):
		# This tests if errors are properly displayed.
		mySourceBad = lib_client.SourceScript(
			"xxx/yyy/zzz.py",
			"uuuuu")
		try:
			tripleBad = mySourceBad.get_triplestore()
		except Exception as exc:
			print("Error detected:",exc)


		mySourceBad = lib_client.SourceUrl(
			"http://rchateau-hp:8000/xxx/yyy/zzz/ttt.py",
			"wwwww")
		try:
			tripleBad = mySourceBad.get_triplestore()
		except Exception as exc:
			print("Error detected:",exc)


if __name__ == '__main__':
    unittest.main()