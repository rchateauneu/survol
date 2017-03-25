import os
import sys
import jpype
from jpype import java
from jpype import javax

# It is possible to return a similar object, but on a remote machine.
def JPypeLocalStartJVM():
	dfltPath = jpype.getDefaultJVMPath()

	# getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
	sys.stderr.write("getDefaultJVMPath=%s\n" % dfltPath)

	# Now extracts the version, which will be used for the JDK directionary.
	baseDfltJVM = os.path.dirname(dfltPath)
	baseJreRelative = os.path.join( baseDfltJVM, "..", ".." )

	baseJreAbs = os.path.abspath(baseJreRelative)
	# baseJreAbs=C:\Program Files\Java\jre1.8.0_121
	sys.stderr.write("baseJreAbs=%s\n" % baseJreAbs)

	dirJre = os.path.basename(baseJreAbs)
	# dirJre=jre1.8.0_121
	sys.stderr.write("dirJre=%s\n" % dirJre)

	strJre = dirJre[:3]
	if strJre != "jre":
		# Our assumption on the directory syntax is wrong.
		return None

	baseJava = os.path.dirname(baseJreAbs)
	dirJdk = "jdk" + dirJre[3:]

	JavaDirPrefix = os.path.join( baseJava, dirJdk )
	# JavaDirPrefix=C:\Program Files\Java\jdk1.8.0_121
	sys.stderr.write("JavaDirPrefix=%s\n" % JavaDirPrefix)

	osPath = os.environ["PATH"]

	# JavaDirPrefix = "C:\\Program Files\\Java\\jdk1.8.0_121"

	# "attach.dll" is not in the jre.
	#sys.stdout.write("PATH=%s\n"%osPath)
	# pathAttachDll = "C:\\Program Files\\Java\\jdk1.8.0_121\\jre\\bin"
	pathAttachDll = JavaDirPrefix + "\\jre\\bin"

	pathOriginal = os.environ["PATH"]

	os.environ["PATH"] = osPath + ";" + pathAttachDll

	# We need to open tools.jar which is in C:\Program Files\Java\jdk1.8.0_121\lib
	# jpype.startJVM(dfltPath,attachPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
	# jpype.startJVM(dfltPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
	jpype.startJVM(dfltPath,"-Djava.class.path=" + JavaDirPrefix + "\\lib\\tools.jar")

	#jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
	jvPckVM = jpype.JPackage('com').sun.tools.attach.VirtualMachine

	os.environ["PATH"] = pathOriginal

	return jvPckVM

def JPypeListVMs(jvPckVM):
	resuProcs = dict()
	listVMs = jvPckVM.list()
	sys.stderr.write("VirtualMachine.list=:\n")
	for oneVM in listVMs:
		dicByProps = dict()
		sys.stderr.write("\n%s\n"%oneVM)
		sys.stderr.write("\t%s\n"%str(dir(oneVM)))
		sys.stderr.write("\tid=%s\n"%str(oneVM.id()))
		sys.stderr.write("\tdisplayName=%s\n"%str(oneVM.displayName()))
		sys.stderr.write("\tgetClass=%s\n"%str(oneVM.getClass()))
		sys.stderr.write("\tprovider=%s\n"%str(oneVM.provider()))
		sys.stderr.write("\tisAttachable=%s\n"%str(oneVM.isAttachable()))
		sys.stderr.write("\ttoString=%s\n"%str(oneVM.toString()))
		# JmxInvestigatePid(oneVM.id(),jvPckVM)

		dicByProps["class"] = oneVM.getClass()
		dicByProps["provider"] = oneVM.provider()
		dicByProps["isAttachable"] = oneVM.isAttachable()

		# sun.tools.attach.WindowsAttachProvider@3f99bd52: 8084 sun.tools.jconsole.JConsole
		dicByProps["toString"] = oneVM.toString()

		# Same as "toString"
		# dicByProps["str"] = str(oneVM)

		resuProcs[oneVM.id()] = dicByProps

	return resuProcs

def ListJavaProcesses():
	jvPckVM = JPypeLocalStartJVM()

	listVMs = JPypeListVMs(jvPckVM)


	# and you have to shutdown the VM at the end
	jpype.shutdownJVM()

	return listVMs
