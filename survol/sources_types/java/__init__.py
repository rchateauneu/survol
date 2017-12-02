"""
Java world
"""

import os
import sys
import jpype
import lib_util
from jpype import java
from jpype import javax

# It is possible to return a similar object, but on a remote machine.
def JPypeLocalStartJVM():
	if lib_util.isPlatformLinux:
		return JPypeLocalStartJVMLinux()

	if lib_util.isPlatformWindows:
		return JPypeLocalStartJVMWindows()

	return None

def JPypeLocalStartJVMLinux():
	# Example: '/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib/amd64/server/libjvm.so'
	dfltPath = jpype.getDefaultJVMPath()

	# getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
	sys.stderr.write("getDefaultJVMPath=%s\n" % dfltPath)

	# Now extracts the version, which will be used for the JDK directionary.
	baseDfltJVM = os.path.dirname(dfltPath)
	baseJreRelative = os.path.join( baseDfltJVM, "..", ".." )

	baseJreAbs = os.path.abspath(baseJreRelative)
	# baseJreAbs=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib
	sys.stderr.write("baseJreAbs=%s\n" % baseJreAbs)

	JavaDirPrefix = os.path.join( baseJreAbs, "../.." )

	# We need to open tools.jar which is in /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/lib/tools.jar
	# jpype.startJVM(dfltPath,"-Djava.class.path=/usr/lib ... /tools.jar")
	jpype.startJVM(dfltPath,"-Djava.class.path=" + JavaDirPrefix + "/lib/tools.jar")

	#jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
	VirtualMachine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

	return VirtualMachine


def JPypeLocalStartJVMWindows():
	# u'C:\\Program Files\\Java\\jre1.8.0_121\\bin\\server\\jvm.dll'
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
		sys.stderr.write("Invalid strJre=%s\n" % strJre)
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
	VirtualMachine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

	os.environ["PATH"] = pathOriginal

	return VirtualMachine


# Attaching to a process is riskier, so we do not do it when listing all Java processes.
# This procedure needs to attache and might fail sometimes.
def JavaJmxPidMBeansAttach(pid,jvPckVM,mbeanObjNam = None):
	CONNECTOR_ADDRESS = "com.sun.management.jmxremote.localConnectorAddress"

	dictResult = {}

	sys.stderr.write("Attaching to pid=%s type=%s\n"%(pid,type(pid)))
	# jpype._jexception.AttachNotSupportedExceptionPyRaisable:
	# com.sun.tools.attach.AttachNotSupportedException:
	# Unable to attach to 32-bit process running under WOW64
	try:
		virtMach = jvPckVM.attach(str(pid))
	except:
		exc = sys.exc_info()
		sys.stderr.write("Exception:%s\n"%str(exc))
		return dictResult

	sys.stderr.write("Attached to pid=%s\n"%pid)
	connectorAddress = virtMach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

	if not connectorAddress:
		# fileSeparator = "\\"
		# agent=C:\Program Files\Java\jre1.8.0_121\lib\management-agent.jar
		# agent = virtMach.getSystemProperties().getProperty("java.home") + fileSeparator + "lib" + fileSeparator + "management-agent.jar"

		agent = os.path.join( virtMach.getSystemProperties().getProperty("java.home"), "lib", "management-agent.jar" )

		sys.stderr.write("agent=%s\n"%str(agent))
		virtMach.loadAgent(agent)
		# agent is started, get the connector address
		connectorAddress = virtMach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

	dictResult["connector"] = connectorAddress

	# "service:jmx:rmi://127.0.0.1/stub/rO0ABXN9AAAAAQ..."
	# sys.stdout.write("connectorAddress=%s\n"%str(connectorAddress))
	# sys.stdout.write("connectorAddress=%s\n"%str(dir(connectorAddress)))

	jmxUrl = javax.management.remote.JMXServiceURL(connectorAddress)
	jmxSoc = javax.management.remote.JMXConnectorFactory.connect(jmxUrl)
	# This interface represents a way to talk to an MBean server, whether local or remote.
	# The MBeanServer interface, representing a local MBean server, extends this interface.
	connectMBean = jmxSoc.getMBeanServerConnection()

	# sys.stderr.write("connectMBean=%s\n"%str(connectMBean))
	# connectMBean=['addNotificationListener', 'class', 'createMBean', 'defaultDomain',
	#  'delegationSubject', 'domains', 'equals', 'getAttribute', 'getAttributes', 'getClass',
	#  'getDefaultDomain', 'getDomains', 'getMBeanCount', 'getMBeanInfo', 'getObjectInstance',
	#  'hashCode', 'invoke', 'isInstanceOf', 'isRegistered', 'mBeanCount', 'notify', 'notifyAll',
	#  'queryMBeans', 'queryNames', 'removeNotificationListener', 'setAttribute', 'setAttributes',
	#  'this$0', 'toString', 'unregisterMBean', 'wait']

	# sys.stderr.write("connectMBean.getDefaultDomain=%s\n"%str(connectMBean.getDefaultDomain()))
	# sys.stderr.write("connectMBean.getDomains=%s\n"%str(connectMBean.getDomains()))

	# mbeanObjNam = "com.sun.management:type=HotSpotDiagnostic"
	if mbeanObjNam:
		sys.stderr.write("mbeanObjNam=%s\n"%mbeanObjNam)
		jvxObjNam = javax.management.ObjectName(mbeanObjNam)
	else:
		jvxObjNam = None

	# jpype._jexception.MalformedObjectNameExceptionPyRaisable: javax.management.MalformedObjectNameException: Key properties cannot be empty
	allMBeans = connectMBean.queryMBeans(jvxObjNam,None)

	# allMBeans=[sun.management.OperatingSystemImpl[java.lang:type=OperatingSystem], sun.management.MemoryManagerImpl[java.
	sys.stderr.write("allMBeans=%s\n"%str(allMBeans))

	vectMBeans = []

	# Gets as much information as possible about this MBean.
	for eltMBean in allMBeans:
		mbeanObjectName = eltMBean.getObjectName()
		oneMBean = {
			"className" : eltMBean.getClassName(),
			"objectName" : str(mbeanObjectName)
		}

		# TODO: To save time, we could do that only if mbeanObjNam is not None.
		oneMBeanInfo = connectMBean.getMBeanInfo(mbeanObjectName)

		descrMBeanInfo = oneMBeanInfo.getDescriptor()
		dictMBeanInfoDescr = {}
		for keyMBeanInfo in descrMBeanInfo.getFieldNames():
			valMBeanInfo = descrMBeanInfo.getFieldValue(keyMBeanInfo)
			dictMBeanInfoDescr[keyMBeanInfo] = valMBeanInfo
		oneMBean["info"] = dictMBeanInfoDescr

		for attr in oneMBeanInfo.getAttributes():
			sys.stderr.write("\t\tattr=%s\n"%str(attr))
			sys.stderr.write("\t\tattr.getName()=%s\n"%attr.getName())
			sys.stderr.write("\t\tattr.getType()=%s\n"%attr.getType())
			sys.stderr.write("\t\tattr.getDescription()=%s\n"%attr.getDescription())

		attrsMBeanInfo = oneMBeanInfo.getAttributes()
		dictMBeanInfo = {}
		for oneAttr in attrsMBeanInfo:
			keyAttr = oneAttr.getName()
			# int=<class'jpype._jclass.java.lang.Integer'>\
			getTp = oneAttr.getType()
			try:
				getAttr = connectMBean.getAttribute(mbeanObjectName,keyAttr)
				# Without a concatenation, it prints "1" instead of boolean True.
				valAttr = str(getAttr) + " (%s)" % getTp
			except:
				valAttr = "N/A"
			dictMBeanInfo[keyAttr] = valAttr
		oneMBean["attrs"] = dictMBeanInfo

		vectMBeans.append( oneMBean )

	dictResult["allMBeans"] = vectMBeans

	# When detaching, all the intermediary objects created by connectMBean are deleted.
	# This is why their content must be stored.
	virtMach.detach()

	return dictResult

# https://www.jtips.info/index.php?title=JMX/Remote

def JavaJmxSystemProperties(pid):
	jvPckVM = JPypeLocalStartJVM()
	try:
		virtMach = jvPckVM.attach(str(pid))
	except:
		exc = sys.exc_info()
		vmSysProps = {
			"jvPckVM" : str(jvPckVM),
			"JMX error" : str(exc),
			"Pid" : str(pid) }
		return vmSysProps

	try:
		gsp = virtMach.getSystemProperties()
		vmSysProps = {}

		for k in gsp:
			v = gsp[k]
			vmSysProps[k] = v

		# J ai tout le temps cette erreur alors que ca marche en programme de test:
		#
		# (<type 'exceptions.RuntimeError'>,
		# RuntimeError('No matching overloads found.
		# at native\common\jp_method.cpp:117',),
		# <traceback object at
		# 0x0000000004ADAC48>\

		virtMach.detach()
	except:
		exc = sys.exc_info()
		vmSysProps = {
			"VM" : str(virtMach),
			"JMX error" : str(exc),
			"Pid" : str(pid) }

	# Shutdown the VM at the end
	QuietShutdown()
	return vmSysProps


# This returns a list of processes without attaching to them,
# so it is simpler and faster.
# The result is a map indexed by pids.
def JPypeListVMs(jvPckVM):
	resuProcs = dict()
	if not jvPckVM:
		return resuProcs

	listVMs = jvPckVM.list()

	sys.stderr.write("VirtualMachine.dir=%s\n"%str(dir(listVMs)))
	# sys.stderr.write("VirtualMachine.list=:\n")
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
		# JavaJmxPidMBeansAttach(oneVM.id(),jvPckVM)

		dicByProps["class"] = oneVM.getClass()
		dicByProps["provider"] = oneVM.provider()
		dicByProps["isAttachable"] = oneVM.isAttachable()

		# sun.tools.attach.WindowsAttachProvider@3f99bd52: 8084 sun.tools.jconsole.JConsole
		dicByProps["toString"] = oneVM.toString()

		# Same as "toString"
		# dicByProps["str"] = str(oneVM)

		resuProcs[oneVM.id()] = dicByProps

	return resuProcs

# This fails on Linux.
def QuietShutdown():
        # Must redirect the Java output
	# Shutdown the VM at the end
	if not lib_util.isPlatformLinux:
		jpype.shutdownJVM()
	return


# TODO: This could work on a remote machine if we have the Java RMI port number and user/pass.
def ListJavaProcesses():
	jvPckVM = JPypeLocalStartJVM()

	listVMs = JPypeListVMs(jvPckVM)

	# Shutdown the VM at the end
	QuietShutdown()

	return listVMs

# TODO: This could work on a remote machine if we have the Java RMI port number and user/pass.
# If mbeanObjNam is None, returns data for all MBeans.
def GetJavaDataFromJmx(thePid,mbeanObjNam = None):
	jvPckVM = JPypeLocalStartJVM()

	javaResults = JavaJmxPidMBeansAttach(thePid,jvPckVM,mbeanObjNam)

	# Some extra data to add ??
	# jvValDict = jvPckVM[thePid]
	# for jvKey in jvPckVM:

	# Shutdown the VM at the end
	QuietShutdown()

	return javaResults



# Development notes:
#
# https://stackoverflow.com/questions/10331189/how-to-find-the-default-jmx-port-number
# C:\Users\rchateau>jvisualvm
# The launcher has determined that the parent process has a console and will reuse it for its own console output.
# Closing the console will result in termination of the running program.
# Use '--console suppress' to suppress console output.
# Use '--console new' to create a separate console window.
#
#
# # Start this command on both machines. Notepad is a simple app. Security disabled.
# java -Dcom.sun.management.jmxremote  \
# -Dcom.sun.management.jmxremote.port=9010 \
# -Dcom.sun.management.jmxremote.local.only=false \
# -Dcom.sun.management.jmxremote.authenticate=false  \
# -Dcom.sun.management.jmxremote.ssl=false   -jar Notepad.jar
#
# jconsole usable on Windows (192.168.0.14) and Linux (192.168.0.17)
# Start it in remote mode with port 9010.
#
# Problem: How can we have the list of remote machines running on a remote host?
# Do they all have a distinct port number ?
# Can we share this port number ?
#
# https://www.optiv.com/blog/exploiting-jmx-rmi
#
#
# Credentials would be like: "JMI" : { "192.168.0.14:9010" : ( "user", "pass" ) }
#
#
