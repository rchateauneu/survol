"""
Java world
"""

import os
import sys
import jpype
import lib_util
import lib_common
from jpype import java
from jpype import javax

globJavaJVM = None

# It is possible to return a similar object, but on a remote machine.
def JPypeLocalStartJVM():
	global globJavaJVM
	if globJavaJVM:
		return globJavaJVM

	try:
		if lib_util.isPlatformLinux:
			globJavaJVM = JPypeLocalStartJVMLinux()

		elif lib_util.isPlatformWindows:
			globJavaJVM = JPypeLocalStartJVMWindows()
		else:
			lib_common.ErrorMessageHtml("Uknown operating system")

	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("JavaJmxSystemProperties caught:" + str(exc))

	return globJavaJVM

def JPypeLocalStartJVMLinux():
	# Example: '/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib/amd64/server/libjvm.so'
	dfltPath = jpype.getDefaultJVMPath()

	# getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
	DEBUG("getDefaultJVMPath=%s", dfltPath)

	# Now extracts the version, which will be used for the JDK directionary.
	baseDfltJVM = os.path.dirname(dfltPath)
	baseJreRelative = os.path.join( baseDfltJVM, "..", ".." )

	baseJreAbs = os.path.abspath(baseJreRelative)
	# baseJreAbs=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib
	DEBUG("baseJreAbs=%s", baseJreAbs)

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
	DEBUG("getDefaultJVMPath=%s", dfltPath)

	# Now extracts the version, which will be used for the JDK directionary.
	baseDfltJVM = os.path.dirname(dfltPath)
	baseJreRelative = os.path.join( baseDfltJVM, "..", ".." )

	baseJreAbs = os.path.abspath(baseJreRelative)
	# baseJreAbs=C:\Program Files\Java\jre1.8.0_121
	DEBUG("baseJreAbs=%s", baseJreAbs)

	dirJre = os.path.basename(baseJreAbs)
	# dirJre=jre1.8.0_121
	DEBUG("dirJre=%s", dirJre)

	strJre = dirJre[:3]
	if strJre != "jre":
		# Our assumption on the directory syntax is wrong.
		DEBUG("Invalid strJre=%s", strJre)
		return None

	baseJava = os.path.dirname(baseJreAbs)
	dirJdk = "jdk" + dirJre[3:]

	JavaDirPrefix = os.path.join( baseJava, dirJdk )
	# JavaDirPrefix=C:\Program Files\Java\jdk1.8.0_121
	DEBUG("JavaDirPrefix=%s", JavaDirPrefix)

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

	DEBUG("Attaching to pid=%s type=%s",pid,type(pid))
	# jpype._jexception.AttachNotSupportedExceptionPyRaisable:
	# com.sun.tools.attach.AttachNotSupportedException:
	# Unable to attach to 32-bit process running under WOW64
	try:
		virtMach = jvPckVM.attach(str(pid))
	except:
		exc = sys.exc_info()
		WARNING("Exception:%s",str(exc))
		return dictResult

	DEBUG("Attached to pid=%s",pid)
	connectorAddress = virtMach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

	if not connectorAddress:
		# fileSeparator = "\\"
		# agent=C:\Program Files\Java\jre1.8.0_121\lib\management-agent.jar
		# agent = virtMach.getSystemProperties().getProperty("java.home") + fileSeparator + "lib" + fileSeparator + "management-agent.jar"

		agent = os.path.join( virtMach.getSystemProperties().getProperty("java.home"), "lib", "management-agent.jar" )

		DEBUG("agent=%s",str(agent))
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
		DEBUG("mbeanObjNam=%s",mbeanObjNam)
		jvxObjNam = javax.management.ObjectName(mbeanObjNam)
	else:
		jvxObjNam = None

	# jpype._jexception.MalformedObjectNameExceptionPyRaisable: javax.management.MalformedObjectNameException: Key properties cannot be empty
	allMBeans = connectMBean.queryMBeans(jvxObjNam,None)

	# allMBeans=[sun.management.OperatingSystemImpl[java.lang:type=OperatingSystem], sun.management.MemoryManagerImpl[java.
	DEBUG("allMBeans=%s",str(allMBeans))

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
			DEBUG("attr=%s",str(attr))
			DEBUG("attr.getName()=%s",attr.getName())
			DEBUG("attr.getType()=%s",attr.getType())
			DEBUG("attr.getDescription()=%s",attr.getDescription())

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

	DEBUG("VirtualMachine.dir=%s",str(dir(listVMs)))
	# sys.stderr.write("VirtualMachine.list=:\n")
	for oneVM in listVMs:
		dicByProps = dict()
		DEBUG("%s",oneVM)
		DEBUG("%s",str(dir(oneVM)))
		DEBUG("id=%s",str(oneVM.id()))
		DEBUG("displayName=%s",str(oneVM.displayName()))
		DEBUG("getClass=%s",str(oneVM.getClass()))
		DEBUG("provider=%s",str(oneVM.provider()))
		DEBUG("isAttachable=%s",str(oneVM.isAttachable()))
		DEBUG("toString=%s",str(oneVM.toString()))
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
# Better not stopping it because there might be several calls.
# On Windows, better reusing the same JVM.
def QuietShutdown():
	return
	# Must redirect the Java output
	# Shutdown the VM at the end
	if not lib_util.isPlatformLinux:
		jpype.shutdownJVM()


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
