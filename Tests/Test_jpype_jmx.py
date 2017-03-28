#!/usr/bin/env python2.6

import os
import sys
import jpype
from jpype import java
from jpype import javax

def OriginalTest():
	HOST='gf0'
	PORT=8386
	USER='admin'
	PASS='mypass'

	URL = "service:jmx:rmi:///jndi/rmi://%s:%d/jmxrmi" % (HOST, PORT)
	#this it the path of your libjvm /usr/lib/jvm/sun-jdk-1.6/jre/lib/amd64/server/libjvm.so on linux
	jpype.startJVM("/System/Library/Frameworks/JavaVM.framework/Libraries/libjvm_compat.dylib")
	java.lang.System.out.println("JVM load OK")

	jhash = java.util.HashMap()
	jarray=jpype.JArray(java.lang.String)([USER,PASS])
	jhash.put (javax.management.remote.JMXConnector.CREDENTIALS, jarray);
	jmxurl = javax.management.remote.JMXServiceURL(URL)
	jmxsoc = javax.management.remote.JMXConnectorFactory.connect(jmxurl,jhash)
	connection = jmxsoc.getMBeanServerConnection();


	object="java.lang:type=Threading"
	attribute="ThreadCount"
	attr=connection.getAttribute(javax.management.ObjectName(object),attribute)
	print  attribute, attr

	#Memory is a special case the answer is a Treemap in a CompositeDataSupport
	object="java.lang:type=Memory"
	attribute="HeapMemoryUsage"
	attr=connection.getAttribute(javax.management.ObjectName(object),attribute)
	print attr.contents.get("used")

def AnotherTest():
	# Installed with "pip install JPype1"
	import jpype
	jpype.startJVM(jpype.getDefaultJVMPath())

	# you can then access to the basic java functions
	jpype.java.lang.System.out.println("hello world")

	# and you have to shutdown the VM at the end
	jpype.shutdownJVM()



# Configuration
if False:
	JAVA_HOME='/home/faizan/downloads/jdk1.7.0_79'
	HOST = 'localhost'
	#PORT = 1099
	PORT = 4444
	LIBJVM=JAVA_HOME+'/jre/lib/amd64/server/libjvm.so'
	RESTCOMM_SMSC_LIBS="/home/faizan/gsm/smscgateway/release/target/jboss-5.1.0.GA/server/simulator/deploy/restcomm-smsc-server/lib/"
	URL = "service:jmx:rmi://localhost/jndi/rmi://localhost:1090/jmxconnector"


class RestCommJmx:
	def __init__(self):
		self.connection = None # mbeanServerConnection
	def connectToJmx(self):
		#this it the path of your libjvm /usr/lib/jvm/sun-jdk-1.6/jre/lib/amd64/server/libjvm.so on linux
		#jpype.startJVM(LIBJVM,"-Djava.class.path="+CLASSPATH+" -Djava.ext.dirs="+CLASSPATH)
		jpype.startJVM(LIBJVM,"-Djava.ext.dirs="+RESTCOMM_SMSC_LIBS)
		jmxurl = javax.management.remote.JMXServiceURL(URL)
		jmxsoc = javax.management.remote.JMXConnectorFactory.connect(jmxurl)
		self.connection = jmxsoc.getMBeanServerConnection()

	def check_association_alarm(self, assocLevel):
		object="org.mobicents.ss7:layer=ALARM,type=Management,name=AlarmHost"
		attribute="CurrentAlarmList"
		attr=self.connection.getAttribute(javax.management.ObjectName(object),attribute)
		alarmList = attr.getCurrentAlarmList()
		errMsg = ""
		for alarmMessage in alarmList:
			objName = alarmMessage.getObjectName()
			if str(objName).lower().startswith("%s:" % assocLevel.lower()) == False:
				continue
			if len(errMsg) > 0 :
				errMsg += "\n"
			errMsg += "%s - %s" % (objName, alarmMessage.getProblemName())
		return errMsg

def usage():
	scriptName = sys.argv[0]
	return "Usage: python %s association_type\n Where association_type is: Association for SCTP, ASP for ASP and AS for AS state check" % scriptName

if False:
	if __name__=="__main__":
		rjmx = RestCommJmx()
		rjmx.connectToJmx()
		if len(sys.argv)<2:
			print usage()
			sys.exit()
		errMsg = rjmx.check_association_alarm(sys.argv[1])
		print "%s" % errMsg


# http://stackoverflow.com/questions/35593185/is-there-a-jmx-service-url-for-local-non-tcp-connections
# http://stackoverflow.com/questions/516142/does-java-6-open-a-default-port-for-jmx-remote-connections/6985565#6985565


def JavaJmxPidMBeansAttach(pid,jvPckVM):
	CONNECTOR_ADDRESS = "com.sun.management.jmxremote.localConnectorAddress"

	sys.stdout.write("jvPckVM=%s\n"%str(jvPckVM))
	sys.stdout.write("Attaching to pid=%s\n"%pid)

	# jpype._jexception.AttachNotSupportedExceptionPyRaisable:
	# com.sun.tools.attach.AttachNotSupportedException:
	# Unable to attach to 32-bit process running under WOW64
	try:
		virtMach = jvPckVM.attach(pid)
		sys.stdout.write("virtMach:%s\n"%str(virtMach))
		vmSysProps = virtMach.getSystemProperties()
	except:
		exc = sys.exc_info()
		sys.stdout.write("Exception:%s\n"%str(exc))
		#sys.stdout.write("Exception:%s\n"%str(dir(exc)))
		return


	# vmSysProps = virtMach.getSystemProperties()
	for keySysProp in vmSysProps:
		valSysProp = vmSysProps[keySysProp]
		sys.stdout.write("==  %s => %s\n" %(keySysProp,valSysProp))

	connectorAddress = virtMach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

	if not connectorAddress:
		# fileSeparator = "\\"
		# agent=C:\Program Files\Java\jre1.8.0_121\lib\management-agent.jar
		# agent = virtMach.getSystemProperties().getProperty("java.home") + fileSeparator + "lib" + fileSeparator + "management-agent.jar"

		agent = os.path.join( vmSysProps.getProperty("java.home"), "lib", "management-agent.jar" )

		sys.stdout.write("agent=%s\n"%str(agent))
		virtMach.loadAgent(agent)
		# agent is started, get the connector address
		connectorAddress = virtMach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

	# "service:jmx:rmi://127.0.0.1/stub/rO0ABXN9AAAAAQ..."
	# sys.stdout.write("connectorAddress=%s\n"%str(connectorAddress))
	# sys.stdout.write("connectorAddress=%s\n"%str(dir(connectorAddress)))

	jmxUrl = javax.management.remote.JMXServiceURL(connectorAddress)
	jmxSoc = javax.management.remote.JMXConnectorFactory.connect(jmxUrl)
	# This interface represents a way to talk to an MBean server, whether local or remote.
	# The MBeanServer interface, representing a local MBean server, extends this interface.
	connectMBean = jmxSoc.getMBeanServerConnection()

	sys.stdout.write("connectMBean=%s\n"%str(connectMBean))
	# connectMBean=['addNotificationListener', 'class', 'createMBean', 'defaultDomain',
	#  'delegationSubject', 'domains', 'equals', 'getAttribute', 'getAttributes', 'getClass',
	#  'getDefaultDomain', 'getDomains', 'getMBeanCount', 'getMBeanInfo', 'getObjectInstance',
	#  'hashCode', 'invoke', 'isInstanceOf', 'isRegistered', 'mBeanCount', 'notify', 'notifyAll',
	#  'queryMBeans', 'queryNames', 'removeNotificationListener', 'setAttribute', 'setAttributes',
	#  'this$0', 'toString', 'unregisterMBean', 'wait']

	sys.stdout.write("connectMBean.getDefaultDomain=%s\n"%str(connectMBean.getDefaultDomain()))
	sys.stdout.write("connectMBean.getDomains=%s\n"%str(connectMBean.getDomains()))

	allMBeans = connectMBean.queryMBeans(None,None)
	sys.stdout.write("allMBeans=%s\n"%str(allMBeans))
	sys.stdout.write("allMBeans=%s\n"%str(dir(allMBeans)))

	for theMBean in allMBeans:
		# sys.stdout.write("\toneMBean=%s\n"%str(dir(theMBean)))
		sys.stdout.write("\toneMBean.objectName=%s\n"%theMBean.objectName)
		# sys.stdout.write("\toneMBean.name=%s\n"%theMBean.name) # Same as objectName
		oneMBean = connectMBean.queryMBeans(theMBean.objectName,None)
		sys.stdout.write("\toneMBean=%s\n"%str(oneMBean))
		sys.stdout.write("\toneMBean.size=%s\n"%str(oneMBean.size()))
		#sys.stdout.write("\toneMBean=%s\n"%str(dir(oneMBean)))
		sys.stdout.write("\n")

	#infoMBean = connectMBean.getMBeanInfo(None,None)
	#sys.stdout.write("infoMBean=%s\n"%str(infoMBean))


	virtMach.detach()

	# VirtualMachine vm = VirtualMachine.attach(pid);
	# String connectorAddress = null;
	# try {
	#     // get the connector address
	#     connectorAddress = vm.getAgentProperties().getProperty(CONNECTOR_ADDRESS);
	#
	#     // no connector address, so we start the JMX agent
	#     if (connectorAddress == null) {
	#        System.out.println("Agent not Started, loading it ...");
	#        String agent = vm.getSystemProperties().getProperty("java.home") +
	#            File.separator + "lib" + File.separator + "management-agent.jar";
	#        vm.loadAgent(agent);
	#
	#        // agent is started, get the connector address
	#        connectorAddress =
	#            vm.getAgentProperties().getProperty(CONNECTOR_ADDRESS);
	#     } else {
	#         System.out.println("JMX Agent already started !");
	#     }
	# } finally {
	#     vm.detach();
	# }
	#
	# System.out.println();
	# System.out.printf("Connecting to jmx server with connectorAddress : %s%n",connectorAddress);
	#
	# // establish connection to connector server
	# JMXServiceURL url = new JMXServiceURL(connectorAddress);
	# JMXConnector connector = JMXConnectorFactory.connect(url);
	#
	# MBeanServerConnection con = connector.getMBeanServerConnection();
	#
	# RuntimeMXBean runtime = ManagementFactory.newPlatformMXBeanProxy(
	#        con, ManagementFactory.RUNTIME_MXBEAN_NAME, RuntimeMXBean.class);
	# System.out.printf("Extracted classpath : %s%n",runtime.getClassPath());





def JPypeLocalStartJVM():
	dfltPath = jpype.getDefaultJVMPath()

	# getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
	sys.stdout.write("getDefaultJVMPath=%s\n" % dfltPath)

	# Now extracts the version, which will be used for the JDK directionary.
	baseDfltJVM = os.path.dirname(dfltPath)
	baseJreRelative = os.path.join( baseDfltJVM, "..", ".." )

	baseJreAbs = os.path.abspath(baseJreRelative)
	# baseJreAbs=C:\Program Files\Java\jre1.8.0_121
	sys.stdout.write("baseJreAbs=%s\n" % baseJreAbs)

	dirJre = os.path.basename(baseJreAbs)
	# dirJre=jre1.8.0_121
	sys.stdout.write("dirJre=%s\n" % dirJre)

	strJre = dirJre[:3]
	if strJre != "jre":
		# Our assumption on the directory syntax is wrong.
		return None

	baseJava = os.path.dirname(baseJreAbs)
	dirJdk = "jdk" + dirJre[3:]

	JavaDirPrefix = os.path.join( baseJava, dirJdk )
	# JavaDirPrefix=C:\Program Files\Java\jdk1.8.0_121
	sys.stdout.write("JavaDirPrefix=%s\n" % JavaDirPrefix)

	osPath = os.environ["PATH"]

	# JavaDirPrefix = "C:\\Program Files\\Java\\jdk1.8.0_121"

	# "attach.dll" is not in the jre.
	#sys.stdout.write("PATH=%s\n"%osPath)
	# pathAttachDll = "C:\\Program Files\\Java\\jdk1.8.0_121\\jre\\bin"
	pathAttachDll = JavaDirPrefix + "\\jre\\bin"
	os.environ["PATH"] = osPath + ";" + pathAttachDll

	# We need to open tools.jar which is in C:\Program Files\Java\jdk1.8.0_121\lib
	# jpype.startJVM(dfltPath,attachPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
	# jpype.startJVM(dfltPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
	jpype.startJVM(dfltPath,"-Djava.class.path=" + JavaDirPrefix + "\\lib\\tools.jar")

	#jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
	VirtualMachine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

	#jvPckVMinstance = VirtualMachine()
	#tmpId = jvPckVMinstance.id()
	#sys.stdout.write("jvPckVM.id=%s\n"%str(tmpId))

	jvPckVM = VirtualMachine
	return jvPckVM

def JPypeListVMs(jvPckVM):
	resuProcs = dict()
	listVMs = jvPckVM.list()

	sys.stdout.write("jvPckVM.dir=%s\n"%str(dir(jvPckVM)))
	sys.stdout.write("jvPckVM.toString=%s\n"%str(jvPckVM))
	# sys.stdout.write("jvPckVM.getSystemProperties=%s\n"%str(jvPckVM.getSystemProperties()))
	sys.stdout.write("VirtualMachine.list=:\n")
	for oneVM in listVMs:
		dicByProps = dict()
		sys.stdout.write("\n%s\n"%oneVM)
		#sys.stdout.write("\t%s\n"%str(dir(oneVM)))
		sys.stdout.write("\tid=%s\n"%str(oneVM.id()))
		sys.stdout.write("\tdisplayName=%s\n"%str(oneVM.displayName()))
		sys.stdout.write("\tgetClass=%s\n"%str(oneVM.getClass()))
		sys.stdout.write("\tprovider=%s\n"%str(oneVM.provider()))
		sys.stdout.write("\tisAttachable=%s\n"%str(oneVM.isAttachable()))
		sys.stdout.write("\ttoString=%s\n"%str(oneVM.toString()))
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


# http://blog.ippon.fr/2012/02/05/monitorer-une-JVM-en-local/
def TestLocal():
	#jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
	jvPckVM = JPypeLocalStartJVM()

	listVMs = JPypeListVMs(jvPckVM)

	#listVMs = jvPckVM.list()
	# sys.stdout.write("VirtualMachine.dir=%s\n"%str(dir(listVMs)))
	sys.stdout.write("VirtualMachine.list=:\n")
	for thePid in listVMs:
		theProcObj = listVMs[thePid]
		for theKey in theProcObj:
			theVal = theProcObj[theKey]
			sys.stdout.write("\t#### %s = %s\n"%(theKey,theVal))
		JavaJmxPidMBeansAttach(thePid,jvPckVM)
		sys.stdout.write("\n")


	# For convenience, the jpype modules predefines the following JPackages : java, javax
	# They can be used as is, without needing to resort to the JPackage class.
	# This packages allows structured access to java packages and classes. It is very similar to a python import statement.
	# Only the root of the package tree need be declared with the JPackage constructor. sub-packages will be created on demand

	java.lang.System.out.println("\nHello World!!")






	# and you have to shutdown the VM at the end
	jpype.shutdownJVM()

	# ERRATIC CRASH WHEN LEAVING !!!
	#
	# A fatal error has been detected by the Java Runtime Environment:
	#
	#  EXCEPTION_ACCESS_VIOLATION (0xc0000005) at pc=0x00000000543d970c, pid=4588, tid=0x0000000000003a20
	#
	# JRE version: Java(TM) SE Runtime Environment (8.0_121-b13) (build 1.8.0_121-b13)
	# Java VM: Java HotSpot(TM) 64-Bit Server VM (25.121-b13 mixed mode windows-amd64 compressed oops)
	# Problematic frame:
	# V  [jvm.dll+0x14970c]
	#
	# Failed to write core dump. Minidumps are not enabled by default on client versions of Windows
	#

# https://nmap.org/nsedoc/scripts/rmi-dumpregistry.html
# Connects to a remote RMI registry and attempts to dump all of its objects.
# Mais on peut aussi le faire proprement, peut-etre.
# Toutefois, utile si on n'a pas les librairies necessaires.
# Quand on scanne avec nmap, il faudrait envoyer vers la deteciton specifique jmx,
# ou tout autre script dependant du protocole.

def TestRemote():
	dfltPath = jpype.getDefaultJVMPath()
	jpype.startJVM(dfltPath)
	# Connection refused.
	# URL = "service:jmx:rmi://localhost/jndi/rmi://localhost:1090/jmxconnector"

	# jpype._jexception.IOExceptionPyRaisable: java.io.IOException:
	# Failed to retrieve RMIServer stub: javax.naming.CommunicationException
	# [Root exception is java.rmi.NoSuchObjectException: no such object in table]
	URL = "service:jmx:rmi://localhost/jndi/rmi://localhost:52964/jmxconnector"

	#  Failed to retrieve RMIServer stub: javax.naming.CommunicationException
	# [Root exception is java.rmi.NoSuchObjectException: no such object in table]
	URL = "service:jmx:rmi:///jndi/rmi://localhost:52964/jmxrmi"

	# jpype._jexception.ClassCastExceptionPyRaisable:
	# java.lang.ClassCastException: com.sun.jndi.rmi.registry.RegistryContext cannot be cast to javax.management.remote.rmi.RMIServer
	URL = "service:jmx:rmi:///jndi/rmi://localhost:52964/"

	# Connection refused to host: localhost; nested exception is: java.net.ConnectException
	URL = "service:jmx:rmi:///jndi/rmi://localhost:1090/jmxrmi"

	# URL = "service:jmx:rmi:///jndi/rmi://%s:%d/jmxrmi" % (HOST, PORT)

	jmxurl = javax.management.remote.JMXServiceURL(URL)

	# "jmxurl=service:jmx:rmi:///jndi/rmi://localhost:52964/jmxrmi"
	print("jmxurl=%s"%str(jmxurl))

	# It throws here:
	jmxsoc = javax.management.remote.JMXConnectorFactory.connect(jmxurl)
	theconnection = jmxsoc.getMBeanServerConnection()

	# and you have to shutdown the VM at the end
	jpype.shutdownJVM()






def AnotherOtherTest():
	# Installed with "pip install JPype1"
	import jpype

	theLocal = True

	if theLocal:
		TestLocal()
	else:
		TestRemote()




AnotherOtherTest()

