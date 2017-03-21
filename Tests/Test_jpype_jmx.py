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


# class _withJMXConnection(object):
# 	connection = None
#
# 	def __init__(self, fn, url):
# 		self.fn = fn
# 		if not _withJMXConnection.connection:
# 			# set up a jmx connection ...
# 			jpype.startJVM("libjvm.so", "-Dcom.sun.management.jmxremote.authenticate=false", "-Xms20m", "-Xmx20m")
# 			jmxurl = jpype.javax.management.remote.JMXServiceURL(url)
# 			jmxsoc = jpype.javax.management.remote.JMXConnectorFactory.connect(jmxurl)
# 			_withJMXConnection.connection = jmxsoc.getMBeanServerConnection()
# 		self.connection = _withJMXConnection.connection

# https://www.snip2code.com/Snippet/1197207/Restcomm-JSS7-SMSC-SIGTRAN-Association-m


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


def TestLocalOld():
	# http://stackoverflow.com/questions/13252914/how-to-connect-to-a-local-jmx-server-by-knowing-the-process-id
	#
	# public static MBeanServerConnection getLocalMBeanServerConnectionStatic(int pid) {
	#     try {
	#         String address = ConnectorAddressLink.importFrom(pid);
	#         JMXServiceURL jmxUrl = new JMXServiceURL(address);
	#         return JMXConnectorFactory.connect(jmxUrl).getMBeanServerConnection();
	#     } catch (IOException e) {
	#         throw new RuntimeException("Of course you still have to implement a good connection handling");
	#     }
	# }
	pid = 8824
	# URL = ConnectorAddressLink.importFrom(pid)

	# Package javax.management.remote.ConnectorAddressLink.importFrom is not Callable
	# URL = javax.management.remote.ConnectorAddressLink.importFrom(pid)

	#from jpype import sun

	URL = javax.management.ConnectorAddressLink.importFrom(pid)

	# jmxurl = javax.management.remote.JMXServiceURL(URL)
	jmxurl = javax.management.remote.JMXServiceURL(URL)

	# "jmxurl=service:jmx:rmi:///jndi/rmi://localhost:52964/jmxrmi"
	print("jmxurl=%s"%str(jmxurl))

	# It throws here:
	jmxsoc = javax.management.remote.JMXConnectorFactory.connect(jmxurl)
	theconnection = jmxsoc.getMBeanServerConnection()

# from jpype import java
# from jpype import javax

# from jpype import com
from jpype import *

# http://blog.ippon.fr/2012/02/05/monitorer-une-JVM-en-local/
def TestLocal():
	pid = 8824

	dfltPath = jpype.getDefaultJVMPath()

	# getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
	sys.stdout.write("getDefaultJVMPath=%s\n" % dfltPath)

	osPath = os.environ["PATH"]
	sys.stdout.write("PATH=%s\n"%osPath)
	os.environ["PATH"] = osPath + ";C:\\Program Files\\Java\\jdk1.8.0_121\\jre\\bin"

	# attach.dll is in C:\Program Files\Java\jdk1.8.0_121\jre\bin
	attachPath = "-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/jre/bin"
	# attachPath = ""

	# We need to open tools.jar which is in C:\Program Files\Java\jdk1.8.0_121\lib

	# Can add extra parameters such as: "-ea -Djava.class.path=..."
	# jpype.startJVM(jvmPath, "-Djava.class.path=/home/di/eclipse_plugins/plugins/*.jar")
	# jpype.startJVM(dfltPath, "-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/*.jar")
	jpype.startJVM(dfltPath,attachPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")

	#jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
	jvPck = jpype.JPackage('com').sun.tools.attach.VirtualMachine

	sys.stdout.write("jvPck=%s\n"%str(jvPck))
	sys.stdout.write("jvPck=%s\n"%str(dir(jvPck)))

	xyz = jvPck.list()
	sys.stdout.write("jvPck=%s\n"%str(xyz))

	# For convenience, the jpype modules predefines the following JPackages :
	# java, javax
	# They can be used as is, without needing to resort to the JPackage class.
	# This packages allows structured access to java packages and classes. It is very similar to a python import statement.
	# Only the root of the package tree need be declared with the JPackage constructor.  sub-packages will be created on
	# demand

	# vmdList = jpype.com.sun.tools.attach.VirtualMachine.list()

	# toto=<Java package java.com.sun.tools.attach.VirtualMachine>
	# jvPck = java.com.sun.tools.attach.VirtualMachine

	# Avec ca, dir() imprime plein de trucs.
	# jvPck = JPackage('org').w3c.dom.Document # .sun.tools.attach.VirtualMachine

	# On pourrait mettre n importe quoi.
	# jvPck = JPackage('com').sun.tools.attach.VirtualMachine
	# jvPck = JPackage('com').sun.tools.attach.VirtualMachine
	#jvPck = JPackage('com.sun.tools.attach.VirtualMachine')

	#sys.stdout.write("jvPck=%s\n"%str(jvPck))
	#sys.stdout.write("jvPck.__doc__=%s\n"%str(jvPck.__doc__))
	#sys.stdout.write("jvPck.__dict__=%s\n"%str(jvPck.__dict__))
	#sys.stdout.write("jvPck=%s\n"%str(dir(jvPck)))
	#sys.stdout.write("jvPck=%s\n"%str(jvPck()))

	java.lang.System.out.println("Hello World!!")

	#jvPck = JPackage('com').sun.tools.attach.VirtualMachine


	#jvObj = jvPck.VirtualMachine()
	#sys.stdout.write("jvObj=%s\n"%str(jvObj))

	sys.stdout.write("============================\n")

	# http://www.docjar.com/html/api/com/sun/tools/attach/VirtualMachine.java.html
	# The list of virtual machine descriptors.
	vmdListPck = jvPck.list

	# vmdList=<Java package java.com.sun.tools.attach.VirtualMachine.list>
	sys.stdout.write("vmdListPck=%s\n"%str(vmdListPck))

	# vmdList = vmdListPck()
	# and you have to shutdown the VM at the end
	jpype.shutdownJVM()


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

