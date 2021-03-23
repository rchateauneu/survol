"""
Java world
"""

import os
import sys
import logging
import jpype
import lib_util
import lib_common

# Module JPype1
# For Python2, pip2 install jpype1==0.6.2 , but 1.1.2 does not install.
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

    except Exception as exc:
        lib_common.ErrorMessageHtml("JavaJmxSystemProperties caught:" + str(exc))

    return globJavaJVM


def JPypeLocalStartJVMLinux():
    # Example: '/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib/amd64/server/libjvm.so'
    dflt_path = jpype.getDefaultJVMPath()

    # getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
    logging.debug("getDefaultJVMPath=%s", dflt_path)

    # Now extracts the version, which will be used for the JDK directionary.
    baseDfltJVM = os.path.dirname(dflt_path)
    baseJreRelative = os.path.join( baseDfltJVM, "..", ".." )

    base_jre_abs = os.path.abspath(baseJreRelative)
    # base_jre_abs=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib
    logging.debug("base_jre_abs=%s", base_jre_abs)

    java_dir_prefix = os.path.join(base_jre_abs, "../..")

    # We need to open tools.jar which is in /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/lib/tools.jar
    # jpype.startJVM(dflt_path,"-Djava.class.path=/usr/lib ... /tools.jar")
    jpype.startJVM(dflt_path, "-Djava.class.path=" + java_dir_prefix + "/lib/tools.jar")

    #jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
    virtual_machine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

    return virtual_machine


def JPypeLocalStartJVMWindows():
    # u'C:\\Program Files\\Java\\jre1.8.0_121\\bin\\server\\jvm.dll'
    dflt_path = jpype.getDefaultJVMPath()

    # getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
    logging.debug("getDefaultJVMPath=%s", dflt_path)

    # Now extracts the version, which will be used for the JDK directionary.
    baseDfltJVM = os.path.dirname(dflt_path)
    base_jre_relative = os.path.join(baseDfltJVM, "..", "..")

    base_jre_abs = os.path.abspath(base_jre_relative)
    # base_jre_abs=C:\Program Files\Java\jre1.8.0_121
    logging.debug("base_jre_abs=%s", base_jre_abs)

    dir_jre = os.path.basename(base_jre_abs)
    # dir_jre=jre1.8.0_121
    logging.debug("dir_jre=%s", dir_jre)

    str_jre = dir_jre[:3]
    if str_jre != "jre":
        # Our assumption on the directory syntax is wrong.
        logging.debug("Invalid str_jre=%s", str_jre)
        return None

    base_java = os.path.dirname(base_jre_abs)
    dir_jdk = "jdk" + dir_jre[3:]

    java_dir_prefix = os.path.join(base_java, dir_jdk)
    # java_dir_prefix=C:\Program Files\Java\jdk1.8.0_121
    logging.debug("java_dir_prefix=%s", java_dir_prefix)

    os_path = os.environ["PATH"]

    # java_dir_prefix = "C:\\Program Files\\Java\\jdk1.8.0_121"

    # "attach.dll" is not in the jre.
    #sys.stdout.write("PATH=%s\n"%os_path)
    # path_attach_dll = "C:\\Program Files\\Java\\jdk1.8.0_121\\jre\\bin"
    path_attach_dll = java_dir_prefix + "\\jre\\bin"

    path_original = os.environ["PATH"]

    os.environ["PATH"] = os_path + ";" + path_attach_dll

    # We need to open tools.jar which is in C:\Program Files\Java\jdk1.8.0_121\lib
    # jpype.startJVM(dflt_path,attachPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
    # jpype.startJVM(dflt_path,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
    jpype.startJVM(dflt_path, "-Djava.class.path=" + java_dir_prefix + "\\lib\\tools.jar")

    #jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
    VirtualMachine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

    os.environ["PATH"] = path_original

    return VirtualMachine


# Attaching to a process is riskier, so we do not do it when listing all Java processes.
# This procedure needs to attache and might fail sometimes.
def JavaJmxPidMBeansAttach(pid, jvPckVM, mbean_obj_nam=None):
    CONNECTOR_ADDRESS = "com.sun.management.jmxremote.localConnectorAddress"

    dict_result = {}

    logging.debug("JavaJmxPidMBeansAttach Attaching to pid=%s type=%s", pid, type(pid))
    # jpype._jexception.AttachNotSupportedExceptionPyRaisable:
    # com.sun.tools.attach.AttachNotSupportedException:
    # Unable to attach to 32-bit process running under WOW64
    #
    # This exception is caught with pytest and many tests.
    # It works fine with few tests or with PyCharm.
    try:
        virt_mach = jvPckVM.attach(str(pid))
    except Exception as exc:
        logging.warning("Exception:%s", str(exc))
        return dict_result

    logging.debug("Attached to pid=%s", pid)
    connectorAddress = virt_mach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

    if not connectorAddress:
        # fileSeparator = "\\"
        # agent=C:\Program Files\Java\jre1.8.0_121\lib\management-agent.jar
        # agent = virt_mach.getSystemProperties().getProperty("java.home") + fileSeparator + "lib" + fileSeparator + "management-agent.jar"

        agent = os.path.join(virt_mach.getSystemProperties().getProperty("java.home"), "lib", "management-agent.jar")

        logging.debug("agent=%s", str(agent))
        virt_mach.loadAgent(agent)
        # agent is started, get the connector address
        connectorAddress = virt_mach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

    dict_result["connector"] = connectorAddress

    # "service:jmx:rmi://127.0.0.1/stub/rO0ABXN9AAAAAQ..."

    jmx_url = javax.management.remote.JMXServiceURL(connectorAddress)
    jmx_soc = javax.management.remote.JMXConnectorFactory.connect(jmx_url)
    # This interface represents a way to talk to an MBean server, whether local or remote.
    # The MBeanServer interface, representing a local MBean server, extends this interface.
    connectMBean = jmx_soc.getMBeanServerConnection()

    # connectMBean=['addNotificationListener', 'class', 'createMBean', 'defaultDomain',
    #  'delegationSubject', 'domains', 'equals', 'getAttribute', 'getAttributes', 'getClass',
    #  'getDefaultDomain', 'getDomains', 'getMBeanCount', 'getMBeanInfo', 'getObjectInstance',
    #  'hashCode', 'invoke', 'isInstanceOf', 'isRegistered', 'mBeanCount', 'notify', 'notifyAll',
    #  'queryMBeans', 'queryNames', 'removeNotificationListener', 'setAttribute', 'setAttributes',
    #  'this$0', 'toString', 'unregisterMBean', 'wait']

    # mbeanObjNam = "com.sun.management:type=HotSpotDiagnostic"
    if mbean_obj_nam:
        logging.debug("mbeanObjNam=%s", mbean_obj_nam)
        jvxObjNam = javax.management.ObjectName(mbean_obj_nam)
    else:
        jvxObjNam = None

    # jpype._jexception.MalformedObjectNameExceptionPyRaisable: javax.management.MalformedObjectNameException: Key properties cannot be empty
    allMBeans = connectMBean.queryMBeans(jvxObjNam, None)

    # allMBeans=[sun.management.OperatingSystemImpl[java.lang:type=OperatingSystem], sun.management.MemoryManagerImpl[java.
    logging.debug("allMBeans=%s", str(allMBeans))

    vectMBeans = []

    # Gets as much information as possible about this MBean.
    for eltMBean in allMBeans:
        mbeanObjectName = eltMBean.getObjectName()
        oneMBean = {
            "className": eltMBean.getClassName(),
            "objectName": str(mbeanObjectName)
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
            logging.debug("attr=%s", str(attr))
            logging.debug("attr.getName()=%s", attr.getName())
            logging.debug("attr.getType()=%s", attr.getType())
            logging.debug("attr.getDescription()=%s", attr.getDescription())

        attrsMBeanInfo = oneMBeanInfo.getAttributes()
        dictMBeanInfo = {}
        for one_attr in attrsMBeanInfo:
            key_attr = one_attr.getName()
            # int=<class'jpype._jclass.java.lang.Integer'>\
            get_tp = one_attr.getType()
            try:
                get_attr = connectMBean.getAttribute(mbeanObjectName, key_attr)
                # Without a concatenation, it prints "1" instead of boolean True.
                val_attr = str(get_attr) + " (%s)" % get_tp
            except:
                val_attr = "N/A"
            dictMBeanInfo[key_attr] = val_attr
        oneMBean["attrs"] = dictMBeanInfo

        vectMBeans.append(oneMBean)

    dict_result["allMBeans"] = vectMBeans

    # When detaching, all the intermediary objects created by connectMBean are deleted.
    # This is why their content must be stored.
    virt_mach.detach()

    return dict_result

# https://www.jtips.info/index.php?title=JMX/Remote


def JavaJmxSystemProperties(pid):
    jvPckVM = JPypeLocalStartJVM()

    try:
        virt_mach = jvPckVM.attach(str(pid))
    except Exception as exc:
        vm_sys_props = {
            "jvPckVM": str(jvPckVM),
            "JMX error": str(exc),
            "Pid": str(pid) }
        return vm_sys_props

    try:
        gsp = virt_mach.getSystemProperties()
        vm_sys_props = {}

        for k in gsp:
            v = gsp[k]
            vm_sys_props[k] = v

        # TODO: Frequent error:
        #
        # (<type 'exceptions.RuntimeError'>,
        # RuntimeError('No matching overloads found.
        # at native\common\jp_method.cpp:117',),
        # <traceback object at
        # 0x0000000004ADAC48>\

        virt_mach.detach()
    except Exception as exc:
        vm_sys_props = {
            "VM": str(virt_mach),
            "JMX error": str(exc),
            "Pid": str(pid) }

    # Shutdown the VM at the end
    QuietShutdown()
    return vm_sys_props


# This returns a list of processes without attaching to them,
# so it is simpler and faster.
# The result is a map indexed by pids.
def JPypeListVMs(jvPckVM):
    resu_procs = dict()
    if not jvPckVM:
        return resu_procs

    listVMs = jvPckVM.list()

    logging.debug("VirtualMachine.dir=%s", str(dir(listVMs)))
    for oneVM in listVMs:
        dic_by_props = dict()
        logging.debug("%s", oneVM)
        logging.debug("%s", str(dir(oneVM)))
        logging.debug("id=%s", str(oneVM.id()))
        logging.debug("displayName=%s", str(oneVM.displayName()))
        logging.debug("getClass=%s", str(oneVM.getClass()))
        logging.debug("provider=%s", str(oneVM.provider()))
        logging.debug("isAttachable=%s", str(oneVM.isAttachable()))
        logging.debug("toString=%s", str(oneVM.toString()))
        # JavaJmxPidMBeansAttach(oneVM.id(),jvPckVM)

        dic_by_props["class"] = oneVM.getClass()
        dic_by_props["provider"] = oneVM.provider()
        dic_by_props["isAttachable"] = oneVM.isAttachable()

        # sun.tools.attach.WindowsAttachProvider@3f99bd52: 8084 sun.tools.jconsole.JConsole
        dic_by_props["toString"] = oneVM.toString()

        # Same as "toString"
        # dic_by_props["str"] = str(oneVM)

        resu_procs[oneVM.id()] = dic_by_props

    return resu_procs


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
def GetJavaDataFromJmx(the_pid, mbean_obj_nam=None):
    jvPckVM = JPypeLocalStartJVM()

    java_results = JavaJmxPidMBeansAttach(the_pid, jvPckVM, mbean_obj_nam)

    # Some extra data to add ??
    # jvValDict = jvPckVM[thePid]
    # for jvKey in jvPckVM:

    # Shutdown the VM at the end
    QuietShutdown()

    return java_results


# Development notes:
#
# https://stackoverflow.com/questions/10331189/how-to-find-the-default-jmx-port-number
# C:\Users\xxyyzz>jvisualvm
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
