"""
Java world
"""

import os
import sys
import logging

# Module JPype1
import jpype
from jpype import java
from jpype import javax

import lib_util
import lib_common


glob_java_jvm = None


# It is possible to return a similar object, but on a remote machine.
def JPypeLocalStartJVM():
    global glob_java_jvm
    if glob_java_jvm:
        return glob_java_jvm

    try:
        if lib_util.isPlatformLinux:
            glob_java_jvm = _jpype_local_start_jvm_linux()

        elif lib_util.isPlatformWindows:
            glob_java_jvm = _jpype_local_start_jvm_windows()
        else:
            lib_common.ErrorMessageHtml("Unknown operating system")

    except Exception as exc:
        lib_common.ErrorMessageHtml("JavaJmxSystemProperties caught:" + str(exc))

    return glob_java_jvm


def _jpype_local_start_jvm_linux():
    # Example: '/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib/amd64/server/libjvm.so'
    dflt_path = jpype.getDefaultJVMPath()

    # getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
    logging.debug("dflt_path=%s", dflt_path)

    # Now extracts the version, which will be used for the JDK directionary.
    base_dflt_jvm = os.path.dirname(dflt_path)
    base_jre_relative = os.path.join( base_dflt_jvm, "..", "..")

    base_jre_abs = os.path.abspath(base_jre_relative)
    # base_jre_abs=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/jre/lib
    logging.debug("base_jre_abs=%s", base_jre_abs)

    java_dir_prefix = os.path.join(base_jre_abs, "../..")

    # We need to open tools.jar which is in /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-2.b14.fc22.x86_64/lib/tools.jar
    # jpype.startJVM(dflt_path,"-Djava.class.path=/usr/lib ... /tools.jar")
    jpype.startJVM(dflt_path, "-Djava.class.path=" + java_dir_prefix + "/lib/tools.jar")

    #jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
    virtual_machine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

    return virtual_machine


def _jpype_local_start_jvm_windows():
    # u'C:\\Program Files\\Java\\jre1.8.0_121\\bin\\server\\jvm.dll'
    dflt_path = jpype.getDefaultJVMPath()

    # getDefaultJVMPath=C:\Program Files\Java\jre1.8.0_121\bin\server\jvm.dll
    logging.debug("getDefaultJVMPath=%s", dflt_path)

    # Now extracts the version, which will be used for the JDK directionary.
    base_dflt_jvm = os.path.dirname(dflt_path)
    base_jre_relative = os.path.join(base_dflt_jvm, "..", "..")

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
    path_attach_dll = java_dir_prefix + "\\jre\\bin"

    path_original = os.environ["PATH"]

    os.environ["PATH"] = os_path + ";" + path_attach_dll

    # We need to open tools.jar which is in C:\Program Files\Java\jdk1.8.0_121\lib
    # jpype.startJVM(dflt_path,attachPath,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
    # jpype.startJVM(dflt_path,"-Djava.class.path=C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar")
    jpype.startJVM(dflt_path, "-Djava.class.path=" + java_dir_prefix + "\\lib\\tools.jar")

    #jvPck = jpype.JPackage('sun').tools.attach.WindowsVirtualMachine
    virtual_machine = jpype.JPackage('com').sun.tools.attach.VirtualMachine

    os.environ["PATH"] = path_original

    return virtual_machine


def _java_jmx_pid_mbeans_attach(pid, jv_pck_vm, mbean_obj_nam=None):
    """
    Attaching to a process is riskier, so we do not do it when listing all Java processes.
    This procedure needs to attache and might fail sometimes.
    """
    CONNECTOR_ADDRESS = "com.sun.management.jmxremote.localConnectorAddress"

    dict_result = {}

    logging.debug("Attaching to pid=%s type=%s", pid, type(pid))
    # jpype._jexception.AttachNotSupportedExceptionPyRaisable:
    # com.sun.tools.attach.AttachNotSupportedException:
    # Unable to attach to 32-bit process running under WOW64
    #
    # This exception is caught with pytest and many tests.
    # It works fine with few tests or with PyCharm.
    try:
        virt_mach = jv_pck_vm.attach(str(pid))
    except Exception as exc:
        logging.warning("Exception:%s", str(exc))
        return dict_result

    logging.debug("Attached to pid=%s", pid)
    connector_address = virt_mach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

    if not connector_address:
        # fileSeparator = "\\"
        # agent=C:\Program Files\Java\jre1.8.0_121\lib\management-agent.jar
        # agent = virt_mach.getSystemProperties().getProperty("java.home") + fileSeparator + "lib" + fileSeparator + "management-agent.jar"

        agent = os.path.join(virt_mach.getSystemProperties().getProperty("java.home"), "lib", "management-agent.jar")

        logging.debug("agent=%s", str(agent))
        virt_mach.loadAgent(agent)
        # agent is started, get the connector address
        connector_address = virt_mach.getAgentProperties().getProperty(CONNECTOR_ADDRESS)

    dict_result["connector"] = connector_address

    # "service:jmx:rmi://127.0.0.1/stub/rO0ABXN9AAAAAQ..."

    jmx_url = javax.management.remote.JMXServiceURL(connector_address)
    jmx_soc = javax.management.remote.JMXConnectorFactory.connect(jmx_url)
    # This interface represents a way to talk to an MBean server, whether local or remote.
    # The MBeanServer interface, representing a local MBean server, extends this interface.
    connect_m_bean = jmx_soc.getMBeanServerConnection()

    # connect_m_bean=['addNotificationListener', 'class', 'createMBean', 'defaultDomain',
    #  'delegationSubject', 'domains', 'equals', 'getAttribute', 'getAttributes', 'getClass',
    #  'getDefaultDomain', 'getDomains', 'getMBeanCount', 'getMBeanInfo', 'getObjectInstance',
    #  'hashCode', 'invoke', 'isInstanceOf', 'isRegistered', 'mBeanCount', 'notify', 'notifyAll',
    #  'queryMBeans', 'queryNames', 'removeNotificationListener', 'setAttribute', 'setAttributes',
    #  'this$0', 'toString', 'unregisterMBean', 'wait']

    # mbeanObjNam = "com.sun.management:type=HotSpotDiagnostic"
    if mbean_obj_nam:
        logging.debug("mbeanObjNam=%s", mbean_obj_nam)
        jvx_obj_nam = javax.management.ObjectName(mbean_obj_nam)
    else:
        jvx_obj_nam = None

    # jpype._jexception.MalformedObjectNameExceptionPyRaisable: javax.management.MalformedObjectNameException: Key properties cannot be empty
    all_mbeans = connect_m_bean.queryMBeans(jvx_obj_nam, None)

    # all_mbeans=[sun.management.OperatingSystemImpl[java.lang:type=OperatingSystem], sun.management.MemoryManagerImpl[java.
    logging.debug("all_mbeans=%s", str(all_mbeans))

    vect_mbeans = []

    # Gets as much information as possible about this MBean.
    for elt_mbean in all_mbeans:
        mbean_object_name = elt_mbean.getObjectName()
        one_mbean = {
            "className": elt_mbean.getClassName(),
            "objectName": str(mbean_object_name)
        }

        # TODO: To save time, we could do that only if mbeanObjNam is not None.
        one_mbean_info = connect_m_bean.getMBeanInfo(mbean_object_name)

        descr_mbean_info = one_mbean_info.getDescriptor()
        dict_mbean_info_descr = {}
        for key_mbean_info in descr_mbean_info.getFieldNames():
            val_m_bean_info = descr_mbean_info.getFieldValue(key_mbean_info)
            dict_mbean_info_descr[key_mbean_info] = val_m_bean_info
        one_mbean["info"] = dict_mbean_info_descr

        for attr in one_mbean_info.getAttributes():
            logging.debug("attr=%s", str(attr))
            logging.debug("attr.getName()=%s", attr.getName())
            logging.debug("attr.getType()=%s", attr.getType())
            logging.debug("attr.getDescription()=%s", attr.getDescription())

        attrs_mbean_info = one_mbean_info.getAttributes()
        dict_mbean_info = {}
        for one_attr in attrs_mbean_info:
            key_attr = one_attr.getName()
            # int=<class'jpype._jclass.java.lang.Integer'>\
            get_tp = one_attr.getType()
            try:
                get_attr = connect_m_bean.getAttribute(mbean_object_name, key_attr)
                # Without a concatenation, it prints "1" instead of boolean True.
                val_attr = str(get_attr) + " (%s)" % get_tp
            except:
                val_attr = "N/A"
            dict_mbean_info[key_attr] = val_attr
        one_mbean["attrs"] = dict_mbean_info

        vect_mbeans.append(one_mbean)

    dict_result["all_mbeans"] = vect_mbeans

    # When detaching, all the intermediary objects created by connect_m_bean are deleted.
    # This is why their content must be stored.
    virt_mach.detach()

    return dict_result

# https://www.jtips.info/index.php?title=JMX/Remote


def JavaJmxSystemProperties(pid):
    jv_pck_vm = JPypeLocalStartJVM()

    try:
        virt_mach = jv_pck_vm.attach(str(pid))
    except Exception as exc:
        vm_sys_props = {
            "jv_pck_vm": str(jv_pck_vm),
            "JMX error": str(exc),
            "Pid": str(pid)}
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
            "Pid": str(pid)}

    # Shutdown the VM at the end
    _quiet_shutdown()
    return vm_sys_props


def JPypeListVMs(jv_pck_vm):
    """
    This returns a list of processes without attaching to them,
    so it is simpler and faster.
    The result is a map indexed by pids.
    """
    resu_procs = dict()
    if not jv_pck_vm:
        return resu_procs

    list_vms = jv_pck_vm.list()

    logging.debug("VirtualMachine.dir=%s", str(dir(list_vms)))
    for one_vm in list_vms:
        dic_by_props = dict()
        logging.debug("%s", one_vm)
        logging.debug("%s", str(dir(one_vm)))
        logging.debug("id=%s", str(one_vm.id()))
        logging.debug("displayName=%s", str(one_vm.displayName()))
        logging.debug("getClass=%s", str(one_vm.getClass()))
        logging.debug("provider=%s", str(one_vm.provider()))
        logging.debug("isAttachable=%s", str(one_vm.isAttachable()))
        logging.debug("toString=%s", str(one_vm.toString()))
        # JavaJmxPidMBeansAttach(one_vm.id(),jvPckVM)

        dic_by_props["class"] = one_vm.getClass()
        dic_by_props["provider"] = one_vm.provider()
        dic_by_props["isAttachable"] = one_vm.isAttachable()

        # sun.tools.attach.WindowsAttachProvider@3f99bd52: 8084 sun.tools.jconsole.JConsole
        dic_by_props["toString"] = one_vm.toString()

        # Same as "toString"
        # dic_by_props["str"] = str(one_vm)

        resu_procs[one_vm.id()] = dic_by_props

    return resu_procs


# This fails on Linux.
# Better not stopping it because there might be several calls.
# On Windows, better reusing the same JVM.
def _quiet_shutdown():
    return
    # Must redirect the Java output
    # Shutdown the VM at the end
    if not lib_util.isPlatformLinux:
        jpype.shutdownJVM()


# TODO: This could work on a remote machine if we have the Java RMI port number and user/pass.
def ListJavaProcesses():
    jv_pck_vm = JPypeLocalStartJVM()

    list_vms = JPypeListVMs(jv_pck_vm)

    # Shutdown the VM at the end
    _quiet_shutdown()

    return list_vms


# TODO: This could work on a remote machine if we have the Java RMI port number and user/pass.
# If mbeanObjNam is None, returns data for all MBeans.
def GetJavaDataFromJmx(the_pid, mbean_obj_nam=None):
    jv_pck_vm = JPypeLocalStartJVM()

    java_results = _java_jmx_pid_mbeans_attach(the_pid, jv_pck_vm, mbean_obj_nam)

    # Some extra data to add ??
    # jvValDict = jv_pck_vm[thePid]
    # for jvKey in jv_pck_vm:

    # Shutdown the VM at the end
    _quiet_shutdown()

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
