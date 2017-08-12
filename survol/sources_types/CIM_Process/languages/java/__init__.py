# On l implemente en Java appele par du Python car de toute facon Java est necessaire.
#
# (1) http://stackoverflow.com/questions/376201/debug-a-java-application-without-starting-the-jvm-with-debug-arguments
# http://docs.oracle.com/cd/E19205-01/819-5257/blabw/index.html
#
# Debugging a Program With dbx using the Process ID:
# $ dbx [program_name|program_name{.class | .jar}|-] process_id
#
# (2)http://docs.oracle.com/javase/7/docs/technotes/guides/jvmti/
# Java Virtual Machine Tool Interface (JVM TI) is a native programming interface for use by tools.
# It provides both a way to inspect the state and to control the execution of applications
# running in the Java virtual machine (JVM). JVM TI supports the full breadth of tools that need access to JVM state,
# including but not limited to: profiling, debugging, monitoring, thread analysis, and coverage analysis tools.
#
# JVM TI replaces the Java Virtual Machine Profiler Interface (JVMPI)
# and the Java Virtual Machine Debug Interface (JVMDI).
# http://docs.oracle.com/javase/1.5.0/docs/guide/jpda/jdwp-spec.html
#
# https://en.wikipedia.org/wiki/Java_Platform_Debugger_Architecture
#
# http://stackoverflow.com/questions/5317152/getting-the-parameters-of-a-running-jvm
# JConsole can do it. Also you can use a powerful jvisualVM tool, which also is included in JDK since 1.6.0.8.
#
# On pourrait donc: Lister les process Java.
# Attention a ce qu'il peut y avoir plusieurs jps ? Comment cette liste est-elle creee ?
# Et s'il y a plusieurs JDK ?
# jps peut fonctionner avec une machine remote.
# Mais on est oblige de deviner le numero de port. Comment faire ? Est-ce que nmap pourrait le trouver ?
#
# The jps command will report the local VM identifier, or lvmid, for each instrumented JVM found on the target system.
# The lvmid is typically, but not necessarily, the operating system's process identifier for the JVM process.
# C:\Users\rchateau>jps -lvm
# 7792 sun.tools.jps.Jps -lvm -Dapplication.home=C:\Program Files\Java\jdk1.8.0_121 -Xms8m
# 3832  -Xms128m -Xmx512m -XX:MaxPermSize=250m -XX:ReservedCodeCacheSize=150m -XX:+UseConcMarkSweepGC -XX:SoftRefLRUPolicyMSPerMB=50 -ea -Dsun.io.useCanonCaches=false -Djava.net.preferIPv4Stack=true -Djb.vmOptions=C:\Program Files (x86)\JetBrains\PyCharm Community Edition 4.5.4\bin\pycharm.exe.vmoptions -Xbootclasspath/a:C:\Program Files (x86)\JetBrains\PyCharm Community Edition 4.5.4\lib\boot.jar -Didea.platform.prefix=PyCharmCore -Didea.no.jre.check=true -Didea.paths.selector=PyCharm40
# 8824 sun.tools.jconsole.JConsole -Dapplication.home=C:\Program Files\Java\jdk1.8.0_121 -Xms8m -Djconsole.showOutputViewer
# 9368 sun.tools.jconsole.JConsole --help -Dapplication.home=C:\Program Files\Java\jdk1.8.0_121 -Xms8m -Djconsole.showOutputViewer
#
# 3832 est pycharm.exe
# 7792 est JPS, justement.
# 8824 jconsole.
# 9368 jconsole --help
#
# Il doit donc y avoir quelque partune ressource partagee par tous les processes java.
#
#
# C:\Users\rchateau>jinfo -sysprops 8824
# Attaching to process ID 8824, please wait...
# Debugger attached successfully.
# Server compiler detected.
# JVM version is 25.121-b13
# java.runtime.name = Java(TM) SE Runtime Environment
# java.vm.version = 25.121-b13
# sun.boot.library.path = C:\Program Files\Java\jdk1.8.0_121\jre\bin
# java.vendor.url = http://java.oracle.com/
# java.vm.vendor = Oracle Corporation
# path.separator = ;
# file.encoding.pkg = sun.io
# java.vm.name = Java HotSpot(TM) 64-Bit Server VM
# sun.os.patch.level = Service Pack 1
# sun.java.launcher = SUN_STANDARD
# user.script =
# user.country = GB
# user.dir = C:\Users\rchateau
# java.vm.specification.name = Java Virtual Machine Specification
# java.runtime.version = 1.8.0_121-b13
# java.awt.graphicsenv = sun.awt.Win32GraphicsEnvironment
# os.arch = amd64
# java.endorsed.dirs = C:\Program Files\Java\jdk1.8.0_121\jre\lib\endorsed
# line.separator =
#
# java.io.tmpdir = C:\Users\rchateau\AppData\Local\Temp\
# java.vm.specification.vendor = Oracle Corporation
# user.variant =
# os.name = Windows 7
# application.home = C:\Program Files\Java\jdk1.8.0_121
# sun.jnu.encoding = Cp1252
# java.library.path = C:\Program Files\Java\jdk1.8.0_121\bin;C:\windows\Sun\Java\bin;C:\windows\system32;C:\windows;C:\ProgramData\Ora
# cle\Java\javapath;C:\oraclexe\app\oracle\product\11.2.0\server\bin;C:\Perl64\site\bin;C:\Perl64\bin;C:\Program Files (x86)\OpenSSH\b
# in;C:\Program Files (x86)\Intel\iCLS Client\;C:\Program Files\Intel\iCLS Client\;C:\windows\system32;C:\windows;C:\windows\System32\
# Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\Intel\Intel(R) Management Engine Components\DAL;C:\Program Files (
# x86)\Intel\Intel(R) Management Engine Components\DAL;C:\Program Files\Intel\Intel(R) Management Engine Components\IPT;C:\Program Fil
# es (x86)\Intel\Intel(R) Management Engine Components\IPT;C:\Program Files\TortoiseSVN\bin;C:\Program Files (x86)\Windows Kits\8.1\Wi
# ndows Performance Toolkit\;C:\Program Files\Microsoft SQL Server\110\Tools\Binn\;C:\Program Files (x86)\Microsoft SDKs\TypeScript\1.
# 0\;C:\Program Files\Microsoft SQL Server\120\Tools\Binn\;c:\Program Files (x86)\Microsoft SQL Server\110\Tools\Binn\;c:\Program File
# s (x86)\Microsoft SQL Server\110\DTS\Binn\;C:\Program Extra\SysinternalsSuite;C:\Program Files (x86)\Microsoft SQL Server\110\Tools\
# Binn\ManagementStudio\;C:\Program Files\Microsoft SQL Server\110\DTS\Binn\;C:\Program Files (x86)\The Open Group\WMI Mapper\bin;C:\P
# ython27;C:\Program_Extra\swigwin-3.0.4;C:\Program_Extra\SysinternalsSuite;C:\Program_Extra;C:/Program Files (x86)/OpenSLP;c:\Apache2
# 4\bin;C:\Program Files (x86)\Graphviz2.38\bin;C:\OpenSSL-Win64\bin;C:\Program Files (x86)\Skype\Phone\;C:\Program Files\TortoiseGit\
# bin;C:\Program Files (x86)\Nmap;C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\;C:\Program Files (x86)\Windows K
# its\10\Debuggers\x64;C:\Python27\Scripts;C:\Program_Extra\Depends64;C:\Program Files\doxygen\bin;C:\MinGW\bin;C:\Program Files\Java\
# jdk1.8.0_121\bin;C:\Program Files (x86)\CVSNT\;C:\Program Files (x86)\Nmap;.
# sun.awt.enableExtraMouseButtons = true
# java.specification.name = Java Platform API Specification
# java.class.version = 52.0
# sun.management.compiler = HotSpot 64-Bit Tiered Compilers
# jconsole.showOutputViewer =
# os.version = 6.1
# user.home = C:\Users\rchateau
# user.timezone =
# java.awt.printerjob = sun.awt.windows.WPrinterJob
# file.encoding = Cp1252
# java.specification.version = 1.8
# user.name = rchateau
# java.class.path = C:\Program Files\Java\jdk1.8.0_121/lib/jconsole.jar;C:\Program Files\Java\jdk1.8.0_121/lib/tools.jar;C:\Program Files\Java\jdk1.8.0_121/classes
# java.vm.specification.version = 1.8
# sun.arch.data.model = 64
# sun.java.command = sun.tools.jconsole.JConsole
# java.home = C:\Program Files\Java\jdk1.8.0_121\jre
# user.language = en
# java.specification.vendor = Oracle Corporation
# awt.toolkit = sun.awt.windows.WToolkit
# java.vm.info = mixed mode
# java.version = 1.8.0_121
# java.ext.dirs = C:\Program Files\Java\jdk1.8.0_121\jre\lib\ext;C:\windows\Sun\Java\lib\ext
# sun.boot.class.path = C:\Program Files\Java\jdk1.8.0_121\jre\lib\resources.jar;C:\Program Files\Java\jdk1.8.0_121\jre\lib\rt.jar;C:\
# Program Files\Java\jdk1.8.0_121\jre\lib\sunrsasign.jar;C:\Program Files\Java\jdk1.8.0_121\jre\lib\jsse.jar;C:\Program Files\Java\jdk
# 1.8.0_121\jre\lib\jce.jar;C:\Program Files\Java\jdk1.8.0_121\jre\lib\charsets.jar;C:\Program Files\Java\jdk1.8.0_121\jre\lib\jfr.jar
# ;C:\Program Files\Java\jdk1.8.0_121\jre\classes
# java.vendor = Oracle Corporation
# file.separator = \
# java.vendor.url.bug = http://bugreport.sun.com/bugreport/
# sun.io.unicode.encoding = UnicodeLittle
# sun.cpu.endian = little
# sun.desktop = windows
# sun.cpu.isalist = amd64
#
#
# C:\Users\rchateau>jinfo -flags 8824
# Attaching to process ID 8824, please wait...
# Debugger attached successfully.
# Server compiler detected.
# JVM version is 25.121-b13
# Non-default VM flags: -XX:CICompilerCount=2 -XX:InitialHeapSize=8388608 -XX:MaxHeapSize=1054867456 -XX:MaxNewSize=351272960 -XX:MinHeapDeltaBytes=524288 -XX:NewSize=2621440 -XX:OldSize=5767168 -XX:+UseCompressedClassPointers -XX:+UseCompressedOops -XX:+UseFastUnorderedTimeStamps -XX:-UseLargePagesIndividualAllocation -XX:+UseParallelGC
# Command line:  -Dapplication.home=C:\Program Files\Java\jdk1.8.0_121 -Xms8m -Djconsole.showOutputViewer
#
# Ca plante avec le process pycharm.
# Peut-etre est-ce parce que jinfo et pycharm ne fonctionnent pas avec le meme Java ?
# Toutefois jps liste pycharm ?
#
# C:\Users\rchateau>where java
# C:\ProgramData\Oracle\Java\javapath\java.exe
# C:\Program Files\Java\jdk1.8.0_121\bin\java.exe
#
#
# jconsole donne des statistiques. Peut-etre en ligne de commande ?
# http://stackoverflow.com/questions/12595277/is-there-cli-version-of-jconsole
# jConsole is just a wrapper around MBeans which you can access directly through the API.
# http://docs.oracle.com/javase/tutorial/jmx/mbeans/standard.html
# An MBean is to JBoss or WebSphere what an SNMP MIB is to Tivoli network manager, or WMI is to a Windows.
# Java Management Extensions (JMX) is a Java technology that supplies tools for managing and monitoring applications,
# system objects, devices (such as printers) and service-oriented networks.
# Those resources are represented by objects called MBeans (for Managed Bean).
# In the API, classes can be dynamically loaded and instantiated.
# Managing and monitoring applications can be designed and developed using the Java Dynamic Management Kit.
#
# Avec Jolokia:
# http://blog.swisstech.net/2013/01/simple-generic-python-script-to-access.html
#
# Avec jpype:
# http://blog.nobugware.com/post/2010/11/08/jmx-query-python-cpython/
