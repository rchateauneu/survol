
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