import os
import sys
import subprocess

# cdb -p pid
# https://blogs.msdn.microsoft.com/oldnewthing/20070427-00/?p=27083
# .call
# .detach
# 0:001> x python27!PyGI*
# 00000000`1e136060 python27!PyGILState_GetThisThreadState (<no parameter info>)
# 00000000`1e136080 python27!PyGILState_Release (<no parameter info>)
# 00000000`1e136450 python27!PyGILState_Ensure (<no parameter info>)
# 0:001> .call python27!PyGILState_Ensure()
#                                       ^ Symbol not a function in '.call python27!PyGILState_Ensure()'
#
#:001> x msvcr90!pri*
#...
#00000000`70ca274c MSVCR90!printf (<no parameter info>)
#...
#0:001> .call msvcr90!printf("hh")
#                          ^ Symbol not a function in '.call msvcr90!printf("hh")'



#That error message is the debugger's somewhat confusing way of saying:
#"I don't have enough information available to make that function call."
#But that's okay, because we have a function that's "close enough", namely CAlphaStream::Read:




def TestShellStdOutWindows(my_pid):
	pass

# This creates a Python file executing some commands.
# The result must be displayed on the debugger's window.
def TestShellStdOutLinux(my_pid):
    filna = "toto.py"

    # The file "results.dat" will contain the result of the execution.
    fi = open(filna,"w")
    fi.write("""
import sys
tmpout = sys.stdout
tmperr = sys.stderr
filout = open('results.dat','w')
sys.stdout = filout
sys.stderr = filout
print("i=%d" % i)
print('Hello from file')
sys.stdout = tmpout
sys.stderr = tmperr
filout.close()
    """)
    fi.close()

    gdb_cmds_filout = [
	'PyGILState_Ensure()',
	'PyRun_SimpleString("execfile(\\"%s\\")")' % filna,
	'PyGILState_Release($1)',
	]

    big_args = ' '.join(["-eval-command='call %s'" % cmd for cmd in gdb_cmds_filout])
    sys.stdout.write("big_args=%s\n\n" % big_args)

    cmdline = 'gdb -p %d -batch %s' % (my_pid, big_args )
    sys.stdout.write("cmdline=%s\n\n" % cmdline)
    subprocess.call(cmdline, shell=True)

# The parameter must be a PID of a process running a window program.
thePid = int(sys.argv[1])

if sys.platform.startswith("win"):
	TestShellStdOutWindows(thePid)
else:
	TestShellStdOutLinux(thePid)

