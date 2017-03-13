import os
import sys
import json
import tempfile
import subprocess

# Thi sis more than stringly inspired from the module pyrasite.


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




def TestShellStdOutWindows(my_pid,vecInstructions):
	pass

# This creates a Python file executing some commands.
# The result must be displayed on the debugger's window.
def TestShellStdOutLinux(my_pid,vecInstructions):
    filnaPair = tempfile.mkstemp(suffix=".py",text=True)
    filna = filnaPair[1]

    # This file will contain the result of the execution.
    outFilNaPair = tempfile.mkstemp(suffix=".dat",text=True)
    outFilFd = outFilNaPair[0]
    # outFilFd.close()
    outFilNa = outFilNaPair[1]

    fi = open(filna,"w")
    fi.write("import sys\n")
    fi.write("tmpout = sys.stdout\n")
    fi.write("tmperr = sys.stderr\n")
    fi.write("filout = open('%s','w')\n" % outFilNa )
    fi.write("sys.stdout = filout\n")
    fi.write("sys.stderr = filout\n")

    for instFi in vecInstructions:
        fi.write("%s\n"% instFi)

    fi.write("sys.stdout = tmpout\n")
    fi.write("sys.stderr = tmperr\n")
    fi.write("filout.close()\n")

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

    filOutDat = open(outFilNa,"r")
    vecResult = filOutDat.readlines();
    filOutDat.close()

    return vecResult


def GetPythonInformations(thePid, vecInstructions):
    vecInstructions.append( 'print(json.dumps(retobj))' )

    if sys.platform.startswith("win"):
        DebuggerPython = TestShellStdOutWindows
    else:
        DebuggerPython = TestShellStdOutLinux

    vecResu = DebuggerPython(thePid,vecInstructions)
    if len(vecResu) != 1:
        sys.stderr.write("Err:%s\n" % str(vecResu) )
        return None

    strResu = vecResu[0]
    objResu = json.loads(strResu)
    return objResu



# for exp in [ "1+1", "traceback.extract_stack()", "globals()" ]:
def GetRemoteStack(thePid):
    # These Python instructions will be executed by a debugger in the context of a Python process.
    # The result is a vector of strings, the output of the execution.
    vecInstructions = [
        'import json',
        'import traceback',
        'retobj = traceback.extract_stack()'
    ]
    objResu = GetPythonInformations(thePid,vecInstructions)
    return objResu



# The parameter must be a PID of a process running a window program.
thePid = int(sys.argv[1])

remSta = GetRemoteStack(thePid)

for st in remSta:
    # == fichier=../essai.py line=6 module=<module>
    # == fichier=<string> line=1 module=<module>
    # == fichier=/tmp/tmpw14tgJ.py line=9 module=<module>
    sys.stdout.write("== fichier=%s line=%d module=%s\n" % ( st[0], st[1], st[2] ) )


#import traceback
#
#def f1(msg):
#    print("extract_stack")
#    print(traceback.extract_stack())
#    print(json.dumps(traceback.extract_stack()))
#    print("")
#
#    print("print_stack")
#    traceback.print_stack()
#    print("")
#    print("MSG="+msg)
#
#def f2(msg):
#    f1(msg)
#
#f2("Hello")

