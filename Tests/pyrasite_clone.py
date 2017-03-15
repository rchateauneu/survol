import os
import sys
import subprocess

def TestShellStdOut(my_pid):
    filna = "toto.py"

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

TestShellStdOut(int(sys.argv[1]))


