from pefile import *
from hooking import *
from pydbg import *
from pydbg.defines import *

import sys

num_args=4

def create_entry(name):
    def hook_entry(dbg,args):
        print "\n>> %s" % name
        for i in range(num_args):
            arg=dbg.get_arg(i)
            print "\targ %i : 0x%x" % (i,arg)
            print "\t\t", dbg.smart_dereference(arg)
        return DBG_CONTINUE
    return hook_entry


def create_return(name):
    def hook_return(dbg,args,retval):
        print "<< %s retval: 0x%x" % (name,dbg.context.Eax)
        return DBG_CONTINUE
    return hook_return


def set_hooks(dbg):
    print "setting hooks"
    hc=hook_container()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for func in entry.imports:
            print 'hook ',func.name," in ",entry.dll
            if entry.dll != 'kernel32.dll':
                hookadd=dbg.func_resolve_debuggee(entry.dll,func.name)
                try:
                    hc.add(dbg,hookadd, 4, create_entry(func.name), create_return(func.name))
                except:
                    print 'failed setting hook for %s' % func.name
                print 'set hook'
    print "done"
    return DBG_CONTINUE


def set_hooks2(dbg):
    print 'setting hooks'
    return DBG_CONTINUE


try:
    prog = sys.argv[1]
    pid = int(sys.argv[2])
except:
    print 'usage: %s [executable] [pid]' % sys.argv[0]
    sys.exit()

pe=PE(prog)
print "pe parsed"
dbg=pydbg()
dbg.attach(pid)
set_hooks(dbg)
dbg.run()