"""
The intention is to port a subset of pydbg:
- It must be in pure Python.
- Python 2 and 3.
- Needed features: attach to a process, log calls to some system api funcitons,
with the arguments.

It would have been possible to fork pydbg but:
- This project is not maintained, not is OpenRCE http://www.openrce.org/ of which it is part.
- Not all features are needed
- Features which are unneeded are quite dangerous and it might be impossible to install
the package because of this reason.

Hence the choice of porting a ubset of pydbg
"""

from __future__ import print_function

import sys
sys.path.append(".")
sys.path.append("pydbg")

import pydbg

from pydbg import pydbg

import os
import time
import multiprocessing
import psutil



#
# API Hooking Abstraction Helper
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

from pydbg.defines import *

########################################################################################################################
class hook_container:
    '''
    The purpose of this class is to provide an easy interface for hooking the entry and return points of arbitrary
    API calls. The hooking of one or both of the points is optional. Example usage:

        def CreateFileA_on_entry (dbg, args):
            pass

        def CreateFileA_on_return (dbg, args, return_value):
            pass

        h = hooks(dbg)
        h.add(dbg.func_resolve("kernel32", "CreateFileA"), 7, CreateFileA_on_entry, CreateFileA_on_exit)

    This class transparently takes care of various thread-related race conditions.
    '''

    hooks = {}

    ####################################################################################################################
    def __init__ (self):
        self.hooks = {}


    ####################################################################################################################
    def add (self, pydbg, address, num_args, entry_hook=None, exit_hook=None):
        '''
        Add a new hook on the specified API which accepts the specified number of arguments. Optionally specify callback
        functions for hooked API entry / exit events. The entry / exit callback prototypes are:

            entry(dbg, args)

        Where entry receives the active PyDbg instance as well as a list of the arguments passed to the hooked routine.

            exit (dbg, args, return_value)

        Where exit received the active PyDbg instance, a list of the arguments passed to the hooked routine and the
        return value from the hooked routine.

        @type  pydbg:      PyDbg Instance
        @param pydbg:      PyDbg Instance
        @type  address:    Long
        @param address:    Address of function to hook
        @type  num_args:   Integer
        @param num_args:   (Optional, Def=0) Number of arguments in function to hook
        @type  entry_hook: Function Pointer
        @param entry_hook: (Optional, Def=None) Function to call on hooked API entry
        @type  exit_hook:  Function Pointer
        @param exit_hook:  (Optional, Def=None) Function to call on hooked API exit

        @rtype:  hooks
        @return: Self
        '''

        # ensure a hook doesn't already exist at the requested address.
        if address in self.hooks.keys():
            return

        # create a new hook instance and activate it.
        h = hook(address, num_args, entry_hook, exit_hook)
        h.hook(pydbg)

        # save the newly created hook into the internal dictionary.
        self.hooks[address] = h

        return self


    ####################################################################################################################
    def remove (self, pydbg, address):
        '''
        De-activate and remove the hook from the specified API address.

        @type  pydbg:   PyDbg Instance
        @param pydbg:   PyDbg Instance
        @type  address: Long
        @param address: Address of function to remove hook from

        @rtype:  hooks
        @return: Self
        '''

        # ensure the address maps to a valid hook point.
        if address not in self.hooks.keys():
            return

        # de-activate the hook.
        self.hooks[address].unhook(pydbg)

        # remove the hook from the internal dictionary.
        del(self.hooks[address])

        return self


    ####################################################################################################################
    def iterate (self, address):
        '''
        A simple iterator function that can be used to iterate through all hooks. Yielded objects are of type hook().

        @rtype:  hook
        @return: Iterated hook entries.
        '''

        for hook in self.hooks.values():
            yield hook


########################################################################################################################
class hook:
    '''
    This helper class abstracts the activation/deactivation of individual hooks. The class is responsible for
    maintaining the various state variables requires to prevent race conditions.
    '''

    hooks      = None
    address    = 0
    num_args   = 0
    entry_hook = None
    exit_hook  = None
    arguments  = {}
    exit_bps   = {}

    ####################################################################################################################
    def __init__ (self, address, num_args, entry_hook=None, exit_hook=None):
        '''
        Initialize the object with the specified parameters.

        @type  address:    Long
        @param address:    Address of function to hook
        @type  num_args:   Integer
        @param num_args:   (Optional, Def=0) Number of arguments in function to hook
        @type  entry_hook: Function Pointer
        @param entry_hook: (Optional, def=None) Function to call on hooked API entry
        @type  exit_hook:  Function Pointer
        @param exit_hook:  (Optional, def=None) Function to call on hooked API exit
        '''

        self.address    = address
        self.num_args   = num_args
        self.entry_hook = entry_hook
        self.exit_hook  = exit_hook
        self.arguments  = {}
        self.exit_bps   = {}


    ####################################################################################################################
    def hook (self, pydbg):
        '''
        Activate the hook by setting a breakpoint on the previously specified address. Breakpoint callbacks are proxied
        through an internal routine that determines and passes further needed information such as function arguments
        and return value.

        @type  pydbg: PyDbg Instance
        @param pydbg: PyDbg Instance
        '''

        pydbg.bp_set(self.address, restore=True, handler=self.__proxy_on_entry)


    ####################################################################################################################
    def unhook (self, pydbg):
        '''
        De-activate the hook by by removing the breakpoint on the previously specified address.

        @type  pydbg: PyDbg Instance
        @param pydbg: PyDbg Instance
        '''

        pydbg.bp_del(self.address)

        # ensure no breakpoints exist on any registered return addresses.
        for address in self.exit_bps.keys():
            pydbg.bp_del(address)


    ####################################################################################################################
    def __proxy_on_entry (self, pydbg):
        '''
        The breakpoint handler callback is proxied through this routine for the purpose of passing additional needed
        information to the user specified hook_{entry,exit} callback. This routine also allows provides a default
        return value of DBG_CONTINUE in the event that the user specified hook callback does not return a value. This
        allows for further abstraction between hooking and the debugger.

        @type  pydbg: PyDbg
        @param pydbg: Debugger instance

        @rtype:  DWORD
        @return: Debugger continue status
        '''

        continue_status = None

        # retrieve and store the arguments to the hooked function.
        # we categorize arguments by thread id to avoid an entry / exit matching race condition, example:
        #     - thread one enters API, saves arguments
        #     - thread two enters API, overwrites arguments
        #     - thread one exists API and uses arguments from thread two
        tid = pydbg.dbg.dwThreadId
        print("__proxy_on_entry tid=", tid)
        print("__proxy_on_entry self.num_args=", self.num_args)
        self.arguments[tid] = []

        if self.exit_hook:
            function_exit = pydbg.get_arg(0)
            print("dir(function_exit)=", dir(function_exit))


        for i in xrange(1, self.num_args + 1):
            print("BEFORE get_arg", i)
            self.arguments[tid].append(pydbg.get_arg(i))

        # if an entry point callback was specified, call it and grab the return value.
        if self.entry_hook:
            continue_status = self.entry_hook(pydbg, self.arguments[tid])

        # if an exit hook callback was specified, determine the function exit.
        if self.exit_hook:
            function_exit = pydbg.get_arg(0)

            # set a breakpoint on the function exit.
            pydbg.bp_set(function_exit, restore=True, handler=self.__proxy_on_exit)

            # increment the break count for the exit bp.
            # we track the number of breakpoints set on the exit point to avoid a hook exit race condition, ie:
            #     - thread one enters API sets BP on exit point
            #     - thread two enters API sets BP on exit point
            #     - thread one exits API and removes BP from exit point
            #     - thread two misses exit BP
            self.exit_bps[function_exit] = self.exit_bps.get(function_exit, 0) + 1

        # if a return value was not explicitly specified, default to DBG_CONTINUE.
        if continue_status == None:
            continue_status = DBG_CONTINUE

        return continue_status


    ####################################################################################################################
    def __proxy_on_exit (self, pydbg):
        '''
        The breakpoint handler callback is proxied through this routine for the purpose of passing additional needed
        information to the user specified hook_{entry,exit} callback. This routine also allows provides a default
        return value of DBG_CONTINUE in the event that the user specified hook callback does not return a value. This
        allows for further abstraction between hooking and the debugger.

        @type  pydbg:       PyDbg
        @param pydbg:       Debugger instance

        @rtype:  DWORD
        @return: Debugger continue status
        '''

        # if we are in this function, then an exit point callback was specified, call it and grab the return value.
        if pydbg.dbg.dwThreadId not in self.arguments.keys():
            return

        continue_status = self.exit_hook(pydbg, self.arguments[pydbg.dbg.dwThreadId], pydbg.context.Eax)

        # reduce the break count
        self.exit_bps[pydbg.context.Eip] -= 1

        # if the break count is 0, remove the bp from the exit point.
        if self.exit_bps[pydbg.context.Eip] == 0:
            pydbg.bp_del(pydbg.context.Eip)

        # if a return value was not explicitly specified, default to DBG_CONTINUE.
        if continue_status == None:
            continue_status = DBG_CONTINUE

        return continue_status



def processing_function(one_argument):
    while True:
        print('Subprocess hello. Sleeping ', one_argument)
        time.sleep(one_argument)
        print('Subprocess leaving after sleep=', one_argument)


# This is our entry hook callback function
def ssl_sniff( dbg, args ):
    print("ssl_sniff")
    print("ssl_sniff")
    print("ssl_sniff")
    # we reach a NULL byte
    buffer  = ""
    offset  = 0
    while 1:
        byte = dbg.read_process_memory( args[1] + offset, 1 )
        if byte != "\x00":
            buffer  += byte
            offset  += 1
            continue
        else:
            break
    print("buffer: %s" % buffer)
    return DBG_CONTINUE

if __name__ == '__main__':
    the_argument = "Hello"
    sleep_time = 1.0
    created_process = multiprocessing.Process(target=processing_function, args=(sleep_time,))
    created_process.start()
    print("created_process=", created_process.pid)
    time.sleep(1.0)
    tst_pydbg = pydbg()

    psutil_proc = psutil.Process(created_process.pid)
    print("psutil_proc.ppid=", psutil_proc.ppid(), os.getpid())
    print("Attaching")
    tst_pydbg.attach(created_process.pid)

    # Common DLLs in Python
    # "c:/windows/system32/shell32.dll",
    # "c:/windows/system32/ole32.dll",
    # "c:/windows/system32/oleaut32.dll",
    # "c:/windows/system32/gdi32.dll"
    # kernel32.dll
    # user32.dll


    # Resolve the function address (Just before encryption)
    # hook_address = tst_pydbg.func_resolve_debuggee("kernel32.dll", "WriteFile")
    hook_address = tst_pydbg.func_resolve("kernel32.dll", "WriteFile")

    # https://gist.github.com/RobinDavid/9213868

    hooks = hook_container()
    # Add the hook to the container. We aren't interested
    # in using an exit callback, so we set it to None.

    print("hook_address=%08x" % hook_address)
    hooks.add(tst_pydbg, hook_address, 2, ssl_sniff, None)
    print("[*] Function hooked at: 0x%08x" % hook_address)

    tst_pydbg.run()




    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")
