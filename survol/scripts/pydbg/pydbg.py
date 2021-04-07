#!c:\python\python.exe

#
# PyDBG
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: pydbg.py 253 2011-01-24 19:13:57Z my.name.is.sober $
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

from __future__ import print_function

import os.path
import sys
import six
import copy
import signal
import struct
import logging
try:
    import pydasm
except ImportError:
    pass
import socket
import ctypes
from ctypes import wintypes
import win32process
import collections

from .windows_h  import *

# macos compatability.
try:
    kernel32 = windll.kernel32
    advapi32 = windll.advapi32
    ntdll    = windll.ntdll
    iphlpapi = windll.iphlpapi
except:
    kernel32 = CDLL(os.path.join(os.path.dirname(__file__), "libmacdll.dylib"))
    advapi32 = kernel32

from .breakpoint              import *
from .hardware_breakpoint     import *
from .memory_breakpoint       import *
from .memory_snapshot_block   import *
from .memory_snapshot_context import *
from .pdx                     import *
from .system_dll              import *

if sys.version_info < (3,):
    big_integer_type = long
else:
    big_integer_type = int

def process_is_wow64(pid=None):
    if pid:
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    else:
        process_handle = GetCurrentProcess()

    temp_is_wow64 = wintypes.BOOL()
    a_bool = IsWow64Process(process_handle, byref(temp_is_wow64))

    return True if temp_is_wow64 else False


def wait_for_process_exit(process_id):
    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)

    result = kernel32.WaitForSingleObject(process_handle, 1000)
    if result == 0: # WAIT_OBJECT_0:
        pass # print("wait_for_process_exit ok stopped pid=", process_id)
    elif result == 258: # WAIT_TIMEOUT:
        pass # print("wait_for_process_exit timeout stopping pid=", process_id, "err=", result)
        result_terminate = kernel32.TerminateProcess(process_handle, 12345)
        pass # self._log("wait_for_process_exit terminate pid%d= result_terminate=%s" % (process_id, result_terminate))
        # raise pdx("Cannot terminate %d" % process_id, True)
    else:
        # self._log("wait_for_process_exit cannot stop pid=%d result=%d" % (process_id, result))
        pass

# This data structure relates to the memory specae of a process.
class memory_space:
    def __init__(self):
        self.breakpoints = {}  # internal breakpoint dictionary, keyed by address
        # TODO: Add memory_breakpoints, hardware_breakpoints, memory_snapshot_blocks, memory_snapshot_contexts

class pydbg(object):
    '''
    This class implements standard low leven functionality including:
        - The load() / attach() routines.
        - The main debug event loop.
        - Convenience wrappers for commonly used Windows API.
        - Single step toggling routine.
        - Win32 error handler wrapped around PDX.
        - Base exception / event handler routines which are meant to be overridden.

    Higher level functionality is also implemented including:
        - Register manipulation.
        - Soft (INT 3) breakpoints.
        - Memory breakpoints (page permissions).
        - Hardware breakpoints.
        - Exception / event handling call backs.
        - Pydasm (libdasm) disassembly wrapper.
        - Process memory snapshotting and restoring.
        - Endian manipulation routines.
        - Debugger hiding.
        - Function resolution.
        - "Intelligent" memory derefencing.
        - Stack/SEH unwinding.
        - Etc...
    '''

    STRING_EXPLORATON_BUF_SIZE    = 256
    STRING_EXPLORATION_MIN_LENGTH = 2

    ####################################################################################################################

    def __init__ (self, ff=True, cs=False):
        '''
        Set the default attributes. See the source if you want to modify the default creation values.

        @type  ff: Boolean
        @param ff: (Optional, Def=True) Flag controlling whether or not pydbg attaches to forked processes
        @type  cs: Boolean
        @param cs: (Optional, Def=False) Flag controlling whether or not pydbg is in client/server (socket) mode
        '''

        # private variables, internal use only:
        self._restore_breakpoint      = None      # breakpoint to restore
        self._guarded_pages           = set()     # specific pages we set PAGE_GUARD on
        self._guards_active           = True      # flag specifying whether or not guard pages are active

        self.page_size                = 0         # memory page size (dynamically resolved at run-time)
        self.pid                      = 0         # debuggee's process id
        self.root_pid                 = 0         # debuggee's root process id
        self.h_process                = None      # debuggee's process handle
        self.h_thread                 = None      # handle to current debuggee thread
        self.debugger_active          = True      # flag controlling the main debugger event handling loop
        self.follow_forks             = ff        # flag controlling whether or not pydbg attaches to forked processes
        self.client_server            = cs        # flag controlling whether or not pydbg is in client/server mode
        self.callbacks                = {}        # exception callback handler dictionary
        self.system_dlls              = []        # list of loaded system dlls
        self.dirty                    = False     # flag specifying that the memory space of the debuggee was modified
        self.system_break             = None      # the address at which initial and forced breakpoints occur at
        self.peb                      = None      # process environment block address
        self.tebs                     = {}        # dictionary of thread IDs to thread environment block addresses

        # internal variables specific to the last triggered exception.
        self.context                  = None      # thread context of offending thread
        self.dbg                      = None      # DEBUG_EVENT
        self.exception_address        = None      # from dbg.u.Exception.ExceptionRecord.ExceptionAddress
        self.write_violation          = None      # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        self.violation_address        = None      # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
        self.exception_code           = None      # from dbg.u.Exception.ExceptionRecord.ExceptionCode

        self.memory_by_pid = collections.defaultdict(memory_space)
        #self.breakpoints              = {}        # internal breakpoint dictionary, keyed by address
        # TODO: This is relative to a process memory space and should go in memory_space with breakpoints.
        self.memory_breakpoints       = {}        # internal memory breakpoint dictionary, keyed by base address
        self.hardware_breakpoints     = {}        # internal hardware breakpoint array, indexed by slot (0-3 inclusive)
        self.memory_snapshot_blocks   = []        # list of memory blocks at time of memory snapshot
        self.memory_snapshot_contexts = []        # list of threads contexts at time of memory snapshot

        self.first_breakpoint         = True      # this flag gets disabled once the windows initial break is handled
        self.memory_breakpoint_hit    = 0         # address of hit memory breakpoint or zero on miss
                                                  # designates whether or not the violation was in reaction to a memory
                                                  # breakpoint hit or other unrelated event.
        self.hardware_breakpoint_hit  = None      # hardware breakpoint on hit or None on miss
                                                  # designates whether or not the single step event was in reaction to
                                                  # a hardware breakpoint hit or other unrelated event.

        self.instruction              = None      # pydasm instruction object, propagated by self.disasm()
        self.mnemonic                 = None      # pydasm decoded instruction mnemonic, propagated by self.disasm()
        self.op1                      = None      # pydasm decoded 1st operand, propagated by self.disasm()
        self.op2                      = None      # pydasm decoded 2nd operand, propagated by self.disasm()
        self.op3                      = None      # pydasm decoded 3rd operand, propagated by self.disasm()

        # control debug/error logging.
        # self._log = lambda msg: None #sys.stderr.write("PDBG_LOG> " + msg + "\n")
        self._log = lambda msg: sys.stdout.write("PDBG_LOG> " + msg + "\n")
        self._err = lambda msg: sys.stdout.write("PDBG_ERR> " + msg + "\n")

        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        self.system_break = None

        self.debug_counter_WaitForDebugEvent = 0
        self.debug_counter_exception_breakpoint = 0
        self.debug_counter_not_ours_breakpoints = 0
        self.debug_counter_deleted_breakpoints = 0
        self.debug_counter_handled_breakpoints = 0

    def set_system_break(self):
        if self.system_break:
            return
        # determine the system DbgBreakPoint address. this is the address at which initial and forced breaks happen.
        # XXX - need to look into fixing this for pydbg client/server.
        try:
            # On Travis, this does not work.
            self.system_break = self.func_resolve(b"ntdll.dll", b"DbgBreakPoint")
        except Exception as exc:
            self.system_break = None
            self._err("Cannot get DbgBreakPoint address. Exc=%s. Continue" % exc)
            modules_list = [one_module[0] for one_module in self.enumerate_modules()]
            self._err("modules_list=%s." % str(modules_list))
            #raise



    ####################################################################################################################
    def addr_to_dll (self, address):
        '''
        Return the system DLL that contains the address specified.

        @type  address: DWORD
        @param address: Address to search system DLL ranges for

        @rtype:  system_dll
        @return: System DLL that contains the address specified or None if not found.
        '''

        for dll in self.system_dlls:
            if dll.base < address < dll.base + dll.size:
                return dll

        return None


    ####################################################################################################################
    def addr_to_module (self, address):
        '''
        Return the MODULEENTRY32 structure for the module that contains the address specified.

        @type  address: DWORD
        @param address: Address to search loaded module ranges for

        @rtype:  MODULEENTRY32
        @return: MODULEENTRY32 strucutre that contains the address specified or None if not found.
        '''

        found = None

        logging.debug("address=%s" % str(address))
        for module in self.iterate_modules():
            if module.modBaseAddr < address < module.modBaseAddr + module.modBaseSize:
                # we have to make a copy of the 'module' since it is an iterator and will be blown away.
                # the reason we can't "break" out of the loop is because there will be a handle leak.
                # and we can't use enumerate_modules() because we need the entire module structure.
                # so there...
                found = copy.copy(module)

        logging.debug("found=%s" % str(found))
        return found


    ####################################################################################################################
    def attach (self, pid):
        '''
        Attach to the specified process by PID. Saves a process handle in self.h_process and prevents debuggee from
        exiting on debugger quit.

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("attaching to pid %d" % pid)

        # obtain necessary debug privileges.
        self.get_debug_privileges()

        self.pid = pid
        self.root_pid = pid
        self.open_process(pid)
        self._log("attach After open_process current_pid=%d pid=%d" % (os.getpid(), pid))
        self.pids_to_handle = {self.pid: self.h_process}

        self.debug_active_process(pid)
        self._log("attach After debug_active_process pid=%d" % pid)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        if not is_64bits:
            self.attach32_end()

        return self.ret_self()

    def attach32_end(self):
        for thread_id in self.enumerate_threads():
            thread_handle  = self.open_thread(thread_id)
            thread_context = self.get_thread_context(thread_handle)
            selector_entry = LDT_ENTRY()

            assert not is_64bits
            self._log("attach thread_id=%s thread_context.SegFs=%s" % (str(thread_id), str(thread_context.SegFs)))
            if not kernel32.GetThreadSelectorEntry(thread_handle, thread_context.SegFs, byref(selector_entry)):
                self._log("attach DISABLE ERROR Error GetThreadSelectorEntry")
                continue
                self.win32_error("GetThreadSelectorEntry()")

            self.close_handle(thread_handle)

            teb  = selector_entry.BaseLow
            teb += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

            # add this TEB to the internal dictionary.
            self.tebs[thread_id] = teb

            # if the PEB has not been set yet, do so now.
            if not self.peb:
                self.peb = self.read_process_memory(teb + 0x30, 4)
                self.peb = struct.unpack("<L", self.peb)[0]


    ####################################################################################################################
    def bp_del (self, address):
        '''
        Removes the breakpoint from target address.

        @see: bp_set(), bp_del_all(), bp_is_ours()

        @type  address: DWORD or List
        @param address: Address or list of addresses to remove breakpoint from

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # if a list of addresses to remove breakpoints from was supplied.
        if type(address) is list:
            # pass each lone address to ourself.
            for addr in address:
                self.bp_del(addr)

            return self.ret_self()

        #self._log("bp_del(0x%016x)" % address)

        # ensure a breakpoint exists at the target address.
        if address in self.memory_by_pid[self.pid].breakpoints:
            # restore the original byte.
            self.write_process_memory(address, self.memory_by_pid[self.pid].breakpoints[address].original_byte)
            self.set_attr("dirty", True)

            # remove the breakpoint from the internal list.
            del self.memory_by_pid[self.pid].breakpoints[address]

        return self.ret_self()


    ####################################################################################################################
    def bp_del_all (self):
        '''
        Removes all breakpoints from the debuggee.

        @see: bp_set(), bp_del(), bp_is_ours()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        #self._log("bp_del_all()")

        for bp in self.memory_by_pid[self.pid].breakpoints.keys():
            self.bp_del(bp)

        return self.ret_self()


    ####################################################################################################################
    def bp_del_hw (self, address=None, slot=None):
        '''
        Removes the hardware breakpoint from the specified address or slot. Either an address or a slot must be
        specified, but not both.

        @see:  bp_set_hw(), bp_del_hw_all()

        @type  address:   DWORD
        @param address:   (Optional) Address to remove hardware breakpoint from.
        @type  slot:      Integer (0 through 3)
        @param slot:      (Optional)

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        if address == slot == None:
            raise pdx("hw bp address or slot # must be specified.")

        if not address and slot not in range(4):
            raise pdx("invalid hw bp slot: %d. valid range is 0 through 3" % slot)

        # de-activate the hardware breakpoint for all active threads.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            if address:
                if   context.Dr0 == address: slot = 0
                elif context.Dr1 == address: slot = 1
                elif context.Dr2 == address: slot = 2
                elif context.Dr3 == address: slot = 3

            # mark slot as inactive.
            # bits 0, 2, 4, 6 for local  (L0 - L3)
            # bits 1, 3, 5, 7 for global (L0 - L3)

            context.Dr7 &= ~(1 << (slot * 2))

            # remove address from the specified slot.
            if   slot == 0: context.Dr0 = 0x00000000
            elif slot == 1: context.Dr1 = 0x00000000
            elif slot == 2: context.Dr2 = 0x00000000
            elif slot == 3: context.Dr3 = 0x00000000

            # remove the condition (RW0 - RW3) field from the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            # remove the length (LEN0-LEN3) field from the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            # set the thread context.
            self.set_thread_context(context, thread_id=thread_id)

        # remove the breakpoint from the internal list.
        del self.hardware_breakpoints[slot]

        return self.ret_self()


    ####################################################################################################################
    def bp_del_hw_all (self):
        '''
        Removes all hardware breakpoints from the debuggee.

        @see: bp_set_hw(), bp_del_hw()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        if 0 in self.hardware_breakpoints: self.bp_del_hw(slot=0)
        if 1 in self.hardware_breakpoints: self.bp_del_hw(slot=1)
        if 2 in self.hardware_breakpoints: self.bp_del_hw(slot=2)
        if 3 in self.hardware_breakpoints: self.bp_del_hw(slot=3)

        return self.ret_self()


    ####################################################################################################################
    def bp_del_mem (self, address):
        '''
        Removes the memory breakpoint from target address.

        @see: bp_del_mem_all(), bp_set_mem(), bp_is_ours_mem()

        @type  address: DWORD
        @param address: Address or list of addresses to remove memory breakpoint from

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("bp_del_mem(0x%08x)" % address)

        # ensure a memory breakpoint exists at the target address.
        if address in self.memory_breakpoints:
            size = self.memory_breakpoints[address].size
            mbi  = self.memory_breakpoints[address].mbi

            # remove the memory breakpoint from our internal list.
            del self.memory_breakpoints[address]

            # page-aligned target memory range.
            start = mbi.BaseAddress
            end   = address + size                                  # non page-aligned range end
            end   = end + self.page_size - (end % self.page_size)   # page-aligned range end

            # for each page in the target range, restore the original page permissions if no other breakpoint exists.
            for page in range(start, end, self.page_size):
                other_bp_found = False

                for mem_bp in self.memory_breakpoints.values():
                    if page <= mem_bp.address < page + self.page_size:
                        other_bp_found = True
                        break
                    if page <= mem_bp.address + size < page + self.page_size:
                        other_bp_found = True
                        break

                if not other_bp_found:
                    try:
                        self.virtual_protect(page, 1, mbi.Protect & ~PAGE_GUARD)

                        # remove the page from the set of tracked GUARD pages.
                        self._guarded_pages.remove(mbi.BaseAddress)
                    except:
                        pass

        return self.ret_self()


    ####################################################################################################################
    def bp_del_mem_all (self):
        '''
        Removes all memory breakpoints from the debuggee.

        @see: bp_del_mem(), bp_set_mem(), bp_is_ours_mem()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("bp_del_mem_all()")

        for address in self.memory_breakpoints.keys():
            self.bp_del_mem(address)

        return self.ret_self()


    ####################################################################################################################
    def bp_is_ours (self, address_to_check):
        '''
        Determine if a breakpoint address belongs to us.

        @see: bp_set(), bp_del(), bp_del_all()

        @type  address_to_check: DWORD
        @param address_to_check: Address to check if we have set a breakpoint at

        @rtype:  Bool
        @return: True if breakpoint in question is ours, False otherwise
        '''

        if address_to_check in self.memory_by_pid[self.pid].breakpoints:
            return True

        return False


    ####################################################################################################################
    def bp_is_ours_mem (self, address_to_check):
        '''
        Determines if the specified address falls within the range of one of our memory breakpoints. When handling
        potential memory breakpoint exceptions it is mandatory to check the offending address with this routine as
        memory breakpoints are implemented by changing page permissions and the referenced address may very well exist
        within the same page as a memory breakpoint but not within the actual range of the buffer we wish to break on.

        @see: bp_set_mem(), bp_del_mem(), bp_del_mem_all()

        @type  address_to_check: DWORD
        @param address_to_check: Address to check if we have set a breakpoint on

        @rtype:  Mixed
        @return: The starting address of the buffer our breakpoint triggered on or False if address falls outside range.
        '''

        for address in self.memory_breakpoints:
            size = self.memory_breakpoints[address].size

            if address_to_check >= address and address_to_check <= address + size:
                return address

        return False


    ####################################################################################################################
    def bp_set (self, address, description="", restore=True, handler=None):
        '''
        Sets a breakpoint at the designated address. Register an EXCEPTION_BREAKPOINT callback handler to catch
        breakpoint events. If a list of addresses is submitted to this routine then the entire list of new breakpoints
        get the same description and restore. The optional "handler" parameter can be used to identify a function to
        specifically handle the specified bp, as opposed to the generic bp callback handler. The prototype of the
        callback routines is::

            func (pydbg)
                return DBG_CONTINUE     # or other continue status

        @see: bp_is_ours(), bp_del(), bp_del_all()

        @type  address:     DWORD or List
        @param address:     Address or list of addresses to set breakpoint at
        @type  description: String
        @param description: (Optional) Description to associate with this breakpoint
        @type  restore:     Bool
        @param restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # if a list of addresses to set breakpoints on from was supplied
        if type(address) is list:
            # pass each lone address to ourself (each one gets the same description / restore flag).
            for addr in address:
                self.bp_set(addr, description, restore, handler)

            return self.ret_self()

        #self._log("bp_set(0x%016x)" % address)
        assert address
        # ensure a breakpoint doesn't already exist at the target address.
        if not address in self.memory_by_pid[self.pid].breakpoints:
            try:
                # save the original byte at the requested breakpoint address.
                original_byte = self.read_process_memory(address, 1)

                # write an int3 into the target process space.
                self.write_process_memory(address, b"\xCC")
                self.set_attr("dirty", True)

                # add the breakpoint to the internal list.
                self.memory_by_pid[self.pid].breakpoints[address] = breakpoint(address, original_byte, description, restore, handler)
            except Exception as exc:
                raise pdx("Failed setting breakpoint at %016x : %s" % (address, exc))
        else:
            self._log("bp_set ALREADY BREAKPOINT in %d" % self.pid)

        return self.ret_self()


    ####################################################################################################################
    def bp_set_hw (self, address, length, condition, description="", restore=True, handler=None):
        '''
        Sets a hardware breakpoint at the designated address. Register an EXCEPTION_SINGLE_STEP callback handler to
        catch hardware breakpoint events. Setting hardware breakpoints requires the internal h_thread handle be set.
        This means that you can not set one outside the context of an debug event handler. If you want to set a hardware
        breakpoint as soon as you attach to or load a process, do so in the first chance breakpoint handler.

        For more information regarding the Intel x86 debug registers and hardware breakpoints see::

            http://pdos.csail.mit.edu/6.828/2005/readings/ia32/IA32-3.pdf
            Section 15.2

        Alternatively, you can register a custom handler to handle hits on the specific hw breakpoint slot.

        *Warning: Setting hardware breakpoints during the first system breakpoint will be removed upon process
        continue.  A better approach is to set a software breakpoint that when hit will set your hardware breakpoints.

        @note: Hardware breakpoints are handled globally throughout the entire process and not a single specific thread.
        @see:  bp_del_hw(), bp_del_hw_all()

        @type  address:     DWORD
        @param address:     Address to set hardware breakpoint at
        @type  length:      Integer (1, 2 or 4)
        @param length:      Size of hardware breakpoint in bytes (byte, word or dword)
        @type  condition:   Integer (HW_ACCESS, HW_WRITE, HW_EXECUTE)
        @param condition:   Condition to set the hardware breakpoint to activate on
        @type  description: String
        @param description: (Optional) Description of breakpoint
        @type  restore:     Boolean
        @param restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("bp_set_hw(%016x, %d, %s)" % (address, length, condition))

        # instantiate a new hardware breakpoint object for the new bp to create.
        hw_bp = hardware_breakpoint(address, length, condition, description, restore, handler=handler)

        if length not in (1, 2, 4):
            raise pdx("invalid hw breakpoint length: %d." % length)

        # length -= 1 because the following codes are used for determining length:
        #       00 - 1 byte length
        #       01 - 2 byte length
        #       10 - undefined
        #       11 - 4 byte length
        length -= 1

        # condition table:
        #       00 - break on instruction execution only
        #       01 - break on data writes only
        #       10 - undefined
        #       11 - break on data reads or writes but not instruction fetches
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            raise pdx("invalid hw breakpoint condition: %d" % condition)

        # check for any available hardware breakpoint slots. there doesn't appear to be any difference between local
        # and global as far as we are concerned on windows.
        #
        #     bits 0, 2, 4, 6 for local  (L0 - L3)
        #     bits 1, 3, 5, 7 for global (G0 - G3)
        #
        # we could programatically search for an open slot in a given thread context with the following code:
        #
        #    available = None
        #    for slot in range(4):
        #        if context.Dr7 & (1 << (slot * 2)) == 0:
        #            available = slot
        #            break
        #
        # but since we are doing global hardware breakpoints, we rely on ourself for tracking open slots.

        if not 0 in self.hardware_breakpoints:
            available = 0
        elif not 1 in self.hardware_breakpoints:
            available = 1
        elif not 2 in self.hardware_breakpoints:
            available = 2
        elif not 3 in self.hardware_breakpoints:
            available = 3
        else:
            raise pdx("no hw breakpoint slots available.")

        # activate the hardware breakpoint for all active threads.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # mark available debug register as active (L0 - L3).
            context.Dr7 |= 1 << (available * 2)

            # save our breakpoint address to the available hw bp slot.
            if   available == 0: context.Dr0 = address
            elif available == 1: context.Dr1 = address
            elif available == 2: context.Dr2 = address
            elif available == 3: context.Dr3 = address

            # set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
            context.Dr7 |= condition << ((available * 4) + 16)

            # set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
            context.Dr7 |= length << ((available * 4) + 18)

            # set the thread context.
            self.set_thread_context(context, thread_id=thread_id)

        # update the internal hardware breakpoint array at the used slot index.
        hw_bp.slot = available
        self.hardware_breakpoints[available] = hw_bp

        return self.ret_self()


    ####################################################################################################################
    def bp_set_mem (self, address, size, description="", handler=None):
        '''
        Sets a memory breakpoint at the target address. This is implemented by changing the permissions of the page
        containing the address to PAGE_GUARD. To catch memory breakpoints you have to register the EXCEPTION_GUARD_PAGE
        callback. Within the callback handler check the internal pydbg variable self.memory_breakpoint_hit to
        determine if the violation was a result of a direct memory breakpoint hit or some unrelated event.
        Alternatively, you can register a custom handler to handle the memory breakpoint. Memory breakpoints are
        automatically restored via the internal single step handler. To remove a memory breakpoint, you must explicitly
        call bp_del_mem().

        @see: bp_is_ours_mem(), bp_del_mem(), bp_del_mem_all()

        @type  address:     DWORD
        @param address:     Starting address of the buffer to break on
        @type  size:        Integer
        @param size:        Size of the buffer to break on
        @type  description: String
        @param description: (Optional) Description to associate with this breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("bp_set_mem() buffer range is %016x - %016x" % (address, address + size))

        # ensure the target address doesn't already sit in a memory breakpoint range:
        if self.bp_is_ours_mem(address):
            self._log("a memory breakpoint spanning %016x already exists" % address)
            return self.ret_self()

        # determine the base address of the page containing the starting point of our buffer.
        try:
            mbi = self.virtual_query(address)
        except:
            raise pdx("bp_set_mem(): failed querying address: %016x" % address)

        self._log("buffer starting at %016x sits on page starting at %016x" % (address, mbi.BaseAddress))

        # individually change the page permissions for each page our buffer spans.
        # why do we individually set the page permissions of each page as opposed to a range of pages? because empirical
        # testing shows that when you set a PAGE_GUARD on a range of pages, if any of those pages are accessed, then
        # the PAGE_GUARD attribute is dropped for the entire range of pages that was originally modified. this is
        # undesirable for our purposes when it comes to the ease of restoring hit memory breakpoints.
        current_page = mbi.BaseAddress

        while current_page <= address + size:
            self._log("changing page permissions on %016x" % current_page)

            # keep track of explicitly guarded pages, to differentiate from pages guarded by the debuggee / OS.
            self._guarded_pages.add(current_page)
            self.virtual_protect(current_page, 1, mbi.Protect | PAGE_GUARD)

            current_page += self.page_size

        # add the breakpoint to the internal list.
        self.memory_breakpoints[address] = memory_breakpoint(address, size, mbi, description, handler)

        return self.ret_self()


    ####################################################################################################################
    def close_handle (self, handle):
        '''
        Convenience wraper around kernel32.CloseHandle()

        @type  handle: Handle
        @param handle: Handle to close

        @rtype:  Bool
        @return: Return value from CloseHandle().
        '''

        return kernel32.CloseHandle(handle)


    ####################################################################################################################
    def dbg_print_all_debug_registers (self):
        '''
        *** DEBUG ROUTINE ***

        This is a debugging routine that was used when debugging hardware breakpoints. It was too useful to be removed
        from the release code.
        '''

        # ensure we have an up to date context for the current thread.
        context = self.get_thread_context(self.h_thread)

        print("eip = %08x" % context.Eip)
        print("Dr0 = %08x" % context.Dr0)
        print("Dr1 = %08x" % context.Dr1)
        print("Dr2 = %08x" % context.Dr2)
        print("Dr3 = %08x" % context.Dr3)
        print("Dr7 = %s"   % self.to_binary(context.Dr7))
        print("      10987654321098765432109876543210")
        print("      332222222222111111111")


    ####################################################################################################################
    def dbg_print_all_guarded_pages (self):
        '''
        *** DEBUG ROUTINE ***

        This is a debugging routine that was used when debugging memory breakpoints. It was too useful to be removed
        from the release code.
        '''

        cursor = 0

        # scan through the entire memory range.
        while cursor < 0xFFFFFFFF:
            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            if mbi.Protect & PAGE_GUARD:
                address = mbi.BaseAddress
                self._log("PAGE GUARD on %016x" % mbi.BaseAddress)

                while 1:
                    address += self.page_size
                    tmp_mbi  = self.virtual_query(address)

                    if not tmp_mbi.Protect & PAGE_GUARD:
                        break

                    self._log("PAGE GUARD on %016x" % address)

            cursor += mbi.RegionSize


    ####################################################################################################################
    def debug_active_process (self, pid):
        '''
        Convenience wrapper around GetLastError() and FormatMessage(). Returns the error code and formatted message
        associated with the last error. You probably do not want to call this directly, rather look at attach().

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        '''

        self._log("debug_active_process pid=%d" % pid)

        # If the process does not exit, it throws this misleading error:
        # E           pdx: [5] DebugActiveProcess(29228): Access is denied.
        if not kernel32.DebugActiveProcess(pid):
            raise pdx("DebugActiveProcess(%d)" % pid, True)


    ####################################################################################################################
    def switch_to_process(self, process_id, message):
        self._log("switch_to_process message=%s FROM self.pid=%d TO process_id=%d root_pid=%d"
                 % (message, self.pid, process_id, self.root_pid))
        self.pid = process_id
        self.open_process(process_id)
        if False:
            if process_id in self.pids_to_handle:
                self.pid = process_id
                self.h_process = self.pids_to_handle[process_id]
            else:
                self.pid = process_id
                self.open_process(process_id)
                self.pids_to_handle[process_id] = process_id

    ####################################################################################################################

    def debug_event_iteration (self, loop_delay=10000):
        """
        Check for and process a debug event.
        """

        continue_status = DBG_CONTINUE
        dbg             = DEBUG_EVENT()

        # struct _DEBUG_EVENT {
        #   DWORD dwDebugEventCode;
        #   DWORD dwProcessId;
        #   DWORD dwThreadId;
        #   union {
        #     EXCEPTION_DEBUG_INFO      Exception;
        #     CREATE_THREAD_DEBUG_INFO  CreateThread;
        #     CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
        #     EXIT_THREAD_DEBUG_INFO    ExitThread;
        #     EXIT_PROCESS_DEBUG_INFO   ExitProcess;
        #     LOAD_DLL_DEBUG_INFO       LoadDll;
        #     UNLOAD_DLL_DEBUG_INFO     UnloadDll;
        #     OUTPUT_DEBUG_STRING_INFO  DebugString;
        #     RIP_INFO                  RipInfo;
        #   } u;
        # }

        def _status_to_str(continue_status):
            return {
                DBG_CONTINUE: "DBG_CONTINUE",
                DBG_EXCEPTION_NOT_HANDLED: "DBG_EXCEPTION_NOT_HANDLED",
            }[continue_status]

        def debug_code_to_message(debug_code):
            try:
                return {
                    EXCEPTION_DEBUG_EVENT: "EXCEPTION_DEBUG_EVENT",
                    CREATE_THREAD_DEBUG_EVENT: "CREATE_THREAD_DEBUG_EVENT",
                    CREATE_PROCESS_DEBUG_EVENT: "CREATE_PROCESS_DEBUG_EVENT",
                    EXIT_THREAD_DEBUG_EVENT: "EXIT_THREAD_DEBUG_EVENT",
                    EXIT_PROCESS_DEBUG_EVENT: "EXIT_PROCESS_DEBUG_EVENT",
                    LOAD_DLL_DEBUG_EVENT: "LOAD_DLL_DEBUG_EVENT",
                    UNLOAD_DLL_DEBUG_EVENT: "UNLOAD_DLL_DEBUG_EVENT",
                    OUTPUT_DEBUG_STRING_EVENT: "OUTPUT_DEBUG_STRING_EVENT",
                    RIP_EVENT: "RIP_EVENT"}[debug_code]
            except KeyError:
                return "Unknown_%d" % debug_code

        #self._log("debug_event_iteration before WaitForDebugEvent")
        # wait for a debug event.
        logging.debug("loop_delay=%f self.pid=%d" % (loop_delay, self.pid))
        if kernel32.WaitForDebugEvent(byref(dbg), loop_delay):
            self.debug_counter_WaitForDebugEvent += 1

            #logging.debug("dbg.dwProcessId=%d" % dbg.dwProcessId)
            if dbg.dwProcessId != self.pid:
                self.switch_to_process(dbg.dwProcessId, debug_code_to_message(dbg.dwDebugEventCode))

            # grab various information with regards to the current exception.
            self.h_thread          = self.open_thread(dbg.dwThreadId)
            self.context           = self.get_thread_context(self.h_thread)

            self.dbg               = dbg
            self.exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
            self.write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
            self.violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
            self.exception_code    = dbg.u.Exception.ExceptionRecord.ExceptionCode

            # self._log("debug_event_iteration dbg.dwDebugEventCode=%d" % dbg.dwDebugEventCode)
            if dbg.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                self._log("debug_event_iteration CREATE_PROCESS_DEBUG_EVENT self.pid=%d dwProcessId=%d" \
                          % (self.pid, dbg.dwProcessId))
                continue_status = self.event_handler_create_process()
            elif dbg.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                self._log("debug_event_iteration CREATE_THREAD_DEBUG_EVENT dwThreadId=%d" % dbg.dwThreadId)
                continue_status = self.event_handler_create_thread()

            elif dbg.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                self._log("debug_event_iteration EXIT_PROCESS_DEBUG_EVENT dwProcessId=%d" % dbg.dwProcessId)
                continue_status = self.event_handler_exit_process()

            elif dbg.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                self._log("debug_event_iteration EXIT_THREAD_DEBUG_EVENT dwThreadId=%d" % dbg.dwThreadId)
                continue_status = self.event_handler_exit_thread()

            elif dbg.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                self._log("LOAD_DLL_DEBUG_EVENT dwProcessId=%d dwThreadId=%d" % (dbg.dwProcessId, dbg.dwThreadId))
                continue_status = self.event_handler_load_dll()

            elif dbg.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
                # self._log("debug_event_iteration UNLOAD_DLL_DEBUG_EVENT")
                continue_status = self.event_handler_unload_dll()

            # an exception was caught.
            elif dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                #self._log("debug_event_iteration EXCEPTION_DEBUG_EVENT")
                # https://stackoverflow.com/questions/3799294/im-having-problems-with-waitfordebugevent-exception-debug-event
                # Windows will send one EXCEPTION_BREAKPOINT (INT3) when it first loads.
                # You must DEBUG_CONTINUE this first breakpoint exception...
                # if you DBG_EXCEPTION_NOT_HANDLED you will get the popup message box:
                # The application failed to initialize properly (0x80000003).

                ec = dbg.u.Exception.ExceptionRecord.ExceptionCode

                # 0x80000003  EXCEPTION_BREAKPOINT
                #self._log("debug_event_iteration() exception: %08x" % ec)

                # call the internal handler for the exception event that just occured.
                if ec == EXCEPTION_ACCESS_VIOLATION:
                    self._log("EXCEPTION_ACCESS_VIOLATION")
                    continue_status = self.exception_handler_access_violation()
                elif ec == EXCEPTION_BREAKPOINT:
                    #self._log("EXCEPTION_BREAKPOINT")
                    self.debug_counter_exception_breakpoint += 1
                    continue_status = self.exception_handler_breakpoint()
                    #self._log("debug_event_iteration() continue_status: %08x DBG_CONTINUE: %08x" % (continue_status, DBG_CONTINUE) )
                elif ec == EXCEPTION_GUARD_PAGE:
                    #self._log("EXCEPTION_GUARD_PAGE")
                    continue_status = self.exception_handler_guard_page()
                elif ec == EXCEPTION_SINGLE_STEP:
                    #self._log("EXCEPTION_SINGLE_STEP")
                    continue_status = self.exception_handler_single_step()
                # generic callback support.
                elif ec in self.callbacks:
                    continue_status = self.callbacks[ec](self)
                # unhandled exception.
                else:
                    self._log("debug_event_iteration TID:%04x caused an unhandled exception (%08x) at %08x" % (self.dbg.dwThreadId, ec, self.exception_address))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            # if the memory space of the debuggee was tainted, flush the instruction cache.
            # from MSDN: Applications should call FlushInstructionCache if they generate or modify code in memory.
            #            The CPU cannot detect the change, and may execute the old code it cached.
            if self.dirty:
                # self._log("FlushInstructionCache")
                kernel32.FlushInstructionCache(self.h_process, 0, 0)

            # close the opened thread handle and resume executing the thread that triggered the debug event.
            self.close_handle(self.h_thread)
            #self._log("debug_event_iteration BEFORE ContinueDebugEvent dbg.dwProcessId=%d" % (dbg.dwProcessId))
            self._log("ContinueDebugEvent continue_status=%s" % _status_to_str(continue_status))
            if not kernel32.ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, continue_status):
                raise pdx("ContinueDebugEvent(p=%d t=%d)" % (dbg.dwProcessId, dbg.dwThreadId), True)

        else:
            self._log("WaitForDebugEvent delay=%d ms" % loop_delay)
            logging.debug("WaitForDebugEvent time-out delay=%d ms" % loop_delay)
            raise pdx("WaitForDebugEvent", True)
            # "The semaphore timeout period has expired."
            # self.win32_error("WaitForDebugEvent")

    ####################################################################################################################
    def debug_event_loop (self):
        '''
        Enter the infinite debug event handling loop. This is the main loop of the debugger and is responsible for
        catching debug events and exceptions and dispatching them appropriately. This routine will check for and call
        the USER_CALLBACK_DEBUG_EVENT callback on each loop iteration. run() is an alias for this routine.

        @see: run()

        @raise pdx: An exception is raised on any exceptional conditions, such as debugger being interrupted or
        debuggee quiting.
        '''

        self._log("debug_event_loop entering. self.debugger_active=%d" % self.debugger_active)
        while self.debugger_active:
            # don't let the user interrupt us in the midst of handling a debug event.
            try:
                def_sigint_handler = None
                def_sigint_handler = signal.signal(signal.SIGINT, self.sigint_handler)
            except:
                pass

            # if a user callback was specified, call it.
            if USER_CALLBACK_DEBUG_EVENT in self.callbacks:
                # user callbacks do not / should not access debugger or contextual information.
                self.dbg = self.context = None
                self.callbacks[USER_CALLBACK_DEBUG_EVENT](self)

            # iterate through a debug event.
            try:
                self.debug_event_iteration()
            except Exception as exc:
                self._log("debug_event_loop In loop on debugger_active: Caught:%s" % exc)
                logging.error("Caught:%s" % exc)
                raise

            # resume keyboard interruptability.
            if def_sigint_handler:
                signal.signal(signal.SIGINT, def_sigint_handler)

        # close the global process handle.
        self.close_handle(self.h_process)

        self._log("debug_event_loop leaving")

    ####################################################################################################################
    def debug_set_process_kill_on_exit (self, kill_on_exit):
        '''
        Convenience wrapper around DebugSetProcessKillOnExit().

        @type  kill_on_exit: Bool
        @param kill_on_exit: True to kill the process on debugger exit, False to let debuggee continue running.

        @raise pdx: An exception is raised on failure.
        '''

        self._log("About to call DebugSetProcessKillOnExit(%s)" % kill_on_exit)
        if not kernel32.DebugSetProcessKillOnExit(kill_on_exit):
            raise pdx("DebugSetProcessKillOnExit(%s)" % kill_on_exit, True)


    ####################################################################################################################
    def detach (self):
        '''
        Detach from debuggee.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("detach detaching from debuggee")

        # remove all software, memory and hardware breakpoints.
        self.bp_del_all()
        self.bp_del_mem_all()
        self.bp_del_hw_all()

        # try to detach from the target process if the API is available on the current platform.
        self._log("DebugActiveProcessStop")
        kernel32.DebugActiveProcessStop(self.pid)

        self._log("detach reset debugger_active")
        self.set_debugger_active(False)
        return self.ret_self()


    ####################################################################################################################
    def disasm (self, address):
        '''
        Pydasm disassemble utility function wrapper. Stores the pydasm decoded instruction in self.instruction.

        @type  address: DWORD
        @param address: Address to disassemble at

        @rtype:  String
        @return: Disassembled string.
        '''

        try:
            data  = self.read_process_memory(address, 32)
        except:
            return "Unable to disassemble at %08x" % address

        # update our internal member variables.
        self.instruction = pydasm.get_instruction(data, pydasm.MODE_32)

        if not self.instruction:
            self.mnemonic = "[UNKNOWN]"
            self.op1      = ""
            self.op2      = ""
            self.op3      = ""

            return "[UNKNOWN]"
        else:
            self.mnemonic = pydasm.get_mnemonic_string(self.instruction, pydasm.FORMAT_INTEL)
            self.op1      = pydasm.get_operand_string(self.instruction, 0, pydasm.FORMAT_INTEL, address)
            self.op2      = pydasm.get_operand_string(self.instruction, 1, pydasm.FORMAT_INTEL, address)
            self.op3      = pydasm.get_operand_string(self.instruction, 2, pydasm.FORMAT_INTEL, address)

            # the rstrip() is for removing extraneous trailing whitespace that libdasm sometimes leaves.
            return pydasm.get_instruction_string(self.instruction, pydasm.FORMAT_INTEL, address).rstrip(" ")


    ####################################################################################################################
    def disasm_around (self, address, num_inst=5):
        '''
        Given a specified address this routine will return the list of 5 instructions before and after the instruction
        at address (including the instruction at address, so 11 instructions in total). This is accomplished by grabbing
        a larger chunk of data around the address than what is predicted as necessary and then disassembling forward.
        If during the forward disassembly the requested address lines up with the start of an instruction, then the
        assumption is made that the forward disassembly self corrected itself and the instruction set is returned. If
        we are unable to align with the original address, then we modify our data slice and try again until we do.

        @type  address:  DWORD
        @param address:  Address to disassemble around
        @type  num_inst: Integer
        @param num_inst: (Optional, Def=5) Number of instructions to disassemble up/down from address

        @rtype:  List
        @return: List of tuples (address, disassembly) of instructions around the specified address.
        '''
        
        if num_inst == 0:
            return [(address, self.disasm(address))]
        
        if num_inst < 0 or not int == type(num_inst):
            self._err("disasm_around called with an invalid window size. reurning error value")
            return [(address, "invalid window size supplied")]
        
        # grab a safe window size of bytes.
        window_size = (num_inst * 64) / 5

        # grab a window of bytes before and after the requested address.
        try:
            data = self.read_process_memory(address - window_size, window_size * 2)
        except:
            return [(address, "Unable to disassemble")]

        # the rstrip() is for removing extraneous trailing whitespace that libdasm sometimes leaves.
        i           = pydasm.get_instruction(data[window_size:], pydasm.MODE_32)
        disassembly = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, address).rstrip(" ")
        complete    = False
        start_byte  = 0

        # loop until we retrieve a set of instructions that align to the requested address.
        while not complete:
            instructions = []
            slice        = data[start_byte:]
            offset       = 0

            # step through the bytes in the data slice.
            while offset < len(slice):
                i = pydasm.get_instruction(slice[offset:], pydasm.MODE_32)

                if not i:
                    break

                # calculate the actual address of the instruction at the current offset and grab the disassembly
                addr = address - window_size + start_byte + offset
                inst = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, addr).rstrip(" ")

                # add the address / instruction pair to our list of tuples.
                instructions.append((addr, inst))

                # increment the offset into the data slice by the length of the current instruction.
                offset += i.length

            # we're done processing a data slice.
            # step through each addres / instruction tuple in our instruction list looking for an instruction alignment
            # match. we do the match on address and the original disassembled instruction.
            index_of_address = 0
            for (addr, inst) in instructions:
                if addr == address and inst == disassembly:
                    complete = True
                    break

                index_of_address += 1

            start_byte += 1

        return instructions[index_of_address-num_inst:index_of_address+num_inst+1]


    ####################################################################################################################
    def dump_context (self, context=None, stack_depth=5, print_dots=True):
        '''
        Return an informational block of text describing the CPU context of the current thread. Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @see: dump_context_list()

        @type  context:     Context
        @param context:     (Optional) Current thread context to examine
        @type  stack_depth: Integer
        @param stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @type  print_dots:  Bool
        @param print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: Information about current thread context.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = self.dump_context_list(context, stack_depth, print_dots)

        context_dump  = "CONTEXT DUMP\n"
        context_dump += "  EIP: %08x %s\n" % (context.Eip, context_list["eip"])
        context_dump += "  EAX: %08x (%10d) -> %s\n" % (context.Eax, context.Eax, context_list["eax"])
        context_dump += "  EBX: %08x (%10d) -> %s\n" % (context.Ebx, context.Ebx, context_list["ebx"])
        context_dump += "  ECX: %08x (%10d) -> %s\n" % (context.Ecx, context.Ecx, context_list["ecx"])
        context_dump += "  EDX: %08x (%10d) -> %s\n" % (context.Edx, context.Edx, context_list["edx"])
        context_dump += "  EDI: %08x (%10d) -> %s\n" % (context.Edi, context.Edi, context_list["edi"])
        context_dump += "  ESI: %08x (%10d) -> %s\n" % (context.Esi, context.Esi, context_list["esi"])
        context_dump += "  EBP: %08x (%10d) -> %s\n" % (context.Ebp, context.Ebp, context_list["ebp"])
        context_dump += "  ESP: %08x (%10d) -> %s\n" % (context.Esp, context.Esp, context_list["esp"])

        for offset in range(0, stack_depth + 1):
            context_dump += "  +%02x: %08x (%10d) -> %s\n" %    \
            (                                                   \
                offset * 4,                                     \
                context_list["esp+%02x"%(offset*4)]["value"],   \
                context_list["esp+%02x"%(offset*4)]["value"],   \
                context_list["esp+%02x"%(offset*4)]["desc"]     \
            )

        return context_dump


    ####################################################################################################################
    def dump_context_list (self, context=None, stack_depth=5, print_dots=True, hex_dump=False):
        '''
        Return an informational list of items describing the CPU context of the current thread. Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @see: dump_context()

        @type  context:     Context
        @param context:     (Optional) Current thread context to examine
        @type  stack_depth: Integer
        @param stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @type  print_dots:  Bool
        @param print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  Dictionary
        @return: Dictionary of information about current thread context.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = {}

        context_list["eip"] = self.disasm(context.Eip)
        context_list["eax"] = self.smart_dereference(context.Eax, print_dots, hex_dump)
        context_list["ebx"] = self.smart_dereference(context.Ebx, print_dots, hex_dump)
        context_list["ecx"] = self.smart_dereference(context.Ecx, print_dots, hex_dump)
        context_list["edx"] = self.smart_dereference(context.Edx, print_dots, hex_dump)
        context_list["edi"] = self.smart_dereference(context.Edi, print_dots, hex_dump)
        context_list["esi"] = self.smart_dereference(context.Esi, print_dots, hex_dump)
        context_list["ebp"] = self.smart_dereference(context.Ebp, print_dots, hex_dump)
        context_list["esp"] = self.smart_dereference(context.Esp, print_dots, hex_dump)

        for offset in range(0, stack_depth + 1):
            try:
                esp = self.flip_endian_dword(self.read_process_memory(context.Esp + offset * 4, 4))

                context_list["esp+%02x"%(offset*4)]          = {}
                context_list["esp+%02x"%(offset*4)]["value"] = esp
                context_list["esp+%02x"%(offset*4)]["desc"]  = self.smart_dereference(esp, print_dots, hex_dump)
            except:
                context_list["esp+%02x"%(offset*4)]          = {}
                context_list["esp+%02x"%(offset*4)]["value"] = 0
                context_list["esp+%02x"%(offset*4)]["desc"]  = "[INVALID]"

        return context_list


    #####################################################################################################################
    def enumerate_modules (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate and return the list of module name / base address tuples that
        belong to the debuggee

        @see: iterate_modules()

        @rtype:  List
        @return: List of module name / base address tuples.
        '''

        # self._log("enumerate_modules()")

        module      = MODULEENTRY32()
        module_list = []
        # self._log("CreateToolhelp32Snapshot")
        snapshot    = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        module.dwSize = sizeof(module)

        # self._log("Module32First")
        # ctypes.ArgumentError: argument 2:
        # Python 2.7
        # <class 'TypeError'>: expected LP_MODULEENTRY32 instance instead of pointer to MODULEENTRY32
        # found_mod = kernel32.Module32First(snapshot, byref(module))
        try:
            # BEWARE: One of the libraries change this signature, therefore it is done again here.
            kernel32.Module32First.argtypes = (wintypes.HANDLE, LP_MODULEENTRY32)
            found_mod = kernel32.Module32First(snapshot, pointer(module))
        except Exception as exc:
            logging.error("Module32First CAUGHT:%s" % str(exc))
            logging.error("Module32First LP_MODULEENTRY32:%s" % LP_MODULEENTRY32)
            logging.error("Module32First pointer(module):%s" % pointer(module))
            raise

        while found_mod:
            module_list.append((module.szModule, module.modBaseAddr))
            # self._log("Module32Next")
            found_mod = kernel32.Module32Next(snapshot, byref(module))

        self.close_handle(snapshot)
        return module_list


    ####################################################################################################################
    def enumerate_processes (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system processes returning a list of pid / process name
        tuples.

        @see: iterate_processes()

        @rtype:  List
        @return: List of pid / process name tuples.

        Example::

            for (pid, name) in pydbg.enumerate_processes():
                if name == "test.exe":
                    break

            pydbg.attach(pid)
        '''

        self._log("enumerate_processes()")

        pe           = PROCESSENTRY32()
        process_list = []
        self._log("CreateToolhelp32Snapshot")
        snapshot     = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        self._log("Process32First")
        found_proc = kernel32.Process32First(snapshot, byref(pe))

        while found_proc:
            process_list.append((pe.th32ProcessID, pe.szExeFile))
            self._log("Process32Next")
            found_proc = kernel32.Process32Next(snapshot, byref(pe))

        self.close_handle(snapshot)
        return process_list


    ####################################################################################################################
    def enumerate_threads (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system threads returning a list of thread IDs that
        belong to the debuggee.

        @see: iterate_threads()

        @rtype:  List
        @return: List of thread IDs belonging to the debuggee.

        Example::
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)
        '''

        self._log("enumerate_threads()")

        thread_entry     = THREADENTRY32()
        debuggee_threads = []
        self._log("CreateToolhelp32Snapshot")
        snapshot         = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        self._log("Thread32First")
        success = kernel32.Thread32First(snapshot, byref(thread_entry))

        while success:
            if thread_entry.th32OwnerProcessID == self.pid:
                debuggee_threads.append(thread_entry.th32ThreadID)

            self._log("Thread32Next")
            success = kernel32.Thread32Next(snapshot, byref(thread_entry))

        self.close_handle(snapshot)
        return debuggee_threads


    ####################################################################################################################
    def event_handler_create_process (self):
        '''
        This is the default CREATE_PROCESS_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        self._log("event_handler_create_process() pid=%d created_pid=%d"
                  % (self.pid, win32process.GetProcessId(self.dbg.u.CreateProcessInfo.hProcess)))

        # don't need this.
        self.close_handle(self.dbg.u.CreateProcessInfo.hFile)
        self._log("Closed handle")

        # self.dbg.u.CreateProcessInfo.hProcess

        if not self.follow_forks:
            self._log("Do not follow forks")
            return DBG_CONTINUE

        if CREATE_PROCESS_DEBUG_EVENT in self.callbacks:
            self._log("Calling create process handler")
            return self.callbacks[CREATE_PROCESS_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_create_thread32 (self):
        '''
        This is the default CREATE_THREAD_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        # resolve the newly created threads TEB and add it to the internal dictionary.
        thread_id      = self.dbg.dwThreadId
        thread_handle  = self.dbg.u.CreateThread.hThread
        thread_context = self.get_thread_context(thread_handle)
        selector_entry = LDT_ENTRY()

        assert not is_64bits
        if not kernel32.GetThreadSelectorEntry(thread_handle, thread_context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        teb  = selector_entry.BaseLow
        teb += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # add this TEB to the internal dictionary.
        self.tebs[thread_id] = teb

        #  apply any existing hardware breakpoints to this new thread.
        for slot, hw_bp in self.hardware_breakpoints.items():
            # mark available debug register as active (L0 - L3).
            thread_context.Dr7 |= 1 << (slot * 2)

            # save our breakpoint address to the available hw bp slot.
            if   slot == 0: thread_context.Dr0 = hw_bp.address
            elif slot == 1: thread_context.Dr1 = hw_bp.address
            elif slot == 2: thread_context.Dr2 = hw_bp.address
            elif slot == 3: thread_context.Dr3 = hw_bp.address

            # set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
            thread_context.Dr7 |= hw_bp.condition << ((slot * 4) + 16)

            # set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
            thread_context.Dr7 |= hw_bp.length << ((slot * 4) + 18)

            # set the thread context.
            self.set_thread_context(thread_context, thread_id=thread_id)

    def event_handler_create_thread64(self):
        #self._log("event_handler_create_thread64 pid=%d tid=%d" % (self.dbg.dwProcessId, self.dbg.dwThreadId))
        pass

    def event_handler_create_thread(self):
        # https://stackoverflow.com/questions/54953185/getthreadselectorentry-throwing-error-not-supported-for-x64-app
        if is_64bits:
            self.event_handler_create_thread64()
        else:
            self.event_handler_create_thread32()

        # pass control to user defined callback.
        if CREATE_THREAD_DEBUG_EVENT in self.callbacks:
            return self.callbacks[CREATE_THREAD_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE

    ####################################################################################################################
    def event_handler_exit_process (self):
        '''
        This is the default EXIT_PROCESS_DEBUG_EVENT handler.

        @raise pdx: An exception is raised to denote process exit.
        '''

        # Debugging stops only if the root process leaves. Otherwise, do on debugging.
        self._log("event_handler_exit_process self.pid=%d self.root_pid=%d" % (self.pid, self.root_pid))
        if self.pid == self.root_pid:
            self._log("event_handler_exit_process debugger now inactive")
            self.set_debugger_active(False)

        if EXIT_PROCESS_DEBUG_EVENT in self.callbacks:
            self._log("event_handler_exit_process calling handler")
            return self.callbacks[EXIT_PROCESS_DEBUG_EVENT](self)
        else:
            self._log("event_handler_exit_process no handler")
            return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_exit_thread (self):
        '''
        This is the default EXIT_THREAD_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        #self._log("pydbg.event_handler_exit_thread() thread id %d" % self.dbg.dwThreadId)

        # before we remove the TEB entry from our internal list, let's give the user a chance to do something with it.
        if EXIT_THREAD_DEBUG_EVENT in self.callbacks:
            continue_status = self.callbacks[EXIT_THREAD_DEBUG_EVENT](self)
        else:
            continue_status = DBG_CONTINUE

        # remove the TEB entry for the exiting thread id.
        if self.dbg.dwThreadId in self.tebs:
            del(self.tebs[self.dbg.dwThreadId])

        return continue_status


    ####################################################################################################################
    def event_handler_load_dll (self):
        '''
        This is the default LOAD_DLL_DEBUG_EVENT handler. You can access the last loaded dll in your callback handler
        with the following example code::

            last_dll = pydbg.get_system_dll(-1)
            print "loading:%s from %s into:%08x size:%d" % (last_dll.name, last_dll.path, last_dll.base, last_dll.size)

        The get_system_dll() routine is preferred over directly accessing the internal data structure for proper and
        transparent client/server support.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        dll = system_dll(self.dbg.u.LoadDll.hFile, self.dbg.u.LoadDll.lpBaseOfDll)
        self.system_dlls.append(dll)

        if LOAD_DLL_DEBUG_EVENT in self.callbacks:
            return self.callbacks[LOAD_DLL_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_unload_dll (self):
        '''
        This is the default UNLOAD_DLL_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        base     = self.dbg.u.UnloadDll.lpBaseOfDll
        unloading = None

        for system_dll in self.system_dlls:
            if system_dll.base == base:
                unloading = system_dll
                break

        # before we remove the system dll from our internal list, let's give the user a chance to do something with it.
        if UNLOAD_DLL_DEBUG_EVENT in self.callbacks:
            continue_status = self.callbacks[UNLOAD_DLL_DEBUG_EVENT](self)
        else:
            continue_status = DBG_CONTINUE

        if not unloading:
            #raise pdx("Unable to locate DLL that is being unloaded from %08x" % base, False)
            pass
        else:
            # close the open file handle to the system dll being unloaded.
            self.close_handle(unloading.handle)

            # remove the system dll from the internal list.
            self.system_dlls.remove(unloading)
            del(unloading)

        return continue_status


    ####################################################################################################################
    def exception_handler_access_violation (self):
        '''
        This is the default EXCEPTION_ACCESS_VIOLATION handler. Responsible for handling the access violation and
        passing control to the registered user callback handler.

        @attention: If you catch an access violaton and wish to terminate the process, you *must* still return
                    DBG_CONTINUE to avoid a deadlock.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        if EXCEPTION_ACCESS_VIOLATION in self.callbacks:
            return self.callbacks[EXCEPTION_ACCESS_VIOLATION](self)
        else:
            return DBG_EXCEPTION_NOT_HANDLED


    ####################################################################################################################
    def exception_handler_breakpoint (self):
        '''
        This is the default EXCEPTION_BREAKPOINT handler, responsible for transparently restoring soft breakpoints
        and passing control to the registered user callback handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        #self._log("pydbg.exception_handler_breakpoint() at %016x from thread id %d" % (self.exception_address, self.dbg.dwThreadId))

        # breakpoints we did not set.
        if not self.bp_is_ours(self.exception_address):
            self.debug_counter_not_ours_breakpoints +=1
            # system breakpoints.
            self.set_system_break()
            assert self.system_break
            if self.exception_address == self.system_break:
                # pass control to user registered call back.
                if EXCEPTION_BREAKPOINT in self.callbacks:
                    continue_status = self.callbacks[EXCEPTION_BREAKPOINT](self)
                else:
                    continue_status = DBG_CONTINUE

                if self.first_breakpoint:
                    self._log("first windows driven system breakpoint at %016x" % self.exception_address)
                    self.first_breakpoint = False

            # ignore all other breakpoints we didn't explicitly set.
            else:
                # self._log("breakpoint not ours %016x" % self.exception_address)
                continue_status = DBG_EXCEPTION_NOT_HANDLED

        # breakpoints we did set.
        else:
            # restore the original byte at the breakpoint address.
            #self._log("restoring original byte at %016x: %s" % (self.exception_address, self.breakpoints[self.exception_address].original_byte))
            self.write_process_memory(self.exception_address, self.memory_by_pid[self.pid].breakpoints[self.exception_address].original_byte)
            # TODO: Why not self.dirty = True ??
            self.set_attr("dirty", True)

            # before we can continue, we have to correct the value of EIP. the reason for this is that the 1-byte INT 3
            # we inserted causes EIP to "slide" + 1 into the original instruction and must be reset.
            # IP = Instruction pointer, jumps to next instruction after interrupt=03
            if is_64bits:
                self.set_register("RIP", self.exception_address)
                self.context.Rip -= 1
            else:
                self.set_register("EIP", self.exception_address)
                self.context.Eip -= 1

            # if there is a specific handler registered for this bp, pass control to it.
            bp_handler = self.memory_by_pid[self.pid].breakpoints[self.exception_address].handler
            if bp_handler:
                continue_status = bp_handler(self)
                self.debug_counter_handled_breakpoints +=1

            # pass control to default user registered call back handler, if it is specified.
            elif EXCEPTION_BREAKPOINT in self.callbacks:
                continue_status = self.callbacks[EXCEPTION_BREAKPOINT](self)

            else:
                continue_status = DBG_CONTINUE

            # if the breakpoint still exists, ie: the user didn't erase it during the callback, and the breakpoint is
            # flagged for restore, then tell the single step handler about it. furthermore, check if the debugger is
            # still active, that way we don't try and single step if the user requested a detach.
            if self.get_attr("debugger_active") and self.exception_address in self.memory_by_pid[self.pid].breakpoints:
                if self.memory_by_pid[self.pid].breakpoints[self.exception_address].restore:
                    self._restore_breakpoint = self.memory_by_pid[self.pid].breakpoints[self.exception_address]
                    self.single_step(True)

                self.bp_del(self.exception_address)
                self.debug_counter_deleted_breakpoints +=1

        #self._log("leaving exception_handler_breakpoint")
        return continue_status

    ####################################################################################################################
    def returned_value(self):
        if is_64bits:
            return self.context.Rax
        else:
            return self.context.Eax

    ####################################################################################################################
    def return_address(self):
        if is_64bits:
            return self.context.Rip
        else:
            return self.context.Eip

    ####################################################################################################################
    def exception_handler_guard_page (self):
        '''
        This is the default EXCEPTION_GUARD_PAGE handler, responsible for transparently restoring memory breakpoints
        passing control to the registered user callback handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        self._log("pydbg.exception_handler_guard_page()")

        # determine the base address of the page where the offending reference resides.
        mbi = self.virtual_query(self.violation_address)

        # if the hit is on a page we did not explicitly GUARD, then pass the violation to the debuggee.
        if mbi.BaseAddress not in self._guarded_pages:
            return DBG_EXCEPTION_NOT_HANDLED

        # determine if the hit was within a monitored buffer, or simply on the same page.
        self.memory_breakpoint_hit = self.bp_is_ours_mem(self.violation_address)

        # grab the actual memory breakpoint object, for the hit breakpoint.
        if self.memory_breakpoint_hit:
            self._log("direct hit on memory breakpoint at %016x" % self.memory_breakpoint_hit)

        if self.write_violation:
            self._log("write violation from %016x on %016x of mem bp" % (self.exception_address, self.violation_address))
        else:
            self._log("read violation from %016x on %016x of mem bp" % (self.exception_address, self.violation_address))

        # if there is a specific handler registered for this bp, pass control to it.
        if self.memory_breakpoint_hit and self.memory_breakpoints[self.memory_breakpoint_hit].handler:
            continue_status = self.memory_breakpoints[self.memory_breakpoint_hit].handler(self)

        # pass control to default user registered call back handler, if it is specified.
        elif EXCEPTION_GUARD_PAGE in self.callbacks:
            continue_status = self.callbacks[EXCEPTION_GUARD_PAGE](self)

        else:
            continue_status = DBG_CONTINUE

        # if the hit page is still in our list of explicitly guarded pages, ie: the user didn't erase it during the
        # callback, then tell the single step handler about it. furthermore, check if the debugger is still active,
        # that way we don't try and single step if the user requested a detach.
        if self.get_attr("debugger_active") and mbi.BaseAddress in self._guarded_pages:
            self._restore_breakpoint = memory_breakpoint(None, None, mbi, None)
            self.single_step(True)

        return continue_status


    ####################################################################################################################
    def exception_handler_single_step (self):
        '''
        This is the default EXCEPTION_SINGLE_STEP handler, responsible for transparently restoring breakpoints and
        passing control to the registered user callback handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        #self._log("pydbg.exception_handler_single_step()")

        # if there is a breakpoint to restore.
        if self._restore_breakpoint:
            bp = self._restore_breakpoint

            # restore a soft breakpoint.
            if isinstance(bp, breakpoint):
                #self._log("restoring breakpoint at 0x%016x" % bp.address)
                self.bp_set(bp.address, bp.description, bp.restore, bp.handler)

            # restore PAGE_GUARD for a memory breakpoint (make sure guards are not temporarily suspended).
            elif isinstance(bp, memory_breakpoint) and self._guards_active:
                self._log("restoring %016x +PAGE_GUARD on page based @ %016x" % (bp.mbi.Protect, bp.mbi.BaseAddress))
                self.virtual_protect(bp.mbi.BaseAddress, 1, bp.mbi.Protect | PAGE_GUARD)

            # restore a hardware breakpoint.
            elif isinstance(bp, hardware_breakpoint):
                self._log("restoring hardware breakpoint on %016x" % bp.address)
                self.bp_set_hw(bp.address, bp.length, bp.condition, bp.description, bp.restore, bp.handler)

        # determine if this single step event occured in reaction to a hardware breakpoint and grab the hit breakpoint.
        # according to the Intel docs, we should be able to check for the BS flag in Dr6. but it appears that windows
        # isn't properly propogating that flag down to us.
        if self.context.Dr6 & 0x1 and 0 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[0]

        elif self.context.Dr6 & 0x2 and 1 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[1]

        elif self.context.Dr6 & 0x4 and 2 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[2]

        elif self.context.Dr6 & 0x8 and 3 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[3]

        # if we are dealing with a hardware breakpoint and there is a specific handler registered, pass control to it.
        if self.hardware_breakpoint_hit and self.hardware_breakpoint_hit.handler:
            continue_status = self.hardware_breakpoint_hit.handler(self)

        # pass control to default user registered call back handler, if it is specified.
        elif EXCEPTION_SINGLE_STEP in self.callbacks:
            continue_status = self.callbacks[EXCEPTION_SINGLE_STEP](self)

        # if we single stepped to handle a breakpoint restore.
        elif self._restore_breakpoint:
            continue_status = DBG_CONTINUE

            # macos compatability.
            # need to clear TRAP flag for MacOS. this doesn't hurt Windows aside from a negligible speed hit.
            context         = self.get_thread_context(self.h_thread)
            context.EFlags &= ~EFLAGS_TRAP
            self.set_thread_context(context)

        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        # if we are handling a hardware breakpoint hit and it still exists, ie: the user didn't erase it during the
        # callback, and the breakpoint is flagged for restore, then tell the single step handler about it. furthermore,
        # check if the debugger is still active, that way we don't try and single step if the user requested a detach.
        if self.hardware_breakpoint_hit != None and self.get_attr("debugger_active"):
            slot = self.hardware_breakpoint_hit.slot

            if slot in self.hardware_breakpoints:
                curr = self.hardware_breakpoints[slot]
                prev = self.hardware_breakpoint_hit

                if curr.address == prev.address:
                    if prev.restore:
                        self._restore_breakpoint = prev
                        self.single_step(True)

                    self.bp_del_hw(slot=prev.slot)

        # reset the hardware breakpoint hit flag and restore breakpoint variable.
        self.hardware_breakpoint_hit = None
        self._restore_breakpoint     = None

        return continue_status


    ####################################################################################################################

    def func_resolve(self, dll, function):
        '''
        Utility function that resolves the address of a given module / function name pair under the context of the
        debugger.
        See this for explanations:
        https://stackoverflow.com/questions/33779657/python-getmodulehandlew-oserror-winerror-126-the-specified-module-could-not-b/33780664#33780664
        https://stackoverflow.com/questions/35849546/getprocaddress-not-working-on-x64-python

        @see: func_resolve_debuggee()

        @type  dll:      String
        @param dll:      Name of the DLL (case-insensitive)
        @type  function: String
        @param function: Name of the function to resolve (case-sensitive)

        @rtype:  DWORD
        @return: Address
        '''

        assert isinstance(dll, six.binary_type)
        assert isinstance(function, six.binary_type)

        dll_utf8 = dll.decode("utf-8")
        dll_module = ctypes.WinDLL(dll_utf8, use_last_error=True)

        function_address = kernel32.GetProcAddress(dll_module._handle, function)
        assert function_address

        # These addresses might be identical but basic libraries like KERNEL32 because they are always loaded first.
        if True or "DEBUG DEBUG":
            address_debuggee = self.func_resolve_debuggee(dll, function)
            if function_address != address_debuggee:
                self._log("func_resolve dll=%s function=%s function_address=%016x" % (dll, function, function_address))
                self._log("func_resolve dll=%s function=%s address_debuggee=%016x" % (dll, function, address_debuggee))
                self._log("DIFFERENT debugger and debuggee addresses for %s." % function)
            # FIXME: DOES NOT MAKE SENSE. WHICH PROCESS IS USED ??

        return function_address


####################################################################################################################
    def func_resolve_debuggee (self, dll_name, func_name):
        '''
        Utility function that resolves the address of a given module / function name pair under the context of the
        debuggee. Note: Be weary of calling this function from within a LOAD_DLL handler as the module is not yet
        fully loaded and therefore the snapshot will not include it.

        @author: Otto Ebeling
        @see:    func_resolve()
        @todo:   Add support for followed imports.

        @type  dll_name:  String
        @param dll_name:  Name of the DLL (case-insensitive, ex:ws2_32.dll)
        @type  func_name: String
        @param func_name: Name of the function to resolve (case-sensitive)

        @rtype:  DWORD
        @return: Address of the symbol in the target process address space if it can be resolved, None otherwise
        '''

        base_address = self.find_dll_base_address (dll_name)
        if base_address:
            try:
                function_address = self.func_resolve_from_dll(base_address, func_name)
            except Exception as exc:
                new_message = "%s. Module=%s" % (str(exc), module.szModule)
                raise Exception(new_message)
            return function_address
        self._log("func_resolve_debuggee func_name=%s module not found dll_name=%s" % (func_name, dll_name))
        return 0

    def canonic_dll_name(self, dll_name):
        assert isinstance(dll_name, six.binary_type)
        dll_name = os.path.basename(dll_name)
        dll_name = dll_name.lower()

        # we can't make the assumption that all DLL names end in .dll, for example Quicktime libs end in .qtx / .qts
        # so instead of this old line:
        #     if not dll_name.endswith(".dll"):
        # we'll check for the presence of a dot and will add .dll as a conveneince.
        if not dll_name.count(b"."):
            dll_name += b".dll"
        return dll_name

    def find_dll_base_address (self, dll_name):
        dll_name = self.canonic_dll_name(dll_name)

        for module in self.iterate_modules():
            if module.szModule.lower() == dll_name:
                base_address = int(cast(module.modBaseAddr, ctypes.c_void_p).value)
                return base_address
        return 0

    def get_base_address_dict(self):
        # TODO: Must be used at a specific moment.
        logging.debug("get_base_address_dict")
        base_address_dict = {}
        for module in self.iterate_modules():
            base_address = int(cast(module.modBaseAddr, ctypes.c_void_p).value)
            base_address_dict[module.szModule.lower()] = base_address
        logging.debug("get_base_address_dict %d elements" % len(base_address_dict))
        return base_address_dict

####################################################################################################################

    def func_resolve_from_dll(self, base_address, func_name):
        def _from_pe_headers32(pe_headers):
            export_directory_rva = struct.unpack("<I", pe_headers[0x78:0x7C])[0]
            export_directory_len = struct.unpack("<I", pe_headers[0x7C:0x80])[0]
            return _from_export_directory(export_directory_rva, export_directory_len)

        def _from_pe_headers64(pe_headers, class_image_optional_header, offset_image_optional_header):
            offset_export_directory = class_image_optional_header.DataDirectory.offset + offset_image_optional_header
            export_directory_rva = struct.unpack("<I", pe_headers[offset_export_directory:offset_export_directory + 4])[
                0]
            export_directory_len = \
            struct.unpack("<I", pe_headers[offset_export_directory + 4:offset_export_directory + 8])[0]
            return _from_export_directory(export_directory_rva, export_directory_len)

        def _from_export_directory(export_directory_rva, export_directory_len):
            export_directory = self.read_process_memory(base_address + export_directory_rva, export_directory_len)
            num_of_functions = struct.unpack("<I", export_directory[0x14:0x18])[0]
            num_of_names = struct.unpack("<I", export_directory[0x18:0x1C])[0]
            address_of_functions = struct.unpack("<I", export_directory[0x1C:0x20])[0]
            address_of_names = struct.unpack("<I", export_directory[0x20:0x24])[0]
            address_of_ordinals = struct.unpack("<I", export_directory[0x24:0x28])[0]
            name_table = self.read_process_memory(base_address + address_of_names, num_of_names * 4)

            # perform a binary search across the function names.
            low = 0
            high = num_of_names

            while low <= high:
                # python does not suffer from integer overflows:
                #     http://googleresearch.blogspot.com/2006/06/extra-extra-read-all-about-it-nearly.html
                middle = (low + high) // 2
                current_address = base_address + struct.unpack("<I", name_table[middle * 4:(middle + 1) * 4])[0]

                # we use a crude approach here. read 256 bytes and cut on NULL char. not very beautiful, but reading
                # 1 byte at a time is very slow.
                name_buffer = self.read_process_memory(current_address, 256)
                name_buffer = name_buffer[:name_buffer.find(b"\0")]

                if name_buffer < func_name:
                    low = middle + 1
                elif name_buffer > func_name:
                    high = middle - 1
                else:
                    # MSFT documentation is misleading - see http://www.bitsum.com/pedocerrors.htm
                    bin_ordinal = self.read_process_memory(base_address + address_of_ordinals + middle * 2, 2)
                    ordinal = struct.unpack("<H", bin_ordinal)[0]  # ordinalBase has already been subtracted
                    bin_func_address = self.read_process_memory(base_address + address_of_functions + ordinal * 4, 4)
                    function_address = struct.unpack("<I", bin_func_address)[0]

                    return base_address + function_address

            # function was not found.
            self._log("_from_export_directory pid=% func_name=%s not found" % (self.pid, func_name))
            return None

        assert isinstance(func_name, six.binary_type)

        #self._log("func_resolve_from_dll  pid=%d func_name=%s base_address=%016x" % (self.pid, func_name, base_address))

        # A PE executable is strctured like that:
        # MZ-DOS header.
        # DOS sergement, executed when running in DOS mode.
        # PE header.
        # Sections table.
        # Section 1, 2, 3 etc...

        assert self.h_process
        try:
            dos_header = self.read_process_memory(base_address, 0x40)
        except:
            self._log("Exception reading from %s" % func_name)
            raise


        # check validity of DOS header.
        if len(dos_header) != 0x40 or dos_header[:2] != b"MZ":
            self._log("Invalid DOS header: %s" % str(dos_header[:2]))
            raise Exception("Invalid DOS header")

        # This contains the beginning of the PE header.
        e_lfanew   = struct.unpack("<I", dos_header[0x3c:0x40])[0]
        pe_headers = self.read_process_memory(base_address + e_lfanew, 0xF8)

        # typedef struct _IMAGE_NT_HEADERS {
        #  0  x00 DWORD                 Signature;
        #  4  x04 IMAGE_FILE_HEADER     FileHeader;
        # 24  x18 IMAGE_OPTIONAL_HEADER OptionalHeader;
        # } IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

        # Signature must contain "PE\0\0" or 0x00004550
        # check validity of PE headers. OK in 32 and 64 bits.
        if len(pe_headers) != 0xF8 or pe_headers[:4] != b"PE\0\0":
            self._log("Invalid PE header.")
            raise Exception("Invalid PE header.")

        # typedef struct _IMAGE_FILE_HEADER {
        #   0 WORD  Machine;
        #   2 WORD  NumberOfSections;
        #   4 DWORD TimeDateStamp;
        #   8 DWORD PointerToSymbolTable;
        #  12 DWORD NumberOfSymbols;
        #  16 WORD  SizeOfOptionalHeader;
        #  18 WORD  Characteristics;
        # } 20 IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

        # IMAGE_FILE_MACHINE_I386  0x014c
        # IMAGE_FILE_MACHINE_IA64  0x0200
        # IMAGE_FILE_MACHINE_AMD64 0x8664
        machine_type = struct.unpack("<H", pe_headers[4:6])[0]
        assert(machine_type in [0x014c, 0x0200, 0x8664])

        # IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
        # IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
        # IMAGE_ROM_OPTIONAL_HDR_MAGIC  0x107

        offset_image_file_header = 4
        offset_image_optional_header = offset_image_file_header + 20
        optional_magic = struct.unpack("<H", pe_headers[offset_image_optional_header:offset_image_optional_header+2])[0]
        assert optional_magic in [0x10b, 0x20b, 0x107]

        if optional_magic == 0x10b:
            class_image_optional_header = IMAGE_OPTIONAL_HEADER32
            assert class_image_optional_header.Magic.offset == 0
            assert class_image_optional_header.DataDirectory.offset == 0x60
            return _from_pe_headers32(pe_headers, class_image_optional_header, offset_image_optional_header)
        elif optional_magic == 0x20b:
            class_image_optional_header = IMAGE_OPTIONAL_HEADER64
            assert class_image_optional_header.Magic.offset == 0
            assert class_image_optional_header.DataDirectory.offset == 0x70
            return _from_pe_headers64(pe_headers, class_image_optional_header, offset_image_optional_header)
        else:
            raise Exception("Cannot work with IMAGE_ROM_OPTIONAL_HDR_MAGIC")



    ####################################################################################################################
    def get_ascii_string (self, data):
        '''
        Retrieve the ASCII string, if any, from data. Ensure that the string is valid by checking against the minimum
        length requirement defined in self.STRING_EXPLORATION_MIN_LENGTH.

        @type  data: Raw
        @param data: Data to explore for printable ascii string

        @rtype:  String
        @return: False on failure, ascii string on discovered string.
        '''

        discovered = ""

        for char in data:
            # if we've hit a non printable char, break
            if ord(char) < 32 or ord(char) > 126:
                break

            discovered += char

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered



    ####################################################################################################################
    def get_arg (self, index, context=None):
        '''
        Given a thread context, this convenience routine will retrieve the function argument at the specified index.
        The return address of the function can be retrieved by specifying an index of 0. This routine should be called
        from breakpoint handlers at the top of a function.

        @type  index:   Integer
        @param index:   Index of the parameter on the stack.
        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  DWORD
        @return: Value of specified argument.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context


        if is_64bits:
            # https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019
            # The first four integer arguments are passed in registers.
            # Integer values are passed in left-to-right order in RCX, RDX, R8, and R9, respectively.
            # Arguments five and higher are passed on the stack.
            # All arguments are right-justified in registers,
            # so the callee can ignore the upper bits of the register and access only the portion of the register necessary.
            # BEWARE: Different logic for floats and doubles.
            if index == 1:
                arg_val = context.Rcx
            elif index == 2:
                arg_val = context.Rdx
            elif index == 3:
                arg_val = context.R8
            elif index == 4:
                arg_val = context.R9
            else:
                arg_val = self.read_process_memory(context.Rsp + index * 8, 8)
                assert isinstance(arg_val, six.binary_type)
                # FIXME: Why flipping here only, and not the registers content ?
                arg_val = self.flip_endian_dword(arg_val)
            #self._log("get_arg index=%d Rsp=%016x Rbp=%016x Rcx=%016x Rdx=%016x arg_val= %016x"
            #          % (index, context.Rsp, context.Rbp, context.Rcx, context.Rdx, arg_val))
        else:
            arg_val = self.read_process_memory(context.Esp + index * 4, 4)
            # self._log("arg_val=", ''.join('{:02x}'.format(ord(x)) for x in arg_val))
            assert isinstance(arg_val, six.binary_type)
            arg_val = self.flip_endian_dword(arg_val)

            #self._log("get_arg index=%d Esp=%08x Ebp=%08x arg_val= %08x" % (index, context.Esp, context.Ebp, arg_val))

        return arg_val

    ####################################################################################################################
    def set_arg (self, index, value, context=None):
        '''
        Given a thread context, this convenience routine will sets the function argument at the specified index.

        @type  index:   Integer
        @param index:   Index of the parameter on the stack.
        @type  value:   Integer
        @param value:   Data to store
        @type  context: Context
        @param context: (Optional) Current thread context to examine
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        if is_64bits:
            # https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019
            # The first four integer arguments are passed in registers.
            # Integer values are passed in left-to-right order in RCX, RDX, R8, and R9, respectively.
            # Arguments five and higher are passed on the stack.
            # All arguments are right-justified in registers,
            # so the callee can ignore the upper bits of the register and access only the portion of the register necessary.
            # BEWARE: Different logic for floats and doubles.
            if index == 1:
                raise Exception("Set_val: Not implemented yet")
            elif index == 2:
                raise Exception("Set_val: Not implemented yet")
            elif index == 3:
                raise Exception("Set_val: Not implemented yet")
            elif index == 4:
                raise Exception("Set_val: Not implemented yet")
            else:
                arg_val = self.unflip_endian_dword(value)
                self.write_process_memory(context.Rsp + index * 8, arg_val, 8)
            #self._log("get_arg index=%d Rsp=%016x Rbp=%016x Rcx=%016x Rdx=%016x arg_val= %016x"
            #          % (index, context.Rsp, context.Rbp, context.Rcx, context.Rdx, arg_val))
        else:
            raise Exception("Set_val: Not implemented yet")

    ####################################################################################################################
    def get_attr (self, attribute):
        '''
        Return the value for the specified class attribute. This routine should be used over directly accessing class
        member variables for transparent support across local vs. client/server debugger clients.

        @see: set_attr()

        @type  attribute: String
        @param attribute: Name of attribute to return.

        @rtype:  Mixed
        @return: Requested attribute or None if not found.
        '''

        if not hasattr(self, attribute):
            return None

        return getattr(self, attribute)


    ####################################################################################################################

    # https://gist.github.com/schlamar/7024668
    def my_get_process_token_not_used(self):
        """
        Get the current process token
        """

        token = wintypes.HANDLE()
        TOKEN_ALL_ACCESS = 0xf01ff
        res = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token)
        if not res > 0:
            raise RuntimeError("Couldn't get process token")
        self._log("my_get_process_token res=%d token=%d" % (res, token))
        return token

    def get_debug_privileges (self):
        '''
        Obtain necessary privileges for debugging.

        @raise pdx: An exception is raised on failure.
        '''

        h_token     = HANDLE()
        luid        = LUID()
        token_state = TOKEN_PRIVILEGES()

        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, byref(h_token)):
            raise pdx("Exception:OpenProcessToken()", True)

        if not advapi32.LookupPrivilegeValueA(0, b"seDebugPrivilege", byref(luid)):
            raise pdx("LookupPrivilegeValue()", True)

        # If the debugging process has the SE_DEBUG_NAME privilege granted and enabled, it can debug any process.
        token_state.PrivilegeCount = 1

        # https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
        # SE_DEBUG_NAME
        # TEXT("SeDebugPrivilege")

        token_state.Privileges[0].Luid = luid
        token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(h_token, 0, byref(token_state), 0, 0, 0):
            raise pdx("AdjustTokenPrivileges()", True)


    ####################################################################################################################
    def get_instruction (self, address):
        '''
        Pydasm disassemble utility function wrapper. Returns the pydasm decoded instruction in self.instruction.

        @type  address: DWORD
        @param address: Address to disassemble at

        @rtype:  pydasm instruction
        @return: pydasm instruction
        '''

        try:
            data  = self.read_process_memory(address, 32)
        except:
            return "Unable to disassemble at %08x" % address

        return pydasm.get_instruction(data, pydasm.MODE_32)


    ####################################################################################################################
    def get_printable_string (self, data, print_dots=True):
        '''
        description

        @type  data:       Raw
        @param data:       Data to explore for printable ascii string
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: False on failure, discovered printable chars in string otherwise.
        '''

        discovered = ""

        for char in data:
            if ord(char) >= 32 and ord(char) <= 126:
                discovered += char
            elif print_dots:
                discovered += "."

        return discovered


    ####################################################################################################################
    def get_register (self, register):
        '''
        Get the value of a register in the debuggee within the context of the self.h_thread.

        @type  register: Register
        @param register: One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Value of specified register.
        '''

        #self._log("getting %s in thread id %d" % (register, self.dbg.dwThreadId))

        register = register.upper()
        if register not in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"):
            raise pdx("invalid register specified")

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        if   register == "EAX": return context.Eax
        elif register == "EBX": return context.Ebx
        elif register == "ECX": return context.Ecx
        elif register == "EDX": return context.Edx
        elif register == "ESI": return context.Esi
        elif register == "EDI": return context.Edi
        elif register == "ESP": return context.Esp
        elif register == "EBP": return context.Ebp
        elif register == "EIP": return context.Eip

        # this shouldn't ever really be reached.
        return 0


    ####################################################################################################################
    def get_system_dll (self, idx):
        '''
        Return the system DLL at the specified index. If the debugger is in client / server mode, remove the PE
        structure (we do not want to send that mammoth over the wire).

        @type  idx: Integer
        @param idx: Index into self.system_dlls[] to retrieve DLL from.

        @rtype:  Mixed
        @return: Requested attribute or None if not found.
        '''

        self._log("get_system_dll()")

        try:
            dll = self.system_dlls[idx]
        except:
            # index out of range.
            return None

        dll.pe = None
        return dll



    ####################################################################################################################
    def get_thread_context (self, thread_handle=None, thread_id=0):
        # This depends on the target process. At the moment,
        # only 32 bits or 64 bits.
        # https://stackoverflow.com/questions/17504174/win-64bit-getthreadcontext-returns-zeroed-out-registers-or-0x57-errorcode
        if is_64bits:
            return self.get_thread_context64(thread_handle, thread_id)
        else:
            return self.get_thread_context32(thread_handle, thread_id)

    ####################################################################################################################
    def get_thread_context64 (self, thread_handle=None, thread_id=0):
        #self._log("get_thread_context64 thread_id=%d" % thread_id)

        context = CONTEXT64()

        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # if a thread handle was not specified, get one from the thread id.
        if not thread_handle:
            h_thread = self.open_thread(thread_id)
        else:
            h_thread = thread_handle

        if not kernel32.GetThreadContext(h_thread, byref(context)):
            self._log("get_thread_context64 error GetThreadContext")
            raise pdx("GetThreadContext() thread_id=%s" % (str(thread_id)), True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle:
            self.close_handle(h_thread)

        if False:
            for register_name, register_type in context._fields_:
                try:
                    self._log("Register:%s Value= %08x" % (register_name, getattr(context, register_name)))
                except TypeError:
                    self._log("Register:%s Not a number" % (register_name))

        #self._log("get_thread_context64 leaving")
        return context

    ####################################################################################################################
    def get_thread_context32 (self, thread_handle=None, thread_id=0):
        '''
        Convenience wrapper around GetThreadContext(). Can obtain a thread context via a handle or thread id.

        @type  thread_handle: HANDLE
        @param thread_handle: (Optional) Handle of thread to get context of
        @type  thread_id:     Integer
        @param thread_id:     (Optional) ID of thread to get context of

        @raise pdx: An exception is raised on failure.
        @rtype:     CONTEXT
        @return:    Thread CONTEXT on success.
        '''

        self._log("get_thread_context32 thread_id=%d" % thread_id)

        context = CONTEXT()

        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # if a thread handle was not specified, get one from the thread id.
        if not thread_handle:
            h_thread = self.open_thread(thread_id)
        else:
            h_thread = thread_handle

        if not kernel32.GetThreadContext(h_thread, byref(context)):
            raise pdx("GetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle:
            self.close_handle(h_thread)

        return context

    ####################################################################################################################
    def get_unicode_string (self, data):
        '''
        description

        @type  data: Raw
        @param data: Data to explore for printable unicode string

        @rtype:  String
        @return: False on failure, ascii-converted unicode string on discovered string.
        '''

        discovered  = ""
        every_other = True

        for char in data:
            if every_other:
                # if we've hit a non printable char, break
                if ord(char) < 32 or ord(char) > 126:
                    break

                discovered += char

            every_other = not every_other

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered


    ####################################################################################################################
    def hex_dump (self, data, addr=0, prefix=""):
        '''
        Utility function that converts data into hex dump format.

        @type  data:   Raw Bytes
        @param data:   Raw bytes to view in hex dump
        @type  addr:   DWORD
        @param addr:   (Optional, def=0) Address to start hex offset display from
        @type  prefix: String (Optional, def="")
        @param prefix: String to prefix each line of hex dump with.

        @rtype:  String
        @return: Hex dump of data.
        '''

        dump  = prefix
        slice = ""

        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                dump += "\n%s%04x: " % (prefix, addr)
                slice = ""

            dump  += "%02x " % ord(byte)
            slice += byte
            addr  += 1

        remainder = addr % 16

        if remainder != 0:
            dump += "   " * (16 - remainder) + " "

        for char in slice:
            if ord(char) >= 32 and ord(char) <= 126:
                dump += char
            else:
                dump += "."

        return dump + "\n"


    ####################################################################################################################
    def hide_debugger (self):
        '''
        Hide the presence of the debugger. This routine requires an active context and therefore can not be called
        immediately after a load() for example. Call it from the first chance breakpoint handler. This routine hides
        the debugger in the following ways:

            - Modifies the PEB flag that IsDebuggerPresent() checks for.

        @raise pdx: An exception is raised if we are unable to hide the debugger for various reasons.
        '''

        selector_entry = LDT_ENTRY()

        # a current thread context is required.
        if not self.context:
            raise pdx("hide_debugger(): a thread context is required. Call me from a breakpoint handler.")

        assert not is_64bits
        if not kernel32.GetThreadSelectorEntry(self.h_thread, self.context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")
        self._log("AFTER GetThreadSelectorEntry")

        fs_base  = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # http://openrce.org/reference_library/files/reference/Windows Memory Layout, User-Kernel Address Spaces.pdf
        # find the peb.
        peb = self.read_process_memory(fs_base + 0x30, 4)
        peb = self.flip_endian_dword(peb)

        # zero out the flag. (3rd byte)
        self.write_process_memory(peb+2, "\x00", 1)

        return self.ret_self()


    ####################################################################################################################
    def is_address_on_stack (self, address, context=None):
        '''
        Utility function to determine if the specified address exists on the current thread stack or not.

        @type  address: DWORD
        @param address: Address to check
        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  Bool
        @return: True if address lies in current threads stack range, False otherwise.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        (stack_top, stack_bottom) = self.stack_range(context)

        if address >= stack_bottom and address <= stack_top:
            return True

        return False


    #####################################################################################################################
    def iterate_modules (self):
        '''
        A simple iterator function that can be used to iterate through all modules the target process has mapped in its
        address space. Yielded objects are of type MODULEENTRY32.

        @author:  Otto Ebeling
        @see:     enumerate_modules()
        @warning: break-ing out of loops over this routine will cause a handle leak.

        @rtype:  MODULEENTRY32
        @return: Iterated module entries.
        '''

        # self._log("iterate_modules pid=%d" % self.pid)

        current_entry = MODULEENTRY32()
        snapshot      = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        current_entry.dwSize = sizeof(current_entry)

        # ctypes.ArgumentError: argument 2: <class 'TypeError'>:
        # expected LP_MODULEENTRY32 instance instead of pointer to MODULEENTRY32
        # if not kernel32.Module32First(snapshot, byref(current_entry)):
        try:
            # BEWARE: One of the libraries change this signature, therefore it is done again here.
            kernel32.Module32First.argtypes = (wintypes.HANDLE, LP_MODULEENTRY32)
            # Module32First.argtypes = (wintypes.HANDLE, LP_MODULEENTRY32)
            if not kernel32.Module32First(snapshot, pointer(current_entry)):
                return
        except:
            # ctypes.ArgumentError: argument 2: <class 'TypeError'>: expected LP_MODULEENTRY32 instance instead of LP_MODULEENTRY32
            # Module32First.argtypes=(<class 'ctypes.c_void_p'>, <class 'scripts.pydbg.system_dll.LP_MODULEENTRY32'>)
            logging.error("Module32First.argtypes=%s" % str(Module32First.argtypes))
            raise

        while 1:
            yield current_entry

            if not kernel32.Module32Next(snapshot, byref(current_entry)):
                break

        # if the above loop is "broken" out of, then this handle leaks.
        self.close_handle(snapshot)


    #####################################################################################################################
    def iterate_processes (self):
        '''
        A simple iterator function that can be used to iterate through all running processes. Yielded objects are of
        type PROCESSENTRY32.

        @see:     enumerate_processes()
        @warning: break-ing out of loops over this routine will cause a handle leak.

        @rtype:  PROCESSENTRY32
        @return: Iterated process entries.
        '''

        self._log("iterate_processes()")

        pe       = PROCESSENTRY32()
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        if not kernel32.Process32First(snapshot, byref(pe)):
            return

        while 1:
            yield pe

            if not kernel32.Process32Next(snapshot, byref(pe)):
                break

        # if the above loop is "broken" out of, then this handle leaks.
        self.close_handle(snapshot)


    #####################################################################################################################
    def iterate_threads (self):
        '''
        A simple iterator function that can be used to iterate through all running processes. Yielded objects are of
        type THREADENTRY32.

        @see:     enumerate_threads()
        @warning: break-ing out of loops over this routine will cause a handle leak.

        @rtype:  THREADENTRY32
        @return: Iterated process entries.
        '''

        self._log("iterate_threads()")

        thread_entry = THREADENTRY32()
        snapshot     = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        if not kernel32.Thread32First(snapshot, byref(thread_entry)):
            return

        while 1:
            if thread_entry.th32OwnerProcessID == self.pid:
                yield thread_entry

            if not kernel32.Thread32Next(snapshot, byref(thread_entry)):
                break

        # if the above loop is "broken" out of, then this handle leaks.
        self.close_handle(snapshot)


    ####################################################################################################################
    def flip_endian (self, dword):
        '''
        Utility function to flip the endianess a given DWORD into raw bytes.

        @type  dword: DWORD
        @param dowrd: DWORD whose endianess to flip

        @rtype:  Raw Bytes
        @return: Converted DWORD in raw bytes.
        '''

        byte1 = chr(dword % 256)
        dword = dword >> 8
        byte2 = chr(dword % 256)
        dword = dword >> 8
        byte3 = chr(dword % 256)
        dword = dword >> 8
        byte4 = chr(dword % 256)

        return "%c%c%c%c" % (byte1, byte2, byte3, byte4)


    ####################################################################################################################
    def flip_endian_dword (self, array_bytes):
        '''
        Utility function to flip the endianess of a given set of raw bytes into a DWORD.

        @type  bytes: Raw Bytes
        @param bytes: Raw bytes whose endianess to flip

        @rtype:  DWORD
        @return: Converted DWORD.
        '''
        # Little-endian, and unsigned long (4 or 8 bytes depending on the platform)
        assert isinstance(array_bytes, six.binary_type)
        if is_64bits:
            word_result = big_integer_type(struct.unpack("<Q", array_bytes)[0])
        else:
            word_result = big_integer_type(struct.unpack("<L", array_bytes)[0])
        return word_result

    ####################################################################################################################
    def unflip_endian_dword (self, word_result):
        '''
        Utility function to do the inverse of flip_endian_dword.

        @type  bytes: DWORD
        @param bytes: Integer

        @rtype:  bytes
        @return: Converted bytes.
        '''
        # Little-endian, and unsigned long (4 or 8 bytes depending on the platform)
        if is_64bits:
            array_bytes = struct.pack("<Q", word_result)
            # FIXME: Check the result then remove.
            word_check = big_integer_type(struct.unpack("<Q", array_bytes)[0])
            assert word_check == word_result
        else:
            raise Exception("unflip_endian_dword: Not implemented yet")
        return array_bytes

    ####################################################################################################################
    def load (self, path_to_file, command_line=None, create_new_console=False, show_window=True):
        '''
        Load the specified executable and optional command line arguments into the debugger.

        @todo: This routines needs to be further tested ... I nomally just attach.

        @type  path_to_file:       String
        @param path_to_file:       Full path to executable to load in debugger
        @type  command_line:       String
        @param command_line:       (Optional, def=None) Command line arguments to pass to debuggee
        @type  create_new_console: Boolean
        @param create_new_console: (Optional, def=False) Create a new console for the debuggee.
        @type  show_window:        Boolean
        @param show_window:        (Optional, def=True) Show / hide the debuggee window.

        @raise pdx: An exception is raised if we are unable to load the specified executable in the debugger.
        '''

        pi = PROCESS_INFORMATION()
        si = STARTUPINFO()

        si.cb = sizeof(si)

        # these flags control the main window display of the debuggee.
        if not show_window:
            si.dwFlags     = 0x1
            si.wShowWindow = 0x0

        # CreateProcess() seems to work better with command line arguments when the path_to_file is passed as NULL.
        if command_line:
            command_line = path_to_file + " " + command_line
            path_to_file = 0

        if self.follow_forks:
            creation_flags = DEBUG_PROCESS
        else:
            creation_flags = DEBUG_ONLY_THIS_PROCESS

        if create_new_console:
            creation_flags |= CREATE_NEW_CONSOLE

        success = kernel32.CreateProcessA(c_char_p(path_to_file),
                                          c_char_p(command_line),
                                          0,
                                          0,
                                          0,
                                          creation_flags,
                                          0,
                                          0,
                                          byref(si),
                                          byref(pi))

        if not success:
            raise pdx("CreateProcess()", True)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        # store the handles we need.
        self.pid       = pi.dwProcessId
        self.root_pid  = self.pid
        self.h_process = pi.hProcess

        # resolve the PEB address.
        selector_entry = LDT_ENTRY()
        thread_context = self.get_thread_context(pi.hThread)

        assert not is_64bits
        if not kernel32.GetThreadSelectorEntry(pi.hThread, thread_context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")
        self._log("AFTER GetThreadSelectorEntry")

        teb  = selector_entry.BaseLow
        teb += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # add this TEB to the internal dictionary.
        self.tebs[pi.dwThreadId] = teb

        self.peb = self.read_process_memory(teb + 0x30, 4)
        self.peb = struct.unpack("<L", self.peb)[0]

        # if the function (CreateProcess) succeeds, be sure to call the CloseHandle function to close the hProcess and
        # hThread handles when you are finished with them. -bill gates
        #
        # we keep the process handle open but don't need the thread handle.
        self.close_handle(pi.hThread)


    ####################################################################################################################
    def open_process (self, pid):
        '''
        Convenience wrapper around OpenProcess().

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        '''

        self.h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        assert self.h_process

        if not self.h_process:
            raise pdx("OpenProcess(%d)" % pid, True)

        self.is_wow64 = wintypes.BOOL()
        a_bool = IsWow64Process(self.h_process, byref(self.is_wow64))

        assert a_bool
        #self._log("open_process pid=%d self.is_wow64=%d" % (pid, 1 if self.is_wow64 else 0))

        return self.h_process


    ####################################################################################################################
    def open_thread (self, thread_id):
        '''
        Convenience wrapper around OpenThread().

        @type  thread_id: Integer
        @param thread_id: ID of thread to obtain handle to

        @raise pdx: An exception is raised on failure.
        '''

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread_id)

        if not h_thread:
            raise pdx("OpenThread(%d)" % thread_id, True)

        return h_thread


    ####################################################################################################################
    def page_guard_clear (self):
        '''
        Clear all debugger-set PAGE_GUARDs from memory. This is useful for suspending memory breakpoints to single step
        past a REP instruction.

        @see: page_guard_restore()

        @rtype:     pydbg
        @return:    Self
        '''

        self._guards_active = False

        for page in self._guarded_pages:
            # make a best effort, let's not crash on failure though.
            try:
                mbi = self.virtual_query(page)
                self.virtual_protect(mbi.BaseAddress, 1, mbi.Protect & ~PAGE_GUARD)
            except:
                pass

        return self.ret_self()


    ####################################################################################################################
    def page_guard_restore (self):
        '''
        Restore all previously cleared debugger-set PAGE_GUARDs from memory. This is useful for suspending memory
        breakpoints to single step past a REP instruction.

        @see: page_guard_clear()

        @rtype:  pydbg
        @return: Self
        '''

        self._guards_active = True

        for page in self._guarded_pages:
            # make a best effort, let's not crash on failure though.
            try:
                mbi = self.virtual_query(page)
                self.virtual_protect(mbi.BaseAddress, 1, mbi.Protect | PAGE_GUARD)
            except:
                pass

        return self.ret_self()


    ####################################################################################################################
    def pid_to_port (self, pid):
        '''
        A helper function that enumerates the IPv4 endpoints for a given process ID.

        @author:    Justin Seitz
        @type  pid: Integer
        @param pid: Process ID to find port information on.

        @raise pdx: An exception is raised on failure
        @rtype:     A list of tuples
        @return:    A list of the protocol, bound address and listening port
        '''

        # local variables to hold all our necessary sweetness.
        listening_port = None
        bound_address  = None
        protocol       = None
        port_list      = []
        tcp_table      = MIB_TCPTABLE_OWNER_PID()
        udp_table      = MIB_UDPTABLE_OWNER_PID()
        init_size      = c_int()

        #### TCP ENDPOINTS

        # the first run is to determine the sizing of the struct.
        size_result = iphlpapi.GetExtendedTcpTable(byref(tcp_table),        \
                                                   byref(init_size),        \
                                                   False,                   \
                                                   AF_INET,                 \
                                                   TCP_TABLE_OWNER_PID_ALL, \
                                                   0)

        if not size_result:
            raise pdx("Couldn't retrieve extended TCP information for PID: %d" % pid, True)

        # retrieve the table of TCP_ROW structs, with the correct size this time.
        reslt       = iphlpapi.GetExtendedTcpTable(byref(tcp_table),        \
                                                   byref(init_size),        \
                                                   False,                   \
                                                   AF_INET,                 \
                                                   TCP_TABLE_OWNER_PID_ALL, \
                                                   0)

        # step through the entries. we only want ports that have the listening flag set. snag the port, address and
        # protocol tuple and add it to port_list.
        for i in range(tcp_table.dwNumEntries):
            if tcp_table.table[i].dwOwningPid == pid:
                if tcp_table.table[i].dwState == MIB_TCP_STATE_LISTEN:
                    listening_port = "%d" % socket.ntohs(tcp_table.table[i].dwLocalPort)
                    bound_address  = socket.inet_ntoa(struct.pack("L", tcp_table.table[i].dwLocalAddr))
                    protocol       = "TCP"

                    port_list.append((protocol, bound_address, listening_port))

        #### UDP ENDPOINTS

        # NOTE: An application can bind a UDP port explicitly to send datagrams, this may not be 100% accurate
        # so we only take into account those UDP sockets which are bound in a manner that allows datagrams on any
        # interface.
        init_size   = c_int(0)
        size_resuld = iphlpapi.GetExtendedUdpTable(byref(udp_table),    \
                                                   byref(init_size),    \
                                                   False,               \
                                                   AF_INET,             \
                                                   UDP_TABLE_OWNER_PID, \
                                                   0)

        # retrieve the table of UDP_ROW structs.
        if not size_result:
            raise pdx("Couldn't retrieve extended UDP information for PID: %d" % pid, True)

        result     = iphlpapi.GetExtendedUdpTable(byref(udp_table),    \
                                                  byref(init_size),    \
                                                  False,               \
                                                  AF_INET,             \
                                                  UDP_TABLE_OWNER_PID, \
                                                  0)

        for i in range(udp_table.dwNumEntries):
            if udp_table.table[i].dwOwningPid == pid:
                # if the local addr is 0 then it is a listening socket accepting datagrams.
                if udp_table.table[i].dwLocalAddr == 0:
                    listening_port = "%d" % socket.ntohs(udp_table.table[i].dwLocalPort)
                    bound_address  = socket.inet_ntoa(struct.pack("L", udp_table.table[i].dwLocalAddr))
                    protocol       = "UDP"

                    port_list.append((protocol, bound_address, listening_port))

        return port_list


    ####################################################################################################################
    def process_restore (self):
        '''
        Restore memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # fetch the current list of threads.
        current_thread_list = self.enumerate_threads()

        # restore the thread context for threads still active.
        for thread_context in self.memory_snapshot_contexts:
            if thread_context.thread_id in current_thread_list:
                self.set_thread_context(thread_context.context, thread_id=thread_context.thread_id)

        # restore all saved memory blocks.
        for memory_block in self.memory_snapshot_blocks:
            try:
                self.write_process_memory(memory_block.mbi.BaseAddress, memory_block.data, memory_block.mbi.RegionSize)
            except pdx as x:
                self._err("-- IGNORING ERROR --")
                self._err("process_restore: " + x.__str__().rstrip("\r\n"))
                pass

        return self.ret_self()


    ####################################################################################################################
    def process_snapshot (self, mem_only=False):
        '''
        Take memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("taking debuggee snapshot")

        do_not_snapshot = [PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS]
        cursor          = 0

        # reset the internal snapshot data structure lists.
        self.memory_snapshot_blocks   = []
        self.memory_snapshot_contexts = []

        if not mem_only:
            # enumerate the running threads and save a copy of their contexts.
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)
    
                self.memory_snapshot_contexts.append(memory_snapshot_context(thread_id, context))
    
                self._log("saving thread context of thread id: %08x" % thread_id)

        # scan through the entire memory range and save a copy of suitable memory blocks.
        while cursor < 0xFFFFFFFF:
            save_block = True

            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            # do not snapshot blocks of memory that match the following characteristics.
            # XXX - might want to drop the MEM_IMAGE check to accomodate for self modifying code.
            if mbi.State != MEM_COMMIT or mbi.Type == MEM_IMAGE:
                save_block = False

            for has_protection in do_not_snapshot:
                if mbi.Protect & has_protection:
                    save_block = False
                    break

            if save_block:
                self._log("Adding %08x +%d to memory snapsnot." % (mbi.BaseAddress, mbi.RegionSize))

                # read the raw bytes from the memory block.
                data = self.read_process_memory(mbi.BaseAddress, mbi.RegionSize)

                self.memory_snapshot_blocks.append(memory_snapshot_block(mbi, data))

            cursor += mbi.RegionSize

        return self.ret_self()


    ####################################################################################################################
    def read (self, address, length):
        '''
        Alias to read_process_memory().

        @see: read_process_memory
        '''

        return self.read_process_memory(address, length)


    ####################################################################################################################
    def read_msr (self, address):
        '''
        Read data from the specified MSR address.

        @see: write_msr

        @type  address: DWORD
        @param address: MSR address to read from.

        @rtype:  tuple
        @return: (read status, msr structure)
        '''

        msr         = SYSDBG_MSR()
        msr.Address = 0x1D9
        msr.Data    = 0xFF  # must initialize this value.

        status = ntdll.NtSystemDebugControl(SysDbgReadMsr,
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            0)

        return (status, msr)


    ####################################################################################################################
    def read_process_memory (self, address, length):
        '''
        Read from the debuggee process space.

        @type  address: DWORD
        @param address: Address to read from.
        @type  length:  Integer
        @param length:  Length, in bytes, of data to read.

        @raise pdx: An exception is raised on failure.
        @rtype:     Raw
        @return:    Read data.
        '''
        assert address

        data         = b""
        read_buf     = create_string_buffer(length)
        count        = c_size_t(0)
        orig_length  = length
        orig_address = address

        # ensure we can read from the requested memory space.WaitForDebugEvent
        _address = address
        _length  = length

        assert self.h_process
        old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)

        while length:
            # self._log("read_process_memory address=%016x length=%d" % (address, length))
            # TODO: Apparently there are default arguments.
            if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
                if not len(data):
                    raise pdx("ReadProcessMemory(%016x, %d, read=%d)" % (address, length, count.value), True)
                else:
                    return data

            data    += read_buf.raw
            length  -= count.value
            address += count.value

        # restore the original page permissions on the target memory region.
        try:
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass

        return data

    ####################################################################################################################
    def resume_all_threads (self):
        '''
        Resume all process threads.

        @see: suspend_all_threads()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        for thread_id in self.enumerate_threads():
            self.resume_thread(thread_id)

        return self.ret_self()


    ####################################################################################################################
    def resume_thread (self, thread_id):
        '''
        Resume the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to resume.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # self._log("resuming thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        # if kernel32.ResumeThread(thread_handle) == -1:


        former_counter = kernel32.ResumeThread(thread_handle)
        if former_counter == -1:
            raise pdx("ResumeThread()", True)

        self.close_handle(thread_handle)

        return former_counter
        # return self.ret_self()


    ####################################################################################################################
    def ret_self (self):
        '''
        This convenience routine exists for internal functions to call and transparently return the correct version of
        self. Specifically, an object in normal mode and a moniker when in client/server mode.

        @return: Client / server safe version of self
        '''

        if self.client_server:
            return "**SELF**"
        else:
            return self


    ####################################################################################################################
    def run (self):
        '''
        Alias for debug_event_loop().

        @see: debug_event_loop()
        '''

        self.debug_event_loop()


    ####################################################################################################################
    def seh_unwind (self, context=None):
        '''
        Unwind the the Structured Exception Handler (SEH) chain of the current or specified thread to the best of our
        abilities. The SEH chain is a simple singly linked list, the head of which is pointed to by fs:0. In cases where
        the SEH chain is corrupted and the handler address points to invalid memory, it will be returned as 0xFFFFFFFF.

        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  List of Tuples
        @return: Naturally ordered list of SEH addresses and handlers.
        '''

        self._log("seh_unwind()")

        selector_entry = LDT_ENTRY()
        seh_chain      = []

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        assert not is_64bits
        if not kernel32.GetThreadSelectorEntry(self.h_thread, context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")
        self._log("AFTER GetThreadSelectorEntry")

        fs_base  = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # determine the head of the current threads SEH chain.
        seh_head = self.read_process_memory(fs_base, 4)
        seh_head = self.flip_endian_dword(seh_head)

        while seh_head != 0xFFFFFFFF:
            try:
                handler = self.read_process_memory(seh_head + 4, 4)
                handler = self.flip_endian_dword(handler)
            except:
                handler = 0xFFFFFFFF

            try:
                seh_head = self.read_process_memory(seh_head, 4)
                seh_head = self.flip_endian_dword(seh_head)
            except:
                seh_head = 0xFFFFFFFF

            seh_chain.append((seh_head, handler))

        return seh_chain


    ####################################################################################################################
    def set_attr (self, attribute, value):
        '''
        Return the value for the specified class attribute. This routine should be used over directly accessing class
        member variables for transparent support across local vs. client/server debugger clients.

        @see: set_attr()

        @type  attribute: String
        @param attribute: Name of attribute to return.
        @type  value:     Mixed
        @param value:     Value to set attribute to.
        '''

        if hasattr(self, attribute):
            setattr(self, attribute, value)


    ####################################################################################################################
    def set_callback (self, exception_code, callback_func):
        '''
        Set a callback for the specified exception (or debug event) code. The prototype of the callback routines is::

            func (pydbg):
                return DBG_CONTINUE     # or other continue status

        You can register callbacks for any exception code or debug event. Look in the source for all event_handler_???
        and exception_handler_??? routines to see which ones have internal processing (internal handlers will still
        pass control to your callback). You can also register a user specified callback that is called on each loop
        iteration from within debug_event_loop(). The callback code is USER_CALLBACK_DEBUG_EVENT and the function
        prototype is::

            func (pydbg)
                return DBG_CONTINUE     # or other continue status

        User callbacks do not / should not access debugger or contextual information.

        @type  exception_code: Long
        @param exception_code: Exception code to establish a callback for
        @type  callback_func:  Function
        @param callback_func:  Function to call when specified exception code is caught.
        '''

        self.callbacks[exception_code] = callback_func


    ####################################################################################################################
    def set_debugger_active (self, enable):
        '''
        Enable or disable the control flag for the main debug event loop. This is a convenience shortcut over set_attr.

        @type  enable: Boolean
        @param enable: Flag controlling the main debug event loop.
        '''

        self._log("set_debugger_active setting debug event loop flag to %s" % enable)
        self.debugger_active = enable


    ####################################################################################################################
    def set_register (self, register, value):
        if is_64bits:
            self.set_register64(register, value)
        else:
            self.set_register32(register, value)

    ####################################################################################################################
    def set_register64(self, register, value):
        #self._log("setting %s to %08x in thread id %d" % (register, value, self.dbg.dwThreadId))

        #register = register.upper()
        register = register[0].upper() + register[1:].lower()
        if register not in (register_name for register_name, register_type in CONTEXT64._fields_):
            raise pdx("invalid register specified:%s" % register)

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        setattr(context, register, value)

        self.set_thread_context(context)

        return self.ret_self()

    ####################################################################################################################
    def set_register32(self, register, value):

        '''
        Set the value of a register in the debuggee within the context of the self.h_thread.

        @type  register: Register
        @param register: One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP
        @type  value:    DWORD
        @param value:    Value to set register to

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        #self._log("setting %s to %08x in thread id %d" % (register, value, self.dbg.dwThreadId))

        register = register.upper()
        if register not in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"):
            raise pdx("invalid register specified")

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        if   register == "EAX": context.Eax = value
        elif register == "EBX": context.Ebx = value
        elif register == "ECX": context.Ecx = value
        elif register == "EDX": context.Edx = value
        elif register == "ESI": context.Esi = value
        elif register == "EDI": context.Edi = value
        elif register == "ESP": context.Esp = value
        elif register == "EBP": context.Ebp = value
        elif register == "EIP": context.Eip = value

        self.set_thread_context(context)

        return self.ret_self()


    ####################################################################################################################
    def set_thread_context (self, context, thread_handle=None, thread_id=0):
        '''
        Convenience wrapper around SetThreadContext(). Can set a thread context via a handle or thread id.

        @type  thread_handle: HANDLE
        @param thread_handle: (Optional) Handle of thread to get context of
        @type  context:       CONTEXT
        @param context:       Context to apply to specified thread
        @type  thread_id:     Integer
        @param thread_id:     (Optional, Def=0) ID of thread to get context of

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # if neither a thread handle or thread id were specified, default to the internal one.
        if not thread_handle and not thread_id:
            h_thread = self.h_thread

        # if a thread handle was not specified, get one from the thread id.
        elif not thread_handle:
            h_thread = self.open_thread(thread_id)

        # use the specified thread handle.
        else:
            h_thread = thread_handle

        if not kernel32.SetThreadContext(h_thread, byref(context)):
            raise pdx("SetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle and thread_id:
            self.close_handle(h_thread)

        return self.ret_self()


    ####################################################################################################################
    def sigint_handler (self, signal_number, stack_frame):
        '''
        Interrupt signal handler. We override the default handler to disable the run flag and exit the main
        debug event loop.

        @type  signal_number:
        @param signal_number:
        @type  stack_frame:
        @param stack_frame:
        '''

        self._log("sigint_handler reset debugger_active")
        self.set_debugger_active(False)


    ####################################################################################################################
    def single_step (self, enable, thread_handle=None):
        '''
        Enable or disable single stepping in the specified thread or self.h_thread if a thread handle is not specified.

        @type  enable:        Bool
        @param enable:        True to enable single stepping, False to disable
        @type  thread_handle: Handle
        @param thread_handle: (Optional, Def=None) Handle of thread to put into single step mode

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        #self._log("single_step(%s)" % enable)

        if not thread_handle:
            thread_handle = self.h_thread

        context = self.get_thread_context(thread_handle)

        if enable:
            # single step already enabled.
            if context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags |= EFLAGS_TRAP
        else:
            # single step already disabled:
            if not context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags = context.EFlags & (0xFFFFFFFFFF ^ EFLAGS_TRAP)

        self.set_thread_context(context, thread_handle=thread_handle)

        return self.ret_self()


    ####################################################################################################################
    def smart_dereference (self, address, print_dots=True, hex_dump=False):
        '''
        "Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII
        or Unicode string. In the absense of a string the printable characters are returned with non-printables
        represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or
        the name of the module it lies in (global data).

        @type  address:    DWORD
        @param address:    Address to smart dereference
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  String
        @return: String of data discovered behind dereference.
        '''

        try:
            mbi = self.virtual_query(address)
        except:
            return "N/A"

        # if the address doesn't point into writable memory (stack or heap), then bail.
        if not mbi.Protect & PAGE_READWRITE:
            return "N/A"

        # if the address does point to writeable memory, ensure it doesn't sit on the PEB or any of the TEBs.
        if mbi.BaseAddress == self.peb or mbi.BaseAddress in self.tebs.values():
            return "N/A"

        try:
            explored = self.read_process_memory(address, self.STRING_EXPLORATON_BUF_SIZE)
        except:
            return "N/A"

        # determine if the write-able address sits in the stack range.
        if self.is_address_on_stack(address):
            location = "stack"

        # otherwise it could be in a module's global section or on the heap.
        else:
            module = self.addr_to_module(address)

            if module:
                location = "%s.data" % module.szModule

            # if the write-able address is not on the stack or in a module range, then we assume it's on the heap.
            # we *could* walk the heap structures to determine for sure, but it's a slow method and this process of
            # elimination works well enough.
            else:
                location = "heap"

        explored_string = self.get_ascii_string(explored)

        if not explored_string:
            explored_string = self.get_unicode_string(explored)

        if not explored_string and hex_dump:
            explored_string = self.hex_dump(explored)

        if not explored_string:
            explored_string = self.get_printable_string(explored, print_dots)

        if hex_dump:
            return "%s --> %s" % (explored_string, location)
        else:
            return "%s (%s)" % (explored_string, location)


    ####################################################################################################################
    def stack_range (self, context=None):
        '''
        Determine the stack range (top and bottom) of the current or specified thread. The desired information is
        located at offsets 4 and 8 from the Thread Environment Block (TEB), which in turn is pointed to by fs:0.

        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  Mixed
        @return: List containing (stack_top, stack_bottom) on success, False otherwise.
        '''

        selector_entry = LDT_ENTRY()

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        assert not is_64bits
        if not kernel32.GetThreadSelectorEntry(self.h_thread, context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")
        self._log("AFTER GetThreadSelectorEntry")

        fs_base  = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # determine the top and bottom of the debuggee's stack.
        stack_top    = self.read_process_memory(fs_base + 4, 4)
        stack_bottom = self.read_process_memory(fs_base + 8, 4)

        stack_top    = self.flip_endian_dword(stack_top)
        stack_bottom = self.flip_endian_dword(stack_bottom)

        return (stack_top, stack_bottom)


    ####################################################################################################################
    def stack_unwind (self, context=None):
        '''
        Unwind the stack to the best of our ability. This function is really only useful if called when EBP is actually
        used as a frame pointer. If it is otherwise being used as a general purpose register then stack unwinding will
        fail immediately.

        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  List
        @return: The current call stack ordered from most recent call backwards.
        '''

        self._log("stack_unwind()")

        selector_entry = LDT_ENTRY()
        call_stack     = []

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        # determine the stack top / bottom.
        (stack_top, stack_bottom) = self.stack_range(context)

        this_frame = context.Ebp

        while this_frame > stack_bottom and this_frame < stack_top:
            # stack frame sanity check: must be DWORD boundary aligned.
            if this_frame & 3:
                break

            try:
                ret_addr = self.read_process_memory(this_frame + 4, 4)
                ret_addr = self.flip_endian_dword(ret_addr)
            except:
                break

            # return address sanity check: return address must live on an executable page.
            try:
                mbi = self.virtual_query(ret_addr)
            except:
                break

            if mbi.Protect not in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
                break

            # add the return address to the call stack.
            call_stack.append(ret_addr)

            # follow the frame pointer to the next frame.
            try:
                next_frame = self.read_process_memory(this_frame, 4)
                next_frame = self.flip_endian_dword(next_frame)
            except:
                break

            # stack frame sanity check: new frame must be at a higher address then the previous frame.
            if next_frame <= this_frame:
                break

            this_frame = next_frame

        return call_stack


    ####################################################################################################################
    def suspend_all_threads (self):
        '''
        Suspend all process threads.

        @see: resume_all_threads()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        for thread_id in self.enumerate_threads():
            self.suspend_thread(thread_id)

        return self.ret_self()


    ####################################################################################################################
    def suspend_thread (self, thread_id):
        '''
        Suspend the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to suspend

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("suspending thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        # if kernel32.SuspendThread(thread_handle) == -1:

        former_counter = kernel32.SuspendThread(thread_handle)
        if former_counter == -1:
            raise pdx("SuspendThread()", True)

        self.close_handle(thread_handle)

        return former_counter
        # return self.ret_self()


    ####################################################################################################################
    def terminate_process (self, exit_code=0, method="terminateprocess"):
        '''
        Terminate the debuggee using the specified method.

        "terminateprocess": Terminate the debuggee by calling TerminateProcess(debuggee_handle).
        "exitprocess":      Terminate the debuggee by setting its current EIP to ExitProcess().

        @type  exit_code: Integer
        @param exit_code: (Optional, def=0) Exit code
        @type  method:    String
        @param method:    (Optonal, def="terminateprocess") Termination method. See __doc__ for more info.

        @raise pdx: An exception is raised on failure.
        '''

        if method.lower().startswith("exitprocess"):
            self.context.Eip = self.func_resolve_debuggee(b"kernel32", b"ExitProcess")
            self.set_thread_context(self.context)

        # fall back to "terminateprocess".
        else:
            if not kernel32.TerminateProcess(self.h_process, exit_code):
                raise pdx("TerminateProcess(%d)" % exit_code, True)


    ####################################################################################################################
    def to_binary (self, number, bit_count=32):
        '''
        Convert a number into a binary string. This is an ugly one liner that I ripped off of some site.

        @see: to_decimal()

        @type  number:    Integer
        @param number:    Number to convert to binary string.
        @type  bit_count: Integer
        @param bit_count: (Optional, Def=32) Number of bits to include in output string.

        @rtype:  String
        @return: Specified integer as a binary string
        '''

        return "".join(map(lambda x:str((number >> x) & 1), range(bit_count -1, -1, -1)))


    ####################################################################################################################
    def to_decimal (self, binary):
        '''
        Convert a binary string into a decimal number.

        @see: to_binary()

        @type  binary: String
        @param binary: Binary string to convert to decimal

        @rtype:  Integer
        @return: Specified binary string as an integer
        '''

        # this is an ugly one liner that I ripped off of some site.
        #return sum(map(lambda x: int(binary[x]) and 2**(len(binary) - x - 1), range(len(binary)-1, -1, -1)))

        # this is much cleaner (thanks cody)
        return int(binary, 2)


    ####################################################################################################################
    def virtual_alloc (self, address, size, alloc_type, protection):
        '''
        Convenience wrapper around VirtualAllocEx()

        @type  address:    DWORD
        @param address:    Desired starting address of region to allocate, can be None
        @type  size:       Integer
        @param size:       Size of memory region to allocate, in bytes
        @type  alloc_type: DWORD
        @param alloc_type: The type of memory allocation (most often MEM_COMMIT)
        @type  protection: DWORD
        @param protection: Memory protection to apply to the specified region

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Base address of the allocated region of pages.
        '''

        if address:
            self._log("VirtualAllocEx(%08x, %d, %08x, %08x)" % (address, size, alloc_type, protection))
        else:
            self._log("VirtualAllocEx(NULL, %d, %08x, %08x)" % (size, alloc_type, protection))

        allocated_address = kernel32.VirtualAllocEx(self.h_process, address, size, alloc_type, protection)

        if not allocated_address:
            raise pdx("VirtualAllocEx(%08x, %d, %08x, %08x)" % (address, size, alloc_type, protection), True)

        return allocated_address


    ####################################################################################################################
    def virtual_free (self, address, size, free_type):
        '''
        Convenience wrapper around VirtualFreeEx()

        @type  address:    DWORD
        @param address:    Pointer to the starting address of the region of memory to be freed
        @type  size:       Integer
        @param size:       Size of memory region to free, in bytes
        @type  free_type:  DWORD
        @param free_type:  The type of free operation

        @raise pdx: An exception is raised on failure.
        '''

        self._log("VirtualFreeEx(%08x, %d, %08x)" % (address, size, free_type))

        if not kernel32.VirtualFreeEx(self.h_process, address, size, free_type):
            raise pdx("VirtualFreeEx(%08x, %d, %08x)" % (address, size, free_type), True)


    ####################################################################################################################
    def virtual_protect (self, base_address, size, protection):
        '''
        Convenience wrapper around VirtualProtectEx()

        @type  base_address: DWORD
        @param base_address: Base address of region of pages whose access protection attributes are to be changed
        @type  size:         Integer
        @param size:         Size of the region whose access protection attributes are to be changed
        @type  protection:   DWORD
        @param protection:   Memory protection to apply to the specified region

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Previous access protection.
        '''

        # self._log("VirtualProtectEx( , 0x%08x, %d, %08x, ,)" % (base_address, size, protection))

        old_protect = c_ulong(0)

        if not kernel32.VirtualProtectEx(self.h_process, base_address, size, protection, byref(old_protect)):
            # The reason for this error "Attempt to access invalid address." could be:
            #  "a very obvious candidate to be your anti-malware software,"
            # https://exceptionshub.com/virtualprotect-and-kernel32-dll-attempt-to-access-invalid-address.html
            raise pdx("VirtualProtectEx(%016x, %d, %08x)" % (base_address, size, protection), True)

        return old_protect.value


    ####################################################################################################################
    def virtual_query (self, address):
        '''
        Convenience wrapper around VirtualQueryEx().

        @type  address: DWORD
        @param address: Address to query

        @raise pdx: An exception is raised on failure.

        @rtype:  MEMORY_BASIC_INFORMATION
        @return: MEMORY_BASIC_INFORMATION
        '''

        mbi = MEMORY_BASIC_INFORMATION()

        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            raise pdx("VirtualQueryEx(%08x)" % address, True)

        return mbi


    ####################################################################################################################
    def win32_error (self, prefix=None):
        '''
        Convenience wrapper around GetLastError() and FormatMessage(). Raises an exception with the relevant error code
        and formatted message.

        @type  prefix: String
        @param prefix: (Optional) String to prefix error message with.

        @raise pdx: An exception is always raised by this routine.
        '''

        error      = c_char_p()
        error_code = kernel32.GetLastError()

        kernel32.FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                None,
                                error_code,
                                0x00000400,     # MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
                                byref(error),
                                0,
                                None)
        if prefix:
            error_message = "%s: %s" % (prefix, error.value)
        else:
            error_message = "GetLastError(): %s" % error.value

        raise pdx(error_message, error_code)


    ####################################################################################################################
    def write (self, address, data, length=0):
        '''
        Alias to write_process_memory().

        @see: write_process_memory
        '''

        return self.write_process_memory(address, data, length)


    ####################################################################################################################
    def write_msr (self, address, data):
        '''
        Write data to the specified MSR address.

        @see: read_msr

        @type  address: DWORD
        @param address: MSR address to write to.
        @type  data:    QWORD
        @param data:    Data to write to MSR address.

        @rtype:  tuple
        @return: (read status, msr structure)
        '''

        msr         = SYSDBG_MSR()
        msr.Address = address
        msr.Data    = data

        status = ntdll.NtSystemDebugControl(SysDbgWriteMsr,
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            0,
                                            0,
                                            0)

        return status


    ####################################################################################################################
    def write_process_memory (self, address, data, length=0):
        '''
        Write to the debuggee process space. Convenience wrapper around WriteProcessMemory(). This routine will
        continuously attempt to write the data requested until it is complete.

        @type  address: DWORD
        @param address: Address to write to
        @type  data:    Raw Bytes
        @param data:    Data to write
        @type  length:  DWORD
        @param length:  (Optional, Def:len(data)) Length of data, in bytes, to write

        @raise pdx: An exception is raised on failure.
        '''

        if is_64bits:
            count = c_ulonglong(0)
        else:
            count = c_ulong(0)

        # if the optional data length parameter was omitted, calculate the length ourselves.
        if not length:
            length = len(data)

        # ensure we can write to the requested memory space.
        _address = address
        _length  = length
        old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)

        while length:
            c_data = c_char_p(data[count.value:])

            if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
                raise pdx("WriteProcessMemory(%016x, ..., %d)" % (address, length), True)

            length  -= count.value
            address += count.value

        # restore the original page permissions on the target memory region.
        self.virtual_protect(_address, _length, old_protect)


    def get_bytes_string(self, address):
        if address == 0:
            return b"<NULL>"
        buffer  = b""
        offset  = 0
        while 1:
            byte = self.read_process_memory(address + offset, 1 )
            if byte != b"\x00":
                buffer  += byte
                offset  += 1
                continue
            else:
                break
        assert offset == len(buffer)
        return buffer

    def get_bytes_size(self, address, number_bytes):
        buffer = self.read_process_memory(address, number_bytes)
        return buffer

    # The input buffer is a Windows UTF-16 string.
    def get_unicode_string(self, address):
        if address == 0:
            return u"<NULL>"
        buffer = b""
        offset = 0
        while 1:
            byte = self.read_process_memory(address + offset, 2)
            assert isinstance(byte, six.binary_type)
            if byte == b"\x00\x00":
                return buffer.decode("utf-16")
            buffer += byte
            offset += 2

    def get_text_string(self, address):
        if sys.version_info >= (3,):
            return self.get_unicode_string(address)
        else:
            return self.get_bytes_string(address)

    def get_long(self, address):
        ret_bytes = self.read_process_memory(address, 4)
        assert len(ret_bytes) == 4
        assert isinstance(ret_bytes, six.binary_type)
        return big_integer_type(struct.unpack("<L", ret_bytes)[0])

    def get_longlong(self, address):
        ret_bytes = self.read_process_memory(address, 8)
        assert len(ret_bytes) == 8
        assert isinstance(ret_bytes, six.binary_type)
        return big_integer_type(struct.unpack("<Q", ret_bytes)[0])

    def get_pointer(self, address):
        ret_bytes = self.read_process_memory(address, sizeof(PVOID))
        assert len(ret_bytes) == sizeof(PVOID)
        assert isinstance(ret_bytes, six.binary_type)
        return big_integer_type(struct.unpack("<Q", ret_bytes)[0])

