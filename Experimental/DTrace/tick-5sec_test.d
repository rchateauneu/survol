#!/usr/sbin/dtrace -s

/*
https://techcommunity.microsoft.com/t5/windows-os-platform-blog/dtrace-on-windows/ba-p/362902
Syscall summary by program for 5 seconds

dtrace -Fn "tick-5sec { exit(0);} syscall:::entry{ @num[pid,execname] = count();} "

dtrace: script 'tick-5sec_test.d' matched 487 probes
CPU     ID                    FUNCTION:NAME
  4   3298                       :tick-5sec

      896  chrome.exe                                                        1
*/

tick-5sec {
	exit(0);
}

syscall:::entry {
	@num[pid,execname] = count();
}