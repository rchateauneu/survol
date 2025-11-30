#!/usr/sbin/dtrace -s

/*
https://techcommunity.microsoft.com/t5/windows-os-platform-blog/dtrace-on-windows/ba-p/362902
Summarize timer set/cancel program for 3 seconds:

dtrace -Fn "tick-3sec { exit(0);} syscall::Nt*Timer*:entry { @[probefunc, execname, pid] = count();}"

dtrace: description 'tick-3sec ' matched 14 probes
CPU FUNCTION
  1 | :tick-3sec

  NtCreateTimer firefox.exe 5524 1
*/

tick-5sec {
	exit(0);
}

syscall::Nt*Timer*:entry {
	@[probefunc, execname, pid] = count();
}