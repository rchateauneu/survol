-D Run tracer process as a detached grandchild, not as parent of the tracee.  This reduces the visible effect of strace by  keeping
      the tracee a direct child of the calling process.
-y    Print paths associated with file descriptor arguments.

-yy   Print ip:port pairs associated with socket file descriptors.
-e expr     A qualifying expression which modifies which events to trace or how to trace them.  The format of the expression is:

            [qualifier=][!]value1[,value2]...

      where  qualifier is one of trace, abbrev, verbose, raw, signal, read, or write and value is a qualifier-dependent symbol or num‐
      ber.  The default qualifier is trace.  Using an exclamation mark negates the set of values.  For example, -e open  means  liter‐
      ally -e trace=open which in turn means trace only the open system call.  By contrast, -e trace=!open means to trace every system
      call except open.  In addition, the special values all and none have the obvious meanings.
      Note that some shells use the exclamation point for history expansion even inside quoted arguments.  If so, you must escape  the
      exclamation point with a backslash.

-e trace=set
      Trace  only  the  specified  set of system calls.  The -c option is useful for determining which system calls might be useful to
      trace.  For example, trace=open,close,read,write means to only trace those four system calls.  Be careful when making inferences
      about the user/kernel boundary if only a subset of system calls are being monitored.  The default is trace=all.
-e trace=file
      Trace   all  system  calls  which  take  a  file  name  as  an  argument.   You  can  think  of  this  as  an  abbreviation  for
      -e trace=open,stat,chmod,unlink,...  which is useful to seeing what files the process is referencing.   Furthermore,  using  the
      abbreviation  will  ensure  that  you don't accidentally forget to include a call like lstat in the list.  Betchya woulda forgot
      that one.

-e trace=process Trace all system calls which involve process management.  
      This is useful for watching the  fork,  wait,  and  exec  steps  of  a process.  
-e trace=network Trace all the network related system calls.  
-e trace=signal Trace all signal related system calls.  
-e trace=ipc Trace all IPC related system calls.  
-e trace=desc Trace all file descriptor related system calls.  
-e trace=memory Trace all memory mapping related system calls.  

-o filename Write  the  trace  output  to the file filename rather than to stderr.  Use filename.pid if -ff is used.  If the argument begins
      with '|' or with '!' then the rest of the argument is treated as a command and all output is piped to it.   This  is  convenient
      for piping the debugging output to a program without affecting the redirections of executed programs.

-O overhead Set  the  overhead  for  tracing system calls to overhead microseconds.  This is useful for overriding the default heuristic for
      guessing how much time is spent in mere measuring when timing system calls using the -c option.  The accuracy of  the  heuristic
      can  be  gauged  by timing a given program run without tracing (using time(1)) and comparing the accumulated system call time to
      the total produced using -c.

-p pid      Attach to the process with the process ID pid and begin tracing.  The trace may be terminated at any time by a  keyboard  inter‐
      rupt  signal  (CTRL-C).   strace will respond by detaching itself from the traced process(es) leaving it (them) to continue run‐
      ning.  Multiple -p options can be used to attach to many processes.  -p "`pidof PROG`" syntax is supported.



strace
