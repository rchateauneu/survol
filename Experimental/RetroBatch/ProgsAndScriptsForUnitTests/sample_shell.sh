#!/usr/bin/bash

# Different steps.

# $ ltrace -tt -T -f -S -s 200 TestProgs/sample_shell.sh 2>&1 | tee UnitTests/sample_shell.ltrace.log
# "TestProgs/sample_shell.sh" is not an ELF file
# 
# $ strace TestProgs/sample_shell.sh
# execve("TestProgs/sample_shell.sh", ["TestProgs/sample_shell.sh"], [/* 34 vars */]) = -1 ENOEXEC (Exec format error)
# write(2, "strace: exec: Exec format error\n", 32strace: exec: Exec format error) = 32
# exit_group(1)                           = ?
# +++ exited with 1 +++

ls
pwd
ps -ef | wc

cat $0
