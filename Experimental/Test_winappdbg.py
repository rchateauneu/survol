# https://winappdbg.readthedocs.io/en/latest/Instrumentation.html
# Attach to process:
# https://parsiya.net/blog/2017-11-09-winappdbg-part-1-basics/#06-attach-to-process-by-name
# Debug.attach(pid)
# https://parsiya.net/blog/2017-11-11-winappdbg-part-2-function-hooking-and-others/#apihooks

# TODO: The goal is to hook functions calls of a process,
# ie functionally do the same as strace.