import os
import sys

res = 0
for idx in range(100):
    res += idx

res += os.getpid()

sys.stdout.write("res=%d\n"%res)
