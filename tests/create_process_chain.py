import os
import sys
import time
import subprocess

try:
    depth = int(sys.argv[1])
except IndexError:
    depth = 3

sys.stdout.write("%d %d\n" % (depth, os.getpid()))
sys.stdout.flush()

if depth > 0:
    sys.stderr.write("About to start depth=%d\n" % depth)
    sys.stderr.flush()
    proc = subprocess.call([sys.executable, '-c', 'import create_process_chain', str(depth - 1)])
else:
    sys.stderr.write("This is the end")
    sys.stderr.flush()
    time.sleep(10)