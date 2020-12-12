#!/usr/bin/env python

# This simulation script behaves like vmstat but with fake numbers.
# It is made to test sources_types/Linux/events_generator_vmstat.py on Windows.

import sys
import time

def _print_header():
    print(
"""procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st""")


def _print_one_line():
    print(
" 0  0 188160 342936 121352 1379096    0    0     1    45    1    1  1  1 97  0  0"
    )

sys.stdout.write("START " + __file__)
sys.stderr.write("START " + __file__)

_print_header()
_print_one_line()
if len(sys.argv) > 1:
    delay = int(sys.argv[1])
    while True:
        sys.stdout.write("LOOP " + __file__)
        sys.stderr.write("LOOP " + __file__)
        time.sleep(delay)
        _print_one_line()

