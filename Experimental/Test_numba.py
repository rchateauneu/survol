import time
import datetime

from numba import jit



def loop_simple_a(the_str, the_int):
    return the_str + the_str + str(the_int)


@jit(nopython=True)
def loop_simple_b(the_str, the_int):
    return the_str + the_str[:-1] + str(the_int)



def test(the_func):
    start_time = time.time()
    ix = 1000000
    while ix > 0:
        the_func("abc", 123+ix)
        ix -= 1

    end_time = time.time()
    print("Time:", end_time - start_time)


test(loop_simple_a)
test(loop_simple_b)
test(loop_simple_a)
test(loop_simple_b)
test(loop_simple_a)
test(loop_simple_b)
