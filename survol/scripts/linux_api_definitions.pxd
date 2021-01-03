
# https://notes-on-cython.readthedocs.io/en/latest/function_declarations.html
# https://cython.readthedocs.io/en/latest/src/tutorial/pure.html

cdef (list, int) parse_call_arguments(int str_args, int ix_start)

class BatchLetCore:
    cdef _init_after_pid(self, one_line, int idx_start):
