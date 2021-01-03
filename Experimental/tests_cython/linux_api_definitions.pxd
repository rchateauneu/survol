
# https://notes-on-cython.readthedocs.io/en/latest/function_declarations.html
# https://cython.readthedocs.io/en/latest/src/tutorial/pure.html

# Beware: It seems that functions which are declared here,
# are sometimes not visible by Python code, in some circumstances.

# cdef (list, int) parse_call_arguments(int str_args, int ix_start)
#cpdef tuple parse_call_arguments(str_args, int ix_start)

#cdef class BatchLetCore:
#    cdef _init_after_pid(self, one_line, int idx_start)
