import ctypes
import CTypesStructs
from CTypesStructs import POINTER_T


class struct_iobuf(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('_ptr',      POINTER_T(ctypes.c_char)),
		('_cnt',      ctypes.c_int32),
		('_base',     POINTER_T(ctypes.c_char)),
		('_flag',     ctypes.c_int32),
		('_file',     ctypes.c_int32),
		('_charbuf',  ctypes.c_int32),
		('_bufsiz',   ctypes.c_int32),
		('_tmpfname', POINTER_T(ctypes.c_char)),
	]


lstStructs = [ struct_iobuf ]
lstStructs = [ ]
