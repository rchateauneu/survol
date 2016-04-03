
import sys
import ctypes
from six.moves import builtins


# required to access _ctypes
import _ctypes

ctypes._pointer_t_type_cache64 = {}
def POINTER_64_T(pointee):
	# a pointer should have the same length as LONG
	fake_ptr_base_type = ctypes.c_uint64
	# specific case for c_void_p
	if pointee is None: # VOID pointer type. c_void_p.
		pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
		clsname = 'c_void'
	else:
		clsname = pointee.__name__
	if clsname in ctypes._pointer_t_type_cache64:
		return ctypes._pointer_t_type_cache64[clsname]
	# make template
	class _T(_ctypes._SimpleCData,):
		# https://docs.python.org/2/library/ctypes.html?highlight=structure
		# AttributeError: class must define a '_type_' attribute which must be
		# a single character string containing one of 'cbBhHiIlLdfuzZqQPXOv?g'.
		# http://svn.python.org/projects/python/branches/py3k/Modules/_ctypes/cfield.c
		# _type_ = 'L'
		_type_ = 'Q' # { 'Q', Q_set, Q_get, &ffi_type_uint64, Q_set_sw, Q_get_sw},
		_subtype_ = pointee
		def _sub_addr_(self):
			return self.value
		def __repr__(self):
			return '%s(%d)'%(clsname, self.value)
		def contents(self):
			raise TypeError('This is not a ctypes pointer.')
		def __init__(self, **args):
			raise TypeError('This is not a ctypes pointer. It is not instanciable.')
	_class = type('LP_%d_%s'%(8, clsname), (_T,),{})
	ctypes._pointer_t_type_cache64[clsname] = _class
	return _class

ctypes._pointer_t_type_cache32 = {}
def POINTER_32_T(pointee):
	# a pointer should have the same length as LONG
	fake_ptr_base_type = ctypes.c_uint32
	# specific case for c_void_p
	if pointee is None: # VOID pointer type. c_void_p.
		pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
		clsname = 'c_void'
	else:
		clsname = pointee.__name__
	if clsname in ctypes._pointer_t_type_cache32:
		return ctypes._pointer_t_type_cache32[clsname]
	# make template
	class _T(_ctypes._SimpleCData,):
		_type_ = 'L'
		_subtype_ = pointee
		def _sub_addr_(self):
			return self.value
		def __repr__(self):
			return '%s(%d)'%(clsname, self.value)
		def contents(self):
			raise TypeError('This is not a ctypes pointer.')
		def __init__(self, **args):
			raise TypeError('This is not a ctypes pointer. It is not instanciable.')
	_class = type('LP_%d_%s'%(4, clsname), (_T,),{})
	ctypes._pointer_t_type_cache32[clsname] = _class
	return _class

c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
	c_long_double_t = ctypes.c_longdouble
else:
	c_long_double_t = ctypes.c_ubyte*16


# These structs are made to be applied to 32bits or 64 bits processes.
iPtr64Platform = ctypes.sizeof(ctypes.c_void_p) == 8
if hasattr(builtins, "CTYPES_POINTER_TARGET_64"):
	isPtr64Target = builtins.CTYPES_POINTER_TARGET_64
else:
	# This should not happen, although we have a backup solution.
	exit(0)
	isPtr64Target = iPtr64Platform

if isPtr64Target == iPtr64Platform:
	POINTER_T = ctypes.POINTER
else:
	if isPtr64Target:
		POINTER_T = POINTER_64_T
	else:
		POINTER_T = POINTER_32_T

#print("iPtr64Platform=%d isPtr64Target=%d" % ( iPtr64Platform, isPtr64Target ) )
#print("Pointer size:%d" % ctypes.sizeof(POINTER_T(None)) )
#print("ctypes.c_uint8 size:%d" % ctypes.sizeof(ctypes.c_uint8) )
#print("ctypes.c_uint64 size:%d" % ctypes.sizeof(ctypes.c_uint64) )
#print("POINTER_64_T size:%d" % ctypes.sizeof(POINTER_64_T(None)) )
#print("POINTER_32_T size:%d" % ctypes.sizeof(POINTER_32_T(None)) )
#print("POINTER_32_T =%s" % str(dir(POINTER_32_T(None))) )
# exit(0)

# Return the pointed type if this is a pointer, otherwise None.
def PointedType(tp):
	tpNam = tp.__name__

	if tpNam.startswith("LP_"):
		if tpNam.startswith("LP_c_") or tpNam.startswith("LP_4_") or tpNam.startswith("LP_8_"):
			# print("TRUE:"+tpNam[ 5: ])
			return tpNam[ 5: ]
		return None

	if tpNam == "c_void_p":
		return "void"

	return None

def PointerSize():
	if isPtr64Target == iPtr64Platform:
		return ctypes.sizeof(ctypes.c_void_p)
	else:
		if isPtr64Target:
			return 8
		else:
			return 4



################################################################################

lstStructs = [  ]


if sys.platform == "win32":
	import CTypesStructs_Windows
	lstStructs.extend( CTypesStructs_Windows.lstStructs )
else:
	import CTypesStructs_Linux
	lstStructs.extend( CTypesStructs_Linux.lstStructs )

if False:
	import CTypesStructs_Tibco
	lstStructs.extend( CTypesStructs_Tibco.lstStructs )

	import CTypesStructs_MQ
	lstStructs.extend( CTypesStructs_MQ.lstStructs )


##########################################################################
	 
