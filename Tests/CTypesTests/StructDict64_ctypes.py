
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
	# print("PointedType:"+str(tp))
	tpNam = tp.__name__
	if tpNam == "c_void_p":
		return "void"
	if tpNam.startswith("LP_c_") or tpNam.startswith("LP_4_") or tpNam.startswith("LP_8_"):
		# print("TRUE:"+tpNam[ 5: ])
		return tpNam[ 5: ]

	# print("FALSE")
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

class struct_time_t(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('tm_sec',   ctypes.c_int32), # 0..61
		('tm_min',   ctypes.c_int32), # 0..59
		('tm_hour',  ctypes.c_int32), # 0..23
		('tm_mday',  ctypes.c_int32), # 1..31
		('tm_mon',   ctypes.c_int32), # 0..11
		('tm_year',  ctypes.c_int32), # since 1900
		('tm_wday',  ctypes.c_int32), # 0..6
		('tm_yday',  ctypes.c_int32), # 0..365
		('tm_isdst', ctypes.c_int32),
	]
	# Check endianness: Should zeroes come first ?
	_regex_ = {
		'tm_sec': "\\x00\\x00\\x00[\\x00-\\x3D]", # 0 .. 61
		'tm_min': "\\x00\\x00\\x00[\\x00-\\x3B]", # 0 .. 59
		'tm_hour': "\\x00\\x00\\x00[\\x00-\\x17]", # 0 .. 23
		'tm_mday': "\\x00\\x00\\x00[\\x01-\\x1F]", # 1 .. 31
		'tm_mon': "\\x00\\x00\\x00[\\x00-\\x0B]", # 0 .. 11
		'tm_year': "|".join("\\0x%08x" % i for i in range(0,255)),
		#	On essaie avec 2016 = 1900 + 116 = 1900 + 64 + 32 + 16 + 4 = 1900 + 0x74
		'tm_year': "\\x00\\x00\\x00\\x6C", # Why 2008 ??
		#	'tm_year': "\\x00\\x00\\x00[\\x00-\\xFF]", # 0 .. 255 years should be alright from 1900.
		'tm_wday': "\\x00\\x00\\x00[\\x00-\\x06]", # 0 .. 6
		#	# Could be expressed with a shorter range.
		#	'tm_yday': "|".join("\\0x%08x" % i for i in range(0,365)),
	}


class struct_SAFEARRAYBOUND(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('cElements', ctypes.c_uint32),
		('lLbound',   ctypes.c_int32),
	]


class struct_SAFEARRAY(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('cDims',          ctypes.c_uint16),  # RangeValue(0,5)
		('fFeatures',      ctypes.c_uint16), # RangeValue(0,0x1000),ExactMatch(0xF008)
		('cbElements',     ctypes.c_uint32),
		('cLocks',         ctypes.c_int32),  # RangeValue(0,999)
		('pvData',         POINTER_T(None)),
		('rgsabound',      struct_SAFEARRAYBOUND * 3),
	]
	_regex_ = {
		# This is a very long regular expression but not choice as there are no range of short ints.
		# In reality not all values can occur.
		'fFeatures': "|".join("\\0x%04x" % i for i in range(0,256*16+1))+"|\\0xF008", # RangeValue(0,0x1000),ExactMatch(0xF008)
	}

class struct_FixedString(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		# Length truncates string. Should be variable...
		('text', ctypes.c_uint8 * 20),
	]
	_regex_ = {
		'text': "[a-zA-Z_0-9]{6,20}",
	}

# Ca ne selectionne rien.
class struct_Url(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		# Length truncates string. Should be variable...
		('url', ctypes.c_uint8 * 20),
	]
	_regex_ = {
		'url': "http://[a-zA-Z_0-9\.]{6,20}",
	}



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

class struct_stat(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('path',   POINTER_T(ctypes.c_char)),
		('buffer', POINTER_T(None)),
	]

class struct_addrinfo(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('ai_flags',     ctypes.c_int32),
		('ai_family',    ctypes.c_int32),
		('ai_socktype',  ctypes.c_int32),
		('ai_protocol',  ctypes.c_int32),
		('ai_addrlen',   ctypes.c_int64), # In fact, size_t
		('ai_canonname', POINTER_T(ctypes.c_char)),
		('ai_addr',      POINTER_T(None)),
		('ai_next',      POINTER_T(None)),
	]


# MQ
# http://usuaris.tinet.cat/jpmiguez/mqv8/cmqc.h



# Tib

# typedef enum
# {
# TIBRV_OK                        = 0,
# TIBRV_IPM_ONLY                  = 117
# } tibrv_status;


# class TibrvStatus
# {
# tibrv_status _status;
# };

# class TibrvDispatchable
# {
# };

# typedef tibrv_u32               tibrvId;

# typedef tibrvId                 tibrvEvent;
# typedef tibrvEvent              tibrvPollEvent;
# typedef tibrvId                 tibrvQueue;
# typedef tibrvQueue              tibrvPollQueue;
# typedef tibrvId                 tibrvTransport;
# typedef tibrvId                 tibrvQueueGroup;
# typedef tibrvId                 tibrvDispatchable;
# typedef tibrvId                 tibrvDispatcher;

# class TibrvQueue : public TibrvDispatchable
# {
# tibrvQueue _queue;
# TibrvQueueOnComplete* _completeCallback;
# void* _closure;
# };

# class TibrvQueueOnComplete
# {
# }

# class TibrvQueueGroup : public TibrvDispatchable
# {
# tibrvQueueGroup  _queueGroup;
# };

# class TibrvDispatcher
# {
# tibrvDispatcher    _dispatcher;
# TibrvDispatchable* _dispatchable;
# };


# class TibrvTransport
# {
# tibrvTransport  _transport;
# };

# class TibrvProcessTransport : public TibrvTransport
# {
# };

# class TibrvNetTransport : public TibrvTransport
# {
# };

# class TibrvVcTransport : public TibrvTransport
# {
# };

# class TibrvEvent
# {
# tibrvEvent      _event;
# TibrvCallback*  _callback;
# TibrvVectorCallback* _vectorCallback;
# TibrvEventOnComplete* _completeCallback;
# void *          _closure;
# TibrvQueue*     _queue;
# tibrvEventType  _objType;
# };


# class TibrvListener : public TibrvEvent
# {
# TibrvTransport* _transport;
# };

# class TibrvVectorListener : public TibrvEvent
# {
# TibrvTransport* _transport;
# };

# class TibrvTimer : public TibrvEvent
# {
# };

# class TibrvEventOnComplete
# {
# };

# class TibrvCallback
# {
# };

# # Mais est ce que la VTBL est prise en compte ???

# class TibrvMsgCallback : public TibrvCallback
# {
# };

# class TibrvTimerCallback : public TibrvCallback
# {
# };

# class TibrvIOCallback : public TibrvCallback
# {
# };

# typedef struct tibrvMsgField
# {
# const char*                 name;
# tibrv_u32                   size;
# tibrv_u32                   count;
# tibrvLocalData              data;
# tibrv_u16                   id;
# tibrv_u8                    type;
# } tibrvMsgField;


# class TibrvMsgField : public tibrvMsgField
# {
# };

# typedef struct tibrvMsgDateTime
# {
# tibrv_i64                   sec;
# tibrv_u32                   nsec;
# } tibrvMsgDateTime;

# class TibrvMsgDateTime : public tibrvMsgDateTime
# {

# };

# typedef struct __tibrvMsg*      tibrvMsg;

# class TibrvMsg
# {
# tibrvMsg     _msg;
# tibrv_bool   _detached;
# tibrv_status _status;
# tibrv_u32    _initsize;
# TibrvEvent*  _event;

# };


# Chercher aussi une chaine de la forme "1.2.3.4"


lstStructs = [ struct_time_t, struct_SAFEARRAY, struct_SAFEARRAYBOUND, struct_FixedString, struct_Url,
			   struct_iobuf, struct_stat, struct_addrinfo ]
lstStructs = [ struct_stat ]


#####  VOIR AUSSI LE CONTENU DEtibrv/types.h !!!!

##########################################################################	 
	 
