import ctypes

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
	# TODO: Check endianness: Should zeroes come first ?
	# TODO: THIS IS ALL WRONG !!
	# All x86 and x86-64 machines (which is just an extension to x86) are little-endian.
	# "import struct; print 'little' if ord(struct.pack('L', 1)[0]) else 'big'"
	# 0xA0B70708 stored in the order : 08 07 B7 A0
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


class struct_FixedString(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		# Length truncates string. Should be variable...
		('text', ctypes.c_uint8 * 20),
	]
	_regex_ = {
		'text': "[a-zA-Z_0-9]{6,20}",
	}

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

lstStructs = [ struct_time_t, struct_FixedString, struct_Url,
			   struct_iobuf, struct_stat, struct_addrinfo ]
lstStructs = [  ]

