import ctypes
import ctypes_scanner
from ctypes_scanner import POINTER_T

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
		'tm_sec': "[\\x00-\\x3D]\\x00\\x00\\x00", # 0 .. 61
		'tm_min': "[\\x00-\\xFF]\\x00\\x00\\x00", # 0 .. 59
		'tm_hour': "[\\x00-\\x17]\\x00\\x00\\x00", # 0 .. 23
		'tm_mday': "[\\x01-\\x1F]\\x00\\x00\\x00", # 1 .. 31
		'tm_mon': "[\\x00-\\x0B]\\x00\\x00\\x00", # 0 .. 11
		###### 'tm_year': "[\\x00-\\xFF]\\x00\\x00\\x00", # 0 .. 255 years, enough from 1900.
		'tm_year': "[\\x5A-\\x82]\\x00\\x00\\x00", # 1990-2030 years, from 1900: 90-130 => 0x5A - 0x82
		'tm_wday': "[\\x00-\\x06]\\x00\\x00\\x00", # 0 .. 6
		######	# Could be expressed with a shorter range.
		######	'tm_yday': "|".join("\\0x%08x" % i for i in range(0,365)),
		'tm_isdst': "[\\x00-\\x01]\\x00\\x00\\x00", # 0 .. 1
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

#define APR_PROTO_TCP       6 = 0x06
#define APR_PROTO_UDP      17 = 0x11
#define APR_PROTO_SCTP    132 = 0x84

# SOCK_STREAM 1	 Sequenced, reliable, connection-based byte streams.
# SOCK_DGRAM 2	 Connectionless, unreliable datagrams of fixed maximum length.
# SOCK_RAW 3	 Raw protocol interface.
# SOCK_RDM 4	 Reliably-delivered messages.
# SOCK_SEQPACKET 5 Sequenced, reliable, connection-based, datagrams of fixed maximum length. 
# SOCK_DCCP 6 Datagram Congestion Control Protocol.
# SOCK_PACKET 10 Linux specific way of getting packets at the dev level.  For writing rarp and other similar things on the user level.
#
# NOT YET.
# OR Flags in type parameter of socket and socketpair used for flags parameter of paccept.
#
# SOCK_CLOEXEC 02000000 Atomically set close-on-exec flag for the new descriptor(s).
# SOCK_NONBLOCK 00004000 Atomically mark descriptor(s) as non-blocking.

# Linux
# struct addrinfo
# {
#   int ai_flags;			/* Input flags.  */
#   int ai_family;		/* Protocol family for socket.  */
#   int ai_socktype;		/* Socket type.  */
#   int ai_protocol;		/* Protocol for socket.  */
#   socklen_t ai_addrlen;		/* Length of socket address.  */
#   struct sockaddr *ai_addr;	/* Socket address for socket.  */
#   char *ai_canonname;		/* Canonical name for service location.  */
#   struct addrinfo *ai_next;	/* Pointer to next in list.  */
# };

class struct_addrinfo(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('ai_flags',     ctypes.c_int32), # AI_PASSIVE
		('ai_family',    ctypes.c_int32), # AF_PROTO_TCP
		('ai_socktype',  ctypes.c_int32), # SOCK_DGRAM
		('ai_protocol',  ctypes.c_int32), # 0
		# ('ai_addrlen',   ctypes.c_int64), # In fact, size_t
		('ai_addrlen',   ctypes.c_int32), # In fact, size_t
		('ai_canonname', POINTER_T(ctypes.c_char)),
		('ai_addr',      POINTER_T(None)),
		('ai_next',      POINTER_T(None)),
	]
	_regex_ = {
		'ai_family': "[\\x00\\x06\\x11\\x84]\\x00\\x00\\x00",
		'ai_socktype': "[\\x01-\\x06\\x0A]\\x00\\x00\\x00",
		'ai_addrlen': "[\\x00-\\x0F][\\x00-\\xFF]\\x00\\x00", # Should not be very big.
	}



lstStructs = [ struct_time_t, struct_FixedString, struct_Url ]
lstStructs = [ struct_addrinfo, struct_time_t ]
ctypes_scanner.DoAll(lstStructs)
