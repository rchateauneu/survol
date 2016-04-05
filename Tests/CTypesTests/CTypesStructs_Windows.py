import ctypes
import CTypesStructs
from CTypesStructs import POINTER_T

# TODO: Structure DEVMODE

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

class struct_IP_ADDRESS_STRING(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('String', ctypes.c_uint8 * 16),
	]
	# Probleme: Ca doit faire moins de 16 caracteres.
	# TODO: After that, we could add an extra validation on the numbers.
	_regex_ = {
		# 'String': "\d+\.\d+\.\d+\.\d+",
		'String': "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
	}


# Rien de concluant pour cette struct mais de toute facon je ne sais meme pas si un element doit apparaitre.
# Il faut donc trouver un type de donnees dont on soit sur qu il existe.
class struct_DISPLAY_DEVICE(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('cb',           ctypes.c_uint32),  # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		('DeviceName',   ctypes.c_uint8 * 32),
		('DeviceString', ctypes.c_uint8 * 128),
		('StateFlags',   ctypes.c_uint32),
		('DeviceID',     ctypes.c_uint8 * 128),
		('DeviceKey',    ctypes.c_uint8 * 128),
	]
	# At least two chars for most fields.
	_regex_ = {
		# All x86 and x86-64 machines (which is just an extension to x86) are little-endian.
		# "import struct; print 'little' if ord(struct.pack('L', 1)[0]) else 'big'"
		# 0xA0B70708 stored in the order : 08 07 B7 A0
		# 'cb': r"\xA8\x01\x00\x00]", # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		# 'cb': r"\xA8\x01\x00\x00", # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		# 'cb': r"...\x00", # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		# 'cb': r"..\x00\x00", # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		'cb': r".\x01\x00\x00", # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		# 'cb': r"....", # size of DISPLAY_DEVICE = 424 bytes = 0x01A8.
		'DeviceName'  : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\.]{30}",
		'DeviceString': "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{126}",
		'DeviceID'    : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{126}",
		'DeviceKey'   : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{126}",
	}



lstStructs = [ struct_SAFEARRAY, struct_SAFEARRAYBOUND, struct_IP_ADDRESS_STRING, struct_DISPLAY_DEVICE ]
lstStructs = [ struct_IP_ADDRESS_STRING ]
