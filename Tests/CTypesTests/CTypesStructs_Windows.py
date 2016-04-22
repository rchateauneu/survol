import ctypes
import ctypes_scanner
from ctypes_scanner import POINTER_T

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

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms684225%28v=vs.85%29.aspx
# typedef struct tagMODULEENTRY32 {
#   DWORD   dwSize;
#   DWORD   th32ModuleID;
#   DWORD   th32ProcessID;
#   DWORD   GlblcntUsage;
#   DWORD   ProccntUsage;
#   BYTE    *modBaseAddr;
#   DWORD   modBaseSize;
#   HMODULE hModule;
#   TCHAR   szModule[MAX_MODULE_NAME32 + 1];
#   TCHAR   szExePath[MAX_PATH];
# } MODULEENTRY32, *PMODULEENTRY32;


# Maybe in winappdbg
MAX_MODULE_NAME32 = 255
MAX_PATH = 260

class struct_MODULEENTRY32(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('dwSize',         ctypes.c_uint32),
		('th32ModuleID',   ctypes.c_uint32),
		('th32ProcessID',  ctypes.c_uint32),
		('GlblcntUsage',   ctypes.c_uint32),
		('ProccntUsage',   ctypes.c_uint32),
		('modBaseAddr',    POINTER_T(ctypes.c_uint8)),
		('modBaseSize',    ctypes.c_uint32),
		('hModule',        POINTER_T(None)),
		('szModule',       ctypes.c_uint8 * (MAX_MODULE_NAME32 + 1) ),
		('szExePath',      ctypes.c_uint8 * MAX_PATH),
	]
	# At least two chars for most fields.
	_regex_ = {
		'szModule'  : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\.]{254}",
		'szExePath' : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{258}",
	}


# Recursive structure;
# http://stackoverflow.com/questions/1228158/python-ctype-recursive-structures
# class EthercatDatagram(Structure):
#     pass
# EthercatDatagram._fields_ = [
#     ("header", EthercatDatagramHeader),
#     ("packet_data_length", c_int),
#     ("packet_data", c_char_p),
#     ("work_count", c_ushort),
#     ("next_command", POINTER(EthercatDatagram))]

#
# https://msdn.microsoft.com/en-us/library/windows/desktop/dd442654%28v=vs.85%29.aspx
#
# typedef struct _FILE_SYSTEM_RECOGNITION_STRUCTURE {
#   UCHAR  Jmp[3];
#   UCHAR  FsName[8];
#   UCHAR  MustBeZero[5];
#   ULONG  Identifier;
#   USHORT Length;
#   USHORT Checksum;
# } FILE_SYSTEM_RECOGNITION_STRUCTURE;
class struct_FILE_SYSTEM_RECOGNITION_STRUCTURE(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('Jmp',         ctypes.c_uint8 * 3 ),
		('FsName',      ctypes.c_uint8 * 8),
		('MustBeZero',  ctypes.c_uint8 * 5),
		('Identifier',  ctypes.c_uint32),
		('Length',      ctypes.c_uint16),
		('Checksum',    ctypes.c_uint16),
	]
	# At least two chars for most fields.
	_regex_ = {
		'FsName'     : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{6}",
		'MustBeZero' : "\x00\x00\x00\x00\x00",
		# TODO: Does not work anyway.
		# Must contain the value 0x53525346 arranged in little-endian byte order.
		# https://technet.microsoft.com/fr-fr/dd442654
		# 'Identifier' : "\x53\x52\x53\x46",
		# 'Identifier' : "\x46\x53\x52\x53",
	}

# typedef struct tagSIZE {
#   LONG cx;
#   LONG cy;
# } SIZE, *PSIZE;
class struct_SIZEL(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('cx',      ctypes.c_uint32 ),
		('cy',      ctypes.c_uint32 ),
	]


#
# typedef struct _POINTL {
#   LONG x;
#   LONG y;
# } POINTL, *PPOINTL;
class struct_POINTL(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('x',      ctypes.c_uint32 ),
		('y',      ctypes.c_uint32 ),
	]

#
# typedef struct _FILETIME {
#   DWORD dwLowDateTime;
#   DWORD dwHighDateTime;
# } FILETIME, *PFILETIME;
class struct_FILETIME(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('dwLowDateTime',       ctypes.c_uint32 ),
		('dwHighDateTime',      ctypes.c_uint32 ),
	]

#
# CLSID
# typedef struct _GUID {
#     unsigned long  Data1;
#     unsigned short Data2;
#     unsigned short Data3;
#     unsigned char  Data4[ 8 ];
# } GUID;
class struct_GUID(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('Data1',  ctypes.c_uint32),
		('Data2',  ctypes.c_uint16),
		('Data3',  ctypes.c_uint16),
		('Data4',  ctypes.c_uint8 * 8),
	]
	# Realistically, at least two chars for most fields.
	_regex_ = {
		# 'Data4' : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{6}",
	}

#
# https://msdn.microsoft.com/en-us/library/windows/desktop/bb773288%28v=vs.85%29.aspx
#
# typedef struct _FILEDESCRIPTOR {
#   DWORD    dwFlags;
#   CLSID    clsid;
#   SIZEL    sizel;
#   POINTL   pointl;
#   DWORD    dwFileAttributes;
#   FILETIME ftCreationTime;
#   FILETIME ftLastAccessTime;
#   FILETIME ftLastWriteTime;
#   DWORD    nFileSizeHigh;
#   DWORD    nFileSizeLow;
#   TCHAR    cFileName[MAX_PATH];
# } FILEDESCRIPTOR, *LPFILEDESCRIPTOR;

class struct_FILEDESCRIPTOR(ctypes.Structure):
	_pack_ = True # source:False
	_fields_ = [
		('dwFlags',            ctypes.c_uint32),
		('clsid',              POINTER_T(struct_GUID)),
		('sizel',              POINTER_T(struct_SIZEL)),
		('pointl',             POINTER_T(struct_POINTL)),
		('dwFileAttributes',   ctypes.c_uint32),
		('ftCreationTime',     POINTER_T(struct_FILETIME)),
		('ftLastAccessTime',   POINTER_T(struct_FILETIME)),
		('ftLastWriteTime',    POINTER_T(struct_FILETIME)),
		('nFileSizeHigh',      ctypes.c_uint32),
		('nFileSizeLow',       ctypes.c_uint32),
		('cFileName',          ctypes.c_uint8 * MAX_PATH),
	]
	# Realistically, at least two chars for most fields.
	_regex_ = {
		'cFileName' : "[a-zA-Z_0-9\.]{2}[\x00a-zA-Z_0-9\..]{258}",
	}



lstStructs = [ struct_SAFEARRAY,
			   struct_SAFEARRAYBOUND,
			   struct_IP_ADDRESS_STRING,
			   struct_DISPLAY_DEVICE,
			   struct_FILETIME,
			   struct_GUID,
			   struct_FILEDESCRIPTOR,
			   struct_MODULEENTRY32,
			   struct_FILE_SYSTEM_RECOGNITION_STRUCTURE]
lstStructs = [ struct_FILE_SYSTEM_RECOGNITION_STRUCTURE ]


ctypes_scanner.DoAll(lstStructs)