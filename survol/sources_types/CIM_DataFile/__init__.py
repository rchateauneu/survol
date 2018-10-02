"""
Standard data file.
"""

import os
import sys
import datetime
import lib_common
import lib_util
import lib_uris
import lib_properties
from lib_properties import pc
import lib_mime
import json

def EntityOntology():
	return ( ["Name"], )

def EntityName(entity_ids_arr):
	entity_id = entity_ids_arr[0]
	# A file name can be very long, so it is truncated.
	file_basename = os.path.basename(entity_id)
	if file_basename == "":
		return entity_id
	else:
		return file_basename

def AddMagic( grph, filNode, filNam ):
	try:
		import magic
	except ImportError:
		DEBUG("File magic unavailable:%s", filNam )
		return

	try:
		ms = magic.open(magic.MAGIC_NONE)
		ms.load()
		mtype =  ms.file(filNam)
		ms.close()
		grph.add( ( filNode, pc.property_information, lib_common.NodeLiteral(mtype) ) )
	except TypeError:
		DEBUG("Type error:%s", filNam )
		return

# Transforms a "stat" date into something which can be printed.
def IntToDateLiteral(timeStamp):
	dtStr = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y-%m-%d %H:%M:%S')
	return lib_common.NodeLiteral(dtStr)

# Adds to the node of a file some information taken from a call to stat().
def AddStatNode( grph, filNode, infoStat ):
	# st_size: size of file, in bytes. The SI unit is mentioned.
	sizUnit = lib_util.AddSIUnit(infoStat.st_size, "B")
	grph.add( ( filNode, pc.property_file_size, lib_common.NodeLiteral(sizUnit) ) )

	grph.add( ( filNode, pc.property_last_access,          IntToDateLiteral(infoStat.st_atime) ) )
	grph.add( ( filNode, pc.property_last_change,          IntToDateLiteral(infoStat.st_mtime) ) )
	grph.add( ( filNode, pc.property_last_metadata_change, IntToDateLiteral(infoStat.st_ctime) ) )

def AddStat( grph, filNode, filNam ):
	try:
		statObj = os.stat(filNam)
		AddStatNode( grph, filNode, statObj )
	except Exception:
		# If there is an error, displays the message.
		exc = sys.exc_info()[1]
		msg = str(exc)
		grph.add( ( filNode, pc.property_information, lib_common.NodeLiteral(msg) ) )

# BEWARE: This link always as a literal. So it is simpler to display
# in an embedded HTML table.
# NON: On stocke les urls vraiment comment des URI.
def AddHtml( grph, filNode, filNam ):
	# Get the mime type, maybe with Magic. Then return a URL with for this mime type.
	# This is a separated script because it returns HTML data, not RDF.

	mime_stuff = lib_mime.FilenameToMime( filNam )
	mime_type = mime_stuff[0]

	if mime_type:
		lib_mime.AddMimeUrl(grph,filNode, "CIM_DataFile",mime_type,[filNam])

# Display the node of the directory this file is in.
def AddParentDir( grph, filNode, filNam ):
	dirPath = os.path.dirname(filNam)
	if dirPath and dirPath != filNam:
		# Possibly trunc last backslash such as in "C:\" as it crashes graphviz !
		if dirPath[-1] == "\\":
			dirPath = dirPath[:-1]
		dirNode = lib_uris.gUriGen.DirectoryUri(dirPath)
		# grph.add( ( dirNode, pc.property_directory, filNode ) )
		# We do not use the property pc.property_directory because it breaks the display.
		# Also, the direction is inverted so the current file is displayed on the left.
		grph.add( ( filNode, lib_common.MakeProp("Top directory"), dirNode ) )

# Plain call to stat with some filtering if the file does not exists.
def GetInfoStat(filNam):
	try:
		info = os.stat(filNam)
	except Exception:
		# On recent Python versions, we would catch IOError or FileNotFoundError.
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))
	except IOError:
		lib_common.ErrorMessageHtml("IOError:"+filNam)
	except FileNotFoundError:
		lib_common.ErrorMessageHtml("File not found:"+filNam)
	except PermissionError:
		lib_common.ErrorMessageHtml("Permission error:"+filNam)
	except OSError:
		lib_common.ErrorMessageHtml("Incorrect syntax:"+filNam)

	return info

def AddDevice(grph,filNode,info):
	deviceName = "Device:"+str(info.st_dev)
	if lib_util.isPlatformLinux:
		# TODO: How to get the device name on Windows ???
		for line in file('/proc/mounts'):
			# lines are device, mountpoint, filesystem, <rest>
			# later entries override earlier ones
			line = [s.decode('string_escape') for s in line.split()[:3]]
			try:
				if os.lstat(line[1]).st_dev == info.st_dev:
					deviceName = line[1]
					break
			except OSError:
				# Beware, index 1, not 0:
				# "[Errno 13] Permission denied: '/run/user/42/gvfs'"
				# Better display the error message.
				exc = sys.exc_info()[1]
				deviceName=str(exc)
				break

		deviceNode = lib_common.gUriGen.DiskPartitionUri(deviceName)
		grph.add( ( filNode, pc.property_file_device, deviceNode ) )

def AddFileProperties(grph,currNode,currFilNam):
	try:
		import win32api
		import lib_win32

		propDict = lib_win32.getFileProperties(currFilNam)
		for prp, val in propDict.items():
			val = propDict[prp]
			if val is None:
				continue

			if isinstance( val, dict ):
				# val = ", ".join( "%s=%s" % (k,val[k]) for k in val )
				val = json.dumps(val)
				# TODO: Unicode error encoding=ascii
				# 169	251	A9	10101001	"Copyright"	&#169;	&copy;	Copyright sign
				# Might contain this: "LegalCopyright Copyright \u00a9 2010"
				val = val.replace("\\","\\\\")
			grph.add( ( currNode, lib_common.MakeProp(prp), lib_common.NodeLiteral(val) ) )
	except ImportError:
		pass

	mimTy = lib_mime.FilenameToMime(currFilNam)
	if mimTy:
		if mimTy[0]:
			grph.add( ( currNode, lib_common.MakeProp("Mime type"), lib_common.NodeLiteral(str(mimTy)) ) )



def AffFileOwner(grph, filNode, filNam):

	def AddFileOwnerWindows(grph, filNode, filNam):
		import win32api
		import win32con
		import win32security

		from sources_types import Win32_UserAccount
		from sources_types import Win32_Group

		def SID_CodeToName(typeSID):
			mapSIDList = {
				win32security.SidTypeUser: "User SID",
				win32security.SidTypeGroup: "Group SID",
				win32security.SidTypeDomain: "Domain SID",
				win32security.SidTypeAlias: "Alias SID",
				win32security.SidTypeWellKnownGroup: "Well-known group",
				win32security.SidTypeDeletedAccount: "Deleted account",
				win32security.SidTypeInvalid: "Invalid SID",
				win32security.SidTypeUnknown: "Unknown type SID",
				win32security.SidTypeComputer: "Computer SID",
				# win32security.SidTypeLabel: "Mandatory integrity label SID" # NOT DEFINED
			}

			try:
				return mapSIDList[typeSID]
			except:
				return "Unknown SID"

		#print "I am", win32api.GetUserNameEx (win32con.NameSamCompatible)

		try:
			sd = win32security.GetFileSecurity (filNam, win32security.OWNER_SECURITY_INFORMATION)
		except:
			exc = sys.exc_info()[1]
			msg = str(exc)
			grph.add( ( filNode, pc.property_owner, lib_common.NodeLiteral(msg) ) )
			return

		owner_sid = sd.GetSecurityDescriptorOwner ()
		accountName, domainName, typeCode = win32security.LookupAccountSid (None, owner_sid)
		typNam = SID_CodeToName(typeCode)
		DEBUG("Domain=%s Name=%s Type=%s", domainName, accountName,typNam)

		if typeCode == win32security.SidTypeUser:
			accountNode = Win32_UserAccount.MakeUri(accountName,domainName)
		elif typeCode == win32security.SidTypeGroup:
			accountNode = Win32_Group.MakeUri(accountName,domainName)
		elif typeCode == win32security.SidTypeWellKnownGroup:
			accountNode = Win32_Group.MakeUri(accountName,domainName)
		else:
			# What else can we do ?
			accountNode = Win32_UserAccount.MakeUri(accountName,domainName)

		# TODO: What can we do with the domain ?
		grph.add( ( accountNode, lib_common.MakeProp("Domain"), lib_common.NodeLiteral(domainName) ) )
		grph.add( ( accountNode, lib_common.MakeProp("SID"), lib_common.NodeLiteral(typNam) ) )
		grph.add( ( filNode, pc.property_owner, accountNode ) )


	def AddFileOwnerLinux(grph, filNode, filNam):
		# Do it a second time, but this is very fast.
		info = GetInfoStat(filNam)

		# st_uid: user id of owner.
		try:
			# Can work on Unix only.
			import pwd
			user = pwd.getpwuid( info.st_uid )
			userName = user[0]
			userNode = lib_common.gUriGen.UserUri(userName)
			grph.add( ( filNode, pc.property_owner, userNode ) )
		except ImportError:
			pass

		# st_gid: group id of owner.
		try:
			# Can work on Unix only.
			import grp
			group = grp.getgrgid( info.st_gid )
			groupName = group[0]
			groupNode = lib_common.gUriGen.GroupUri(groupName)
			grph.add( ( filNode, pc.property_group, groupNode ) )
		except ImportError:
			pass

		return

	try:
		if lib_util.isPlatformWindows:
			AddFileOwnerWindows(grph, filNode, filNam)
		elif lib_util.isPlatformLinux:
			AddFileOwnerLinux(grph, filNode, filNam)
		else:
			WARNING("unknown OS")
			pass
	except:
		raise
		pass


# This applies on Linux only. Given an executable,
# it looks for a Shebang, and returns the string, or nothing.
# The first element of the string is an interpreter.
# Now we must use the same logic as CIM_Process/languages,
# to detect the language and accordingly parse this file
# by correctly detecting its language.
def GetShebang(grph, filNode, filNam):
	return None


def AddInfo(grph,node,entity_ids_arr):
	"""
		This creates a couple of nodes about a file.
	"""
	filNam = entity_ids_arr[0]
	if filNam == "":
		return
	AddMagic( grph,node,filNam)
	AddStat( grph,node,filNam)
	AddHtml( grph,node,filNam)
	AddParentDir( grph,node,filNam)

# It receives as CGI arguments, the entity type which is "HttpUrl_MimeDocument", and the filename.
# It must then return the content of the file, with the right MIME type,
def DisplayAsMime(grph,node,entity_ids_arr):
	fileName = entity_ids_arr[0]

	mime_stuff = lib_mime.FilenameToMime( fileName )

	DEBUG("DisplayAsMime fileName=%s MIME:%s", fileName, str(mime_stuff) )

	mime_type = mime_stuff[0]

	# It could also be a binary stream.
	if mime_type == None:
		lib_common.ErrorMessageHtml("No mime type for %s"%fileName)

	# TODO: Find a solution for JSON files such as:
	# "No mime type for C:\Users\rchateau\AppData\Roaming\Mozilla\Firefox\Profiles\gciw4sok.default/dh-ldata.json"

	try:
		# TODO: Change this with WSGI.
		lib_util.CopyFile( mime_type, fileName )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("file_to_mime.py Reading fileName=%s, caught:%s" % ( fileName, str(exc) ) )


# TODO: Some files in /proc filesystem, on Linux, could be displayed
# not simply as plain text files, but with links replacing text.
# Example:
#
#  /proc/diskstats
#  11       0 sr0 0 0 0 0 0 0 0 0 0 0 0
#   8       0 sda 153201 6874 4387154 1139921 637311 564765 40773896 13580495 0 2700146 14726473
#
# /proc/devices
#Character devices:
#  4 /dev/vc/0
#  4 tty
#
#  ... etc ...
