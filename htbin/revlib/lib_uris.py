import sys
import socket
import lib_util
import rdflib

################################################################################

# For example, a process on a remote machine.
# Eventuellement, on peut savoir sur notre machine locale, quelques infos
# sur le process distant (Avec interrogation a distance ??)
# On ne sait pas a quoi ressemble l'URL de la machine distante qui en principe
# a des infos sur ce process.
# Il faudrait faire une discovery qui grouperait des infos:
# "host + entity+_type" => url_pattern. Eventuellement plusieurs patterns.
#  ... et pas forcement le meme host.
# Donc une sorte de "remote_entity.pl?host=x&type=y&id=z" qui tourne sur notre machine
# locale, va interroger le host, donne plusieurs urls y compris sur
# notre machine, essaye de deduire quelque chose des discovery.
# Il suppose le numero de port du remote host mais on peut l'editer.

class LocalBox:

	def MakeTheNode(self, entity_type, entity_id):
		return self.MakeTheNodeFromScript( "/entity.py", entity_type, entity_id)

	def MakeTheNodeFromScript(self, path, entity_type, entity_id):
		url = self.TypeMake( path, entity_type ) + entity_id
		return rdflib.term.URIRef( url )

	def UriMake(self, entity_type, *entity_id_arr):
		#sys.stderr.write("UriMake entity_id_arr=%s\n" % str(entity_id_arr) )
		keys = lib_util.OntologyClassKeys(entity_type)
		#sys.stderr.write("UriMake keys=%s\n" % str(keys) )
		if len(keys) != len(entity_id_arr):
			sys.stderr.write("Different lens:%s and %s\n" % (str(keys),str(entity_id_arr)))
		entity_id = ",".join( "%s=%s" % kwItems for kwItems in zip( keys, entity_id_arr ) )
		#sys.stderr.write("UriMake entity_id=%s\n" % entity_id)
		return self.MakeTheNode( entity_type, entity_id )

	def UriMakeFromDict(self, entity_type, entity_id_dict):
		entity_id = ",".join( "%s=%s" % kwItems for kwItems in entity_id_dict.items() )
		return self.MakeTheNode( entity_type, entity_id )

	def TypeMake(self, path, entity_type):
		return lib_util.uriRoot + path + "?xid=" + entity_type + "."

	###################################################################################

	def PidUri(self,pid):
		return self.UriMake('CIM_Process',str(pid))

	# TODO: Necessaire car CIM_ComputerSystem veut un nom de machine.
	# socket.gethostbyaddr("192.168.1.83")     => ('rchateau-HP.home', [], ['192.168.1.83'])
	# socket.gethostbyaddr("192.168.1.88")     => ('Unknown-30-b5-c2-02-0c-b5-2.home', [], ['192.168.1.88'])
	# socket.gethostbyaddr("192.168.1.81")     => ('WDMyCloudMirror.home', [], ['192.168.1.81'])
	def HostnameUri(self,hostAddr):
		# WMI    : CIM_ComputerSystem => WIN32_ComputerSystem
		# OpenLMI: CIM_LogicalElement => CIM_System et CIM_ComputerSystem =>  CIM_UnitaryComputerSystem => PG_ComputerSystem
		# OpenPegasus: Idem.
		# sys.stderr.write("HostnameUri=%s\n" % hostName )
		try:
			# WMI wants only the first part of the address on Windows (Same string for OpenPegasus and WMI).
			# On Linux apparently, Name="Unknown-30-b5-c2-02-0c-b5-2.home"
			# TODO: Fix this !
			hostDns = socket.gethostbyaddr(hostAddr)[0]
			hostName = hostDns.split(".")[0]
		except:
			exc = sys.exc_info()[1]
			sys.stderr.write("HostnameUri hostAddr=%s. Caught: %s" % (hostAddr, str(exc) ) )
			hostName = hostAddr
		return self.UriMake("CIM_ComputerSystem",hostName)

	# TODO: THIS WILL NOT WORK IF REMOTE LIB, BECAUSE IT WRAPS A RemoteXXX
	def SharedLibUri(self,soname):
		return self.UriMake("file", lib_util.EncodeUri(soname) )

	# For a partition. Display the mount point and IO performance.
	def DiskPartitionUri(self,disk_name):
		return self.UriMake("partition",disk_name)

	# For a hard-disk.
	def DiskUri(self,disk_name):
		return self.UriMake("disk",disk_name)

	# smbshare has the form "//HOST/SHARE"
	def SmbShareUri(self,smbshare):
		return self.UriMake("smbshr", smbshare)

	# TODO: IN FACT THIS IS SIMPLY A MACHINE. MAYBE WE SHOULD SUBCLASS TYPES ?????
	# OR MAYBE ADD SEVERAL CLASS NAMES ??? "smbserver+hostname" ?
	# OR MAYBE THE ABSTRACT CONCEPT OF A SERVER, POINTING TO THE MACHINE ITSELF?
	def SmbServerUri(self,smbserver):
		return self.UriMake("smbserver", smbserver)

	def SmbFileUri(self,smbshare,smbfile):
		if smbfile != "" and smbfile[0] != "/":
			fullnam = smbshare + "/" + smbfile
		else:
			fullnam = smbshare + smbfile
		return self.UriMake("smbfile", fullnam )

	# TODO: Services are also a process.
	def ServiceUri(self,service):
		return self.UriMake("Win32_Service", service)

	def SmbDomainUri(self,smbdomain):
		return self.UriMake("smbdomain", smbdomain)

	# Purely abstract, because a symbol can be defined in several libraries.
	# Its use depend on the behaviour of the dynamic linker if it is defined several
	# times in the same binary.
	# If the file is not defined, this is a system call.
	# TODO: DOES NOT WORK IF REMOTE SYMBOL.
	def SymbolUri(self,symbol_name, file = ""):
		return self.UriMake("symbol", symbol_name + "@" + file )

	# Not a very sound concept. We will see later.
	def ClassUri(self,symbol_name, file = ""):
		return self.UriMake("class", symbol_name + "@" + file )

	# The convention for all the entity_ids is that it must return None if this is not of the given type.
	def SymbolExtract(entity_id):
		try:
			return entity_id.split('@')[0:2]
		except Exception:
			return None

	# This must be a complete path name.
	# If there is a backslash-L, it will be replaced by "<TABLE>" in graphviz:
	# XML Parsing Error: not well-formed
	# Location: http://127.0.0.1/Survol/htbin/entity.py?xid=file:C%3A%5CUsers%5Crchateau%5CAppData%5CLocal%5CMicrosoft%5CWindows%5CExplorer%5CThumbCacheToDelete%5Cthm9798.tmp
	def FileUri(self,path):
		# It must starts with a slash except on Windows.
		return self.UriMake("file", lib_util.EncodeUri(path))

	def OracleDbUri(self,dbName):
		return self.UriMakeFromDict("oracle_db", { "Db" : dbName } )

	def OracleSessionUri(self,dbName,sessionId):
		return self.UriMakeFromDict("oracle_session", { "Db" : dbName, "Session" : sessionId } )

	# Beware of the possible confusion with normal users.
	def OracleSchemaUri(self,dbName,schemaName):
		return self.UriMakeFromDict("oracle_schema", { "Db" : dbName, "Schema" : schemaName } )

	# Beware of the possible confusion with normal users.
	def OracleTableUri(self,dbName,schemaName,tableName):
		return self.UriMakeFromDict("oracle_table", { "Db" : dbName, "Schema" : schemaName, "Table" : tableName } )

	# Ambiguity with tables, oracle or normal users.
	def OracleViewUri(self,dbName,schemaName,viewName):
		return self.UriMakeFromDict("oracle_view", { "Db" : dbName, "Schema" : schemaName, "View" : viewName } )

	# Ambiguity with tables, oracle or normal users.
	def OraclePackageUri(self,dbName,schemaName,packageName):
		return self.UriMakeFromDict("oracle_package", { "Db" : dbName, "Schema" : schemaName, "Package" : packageName } )

	# Ambiguity with tables, oracle or normal users.
	def OraclePackageBodyUri(self,dbName,schemaName,packageBodyName):
		return self.UriMakeFromDict("oracle_package_body", { "Db" : dbName, "Schema" : schemaName, "Package" : packageBodyName } )

	# Ambiguity with tables, oracle or normal users.
	def OracleSynonymUri(self,dbName,schemaName,synonymName):
		return self.UriMakeFromDict("oracle_synonym", { "Db" : dbName, "Schema" : schemaName, "Synonym" : synonymName } )

	# This creates a node for a socket, so later it can be merged
	# with the same socket.
	# TODO: The URL should do something useful.
	# If the port is known, we could wrap the associated service in a Python script.
	# On the other hand, it forces the usage of a service.
	def AddrUri(self,addr,port,transport="tcp"):
		try:
			portNam = socket.getservbyport( int(port) )
		except socket.error:
			portNam = str(port)

		url = addr + ':' + portNam
		if transport != 'tcp':
			# This will happen rarely.
			url += ":" + transport
		return self.UriMake("addr",url)

	# TODO: Maybe this should be a file, nothing else.
	def MemMapUri(self,memmap_path):
		# Because DOT replace "\L" by "<TABLE>".
		# Probably must do that for files also.
		# "xid=memmap:C:\Program Files (x86)Memory mapsoogle\Chrome\Application\39.0.2171.95<TABLE>ocales\fr.pak"
		return self.UriMake("memmap",memmap_path.replace('\\','/') )

	def UserUri(self,username):
		# If Unix "CIM_UnixUser"
		# If Windows "CIM_Win32User"
		if lib_util.isPlatformLinux:
			userTp = "user"
		elif lib_util.isPlatformWindows:
			userTp = "user"
		else:
			userTp = "user"
		return self.UriMake(userTp,username)

	def GroupUri(self,groupname):
		return self.UriMake("group",groupname)

	def OdbcDsnUri(self,dsn):
		return self.UriMake("odbc_dsn",dsn)

	# TODO: At the moment, keys have this structure: {CE4AACFA-3CFD-4028-B2D9-F272314F07C8}
	# But we need a string to loop in the registry: win32con.HKEY_CLASSES_ROOT, "TypeLib".
	# What about the other thnigs in combrowse.py ? "Registered Categories" and "Running Objects" ?
	def ComRegisteredTypeLibUri(self, keyName ):
		return self.UriMake("com_registered_type_lib", lib_util.EncodeUri(keyName) )

	def ComTypeLibUri(self, fileName ):
		return self.UriMake("com_type_lib", lib_util.EncodeUri(fileName) )





gUriGen = LocalBox()

class RemoteBox (LocalBox):
	def __init__(self,mach):
		self.m_mach = mach

	def TypeMake(self, path, entity_type):
		return lib_util.uriRoot + path + "?xid=" + self.m_mach + "@" + entity_type + "."

