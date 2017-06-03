import os
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

# Convertir le moniker en moniker WBEM et "NOUS" et ajouter liens.
# En plus, on va creer un entity_all.py qui synthetise les trois.
# Il faut donc avoir un format unique pour les xid, cad les moniker.
# On a donc une table qui passe du host netbios vers l url WBEM. Et s'il y a plusieurs urls WBEM ?
# Netbios ou bien adresse IP ?
# On suppose que les classes sont uniques quelque soit le namespace,
# et qu'une classe ne peut pas apparaitre dans plusieurs namespaces (Meme supposition pour WMI).
# Pour chaque serveur WBEM et peut etre aussi pour chaque machine WMI (Ou bien chaque version ?)
# on a un dictionnaire qui pointe de la classe vers le namespace.
# Pour chaque classe, on definit aussi les classes de bases qu on peut investiguer.
#
#
# On ne peut pas comparer directement, de totue facon, des accounts WMI et WBEM.
# Mais notre ontologie doit faire la jonction avec WMI d'une part,
# et WBEM d'autre part (Si Linux).
# Une possibilite est de dupliquer nos directories.
# En ce qui nous concerne, 2/3 du code est specifique Linux.
#
# Quand on veut aller d'un objet portable (Process) vers un qui nest pas
# portacle comme un user, il faut choisir dynamiquement le type:
# Par exemple ici, Win32_UserAccount ou bien LMI_Account, qui n ont pas d ancetre commun.
# Ou bien Win32_Group et LMI_Group.
# On ne sait pas encore faire. Limitons-nous pour le moment aux cas sans ambiguites.
#
#
#
# Jusqu'ou remonter ?
# Un critere peut etre de remonter d abord dans notre classe, tant qu'on trouve notre propriete,
# en l'occurence "Handle". Au-dessus, ca n'aurait pas de sens.
# On peut selectionner les processes dans WIN et WBEM uniquement a partir de la classe CIM_Process.
# Donc: On cherche la classe de base la plus elevee qui a toujours nos criteres.
# Ensuite on cherche le namespace de cette classe dans le serveur d'en face (WMI ou WBEM),
# on ajoute les memes criteres. Puis on fait la recherche.
# Pour chaque type de serveur, il faudrait une fonction qui renvoie du RDF.
#
# ====================================================================================
#
# Peut etre que entity_id pourrait etre soit une valeur unique: Si une seule clef,
# ou bien un dictionnaire de paires clef-valeur.
# Ne nous pressons pas: Dans un premier temps:
# * Remplacer cimom=xxx par le moniker (En effet, c etait une erreur).
# * Remplacer nos classes par des classes DMTF, avec mecanismes a rajouter.



class LocalBox:

	def MakeTheNode(self, entity_type, entity_id):
		return self.MakeTheNodeFromScript( "/entity.py", entity_type, entity_id)

	def MakeTheNodeFromScript(self, path, entity_type, entity_id):
		url = lib_util.uriRoot + path + "?xid=" + self.TypeMake() + entity_type + "." + entity_id
		return rdflib.term.URIRef( url )

	def BuildEntity(self, entity_type, *entity_id_arr):
		#sys.stderr.write("UriMake entity_id_arr=%s\n" % str(entity_id_arr) )
		keys = lib_util.OntologyClassKeys(entity_type)
		#sys.stderr.write("UriMake keys=%s\n" % str(keys) )

		lenKeys = len(keys)
		lenEntIds = len(entity_id_arr)
		if lenKeys < lenEntIds:
			# Append fake temporary keys
			sys.stderr.write("BuildEntity entity_type=%s Not enough keys:%s and %s\n" % (entity_type,str(keys),str(entity_id_arr)))
			keys += [ "Key_%d" % idx for idx in range(lenKeys,lenEntIds) ]
		elif lenKeys > lenEntIds:
			# Not enough values. This is not a problem because of queries returning several objects.
			sys.stderr.write("BuildEntity entity_type=%s Not enough values:%s and %s\n" % (entity_type,str(keys),str(entity_id_arr)))
			# entity_id_arr += [ "Unknown" ] * ( lenKeys - lenEntIds )

		# C est peut etre ici le probleme car on conserve l ordre ???
		# zip pas tres rapide.
		# dict tres rapide et commode.
		# si on est tributaire de l ordre,
		# on va forcement se planter de tps en tps/
		# Qu est ce qu apporte l ordre ?
		# Au lieu de zip, on aura aussi vite fait de batir un dict.

		# entity_id = ",".join( "%s=%s" % kwItems for kwItems in zip( keys, entity_id_arr ) )
		# Sorted keys
		entity_id = ",".join( "%s=%s" % kwItems for kwItems in dict(zip( keys, entity_id_arr ) ).items() )

		return entity_id

	def UriMake(self, entity_type, *entity_id_arr):
		entity_id = self.BuildEntity( entity_type, *entity_id_arr )
		return self.MakeTheNode( entity_type, entity_id )

	def UriMakeFromScript(self, path, entity_type, *entity_id_arr):
		entity_id = self.BuildEntity( entity_type, *entity_id_arr )
		return self.MakeTheNodeFromScript( path, entity_type, entity_id )

	def UriMakeFromDict(self, entity_type, entity_id_dict):
		entity_id = ",".join( "%s=%s" % kwItems for kwItems in entity_id_dict.items() )
		return self.MakeTheNode( entity_type, entity_id )

	# This is a virtual method.
	def TypeMake(self):
		return ""

	###################################################################################


	# TODO: Si on ne trouve pas, charger le module "sources_types/<type>/__init__.py"



	# >>> wmi.WMI().Win32_Process()[0].derivation()
	# (u'CIM_Process', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
	#
	# OpenLMI:
	# CIM_ManagedElement 	Instance Names 	Instances
	# |--- CIM_ManagedSystemElement 	Instance Names 	Instances
	# |    |--- CIM_LogicalElement
	# |    |    |--- CIM_EnabledLogicalElement 	Instance Names 	Instances
	# |    |    |    |--- CIM_Process 	Instance Names 	Instances
	# |    |    |    |    |--- CIM_UnixProcess 	Instance Names 	Instances
	# |    |    |    |    |    |--- TUT_UnixProcess 	Instance Names 	Instances
	#
	# OpenPegasus/Windows:
	# CIM_ManagedElement 	Instance Names 	Instances
	# |--- CIM_ManagedSystemElement 	Instance Names 	Instances
	# |    |--- CIM_LogicalElement 	Instance Names 	Instances
	# |    |    |--- CIM_EnabledLogicalElement 	Instance Names 	Instances
	# |    |    |    |--- CIM_Process 	Instance Names 	Instances
	# |    |    |    |    |--- PG_UnixProcess 	Instance Names 	Instances
	#
	# Quant a nous: "process" qui deviendra CIM_Process.
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
			# See lib_util.HostName()
			# WMI wants only the first part of the address on Windows (Same string for OpenPegasus and WMI).
			# On Linux apparently, Name="Unknown-30-b5-c2-02-0c-b5-2.home"
			# Beware of a normal address such as: "wb-in-f95.1e100.net"
			# TODO: Fix this !
			hostDns = socket.gethostbyaddr(hostAddr)[0]
			hostSplit = hostDns.split(".")
			if len(hostSplit) == 2 and hostSplit[1] == "home":
				# if isPlatformLinux:
				hostName = hostSplit[0]
			else:
				hostName = hostDns
		except:
			exc = sys.exc_info()[1]
			sys.stderr.write("HostnameUri hostAddr=%s. Caught: %s\n" % (hostAddr, str(exc) ) )
			hostName = hostAddr
		return self.UriMake("CIM_ComputerSystem",hostName)

	# TODO: THIS WILL NOT WORK IF REMOTE LIB, BECAUSE IT WRAPS A RemoteXXX
	#
	# >>> wmi.WMI().CIM_DataFile.derivation()
	# (u'CIM_LogicalFile', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
	# >>> wmi.WMI().Win32_Directory.derivation()
	# (u'CIM_Directory', u'CIM_LogicalFile', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
	#
	# OpenLMI:
	# CIM_ManagedElement 	Instance Names 	Instances
	# |--- CIM_ManagedSystemElement 	Instance Names 	Instances
	# |    |--- CIM_LogicalElement 	Instance Names 	Instances
	# |    |    |--- CIM_UnixFile 	Instance Names 	Instances
	# |    |    |    |--- LMI_UnixFile 	Instance Names 	Instances
	# |    |    |--- CIM_LogicalFile 	Instance Names 	Instances
	# |    |    |    |--- CIM_DataFile 	Instance Names 	Instances
	# |    |    |    |    |--- LMI_DataFile 	Instance Names 	Instances
	# |    |    |    |    |--- LMI_UnixSocket 	Instance Names 	Instances
	# |    |    |    |--- CIM_DeviceFile 	Instance Names 	Instances
	# |    |    |    |    |--- CIM_UnixDeviceFile 	Instance Names 	Instances
	# |    |    |    |    |    |--- LMI_UnixDeviceFile 	Instance Names 	Instances
	# |    |    |    |--- CIM_Directory 	Instance Names 	Instances
	# |    |    |    |    |--- CIM_UnixDirectory 	Instance Names 	Instances
	# |    |    |    |    |    |--- LMI_UnixDirectory 	Instance Names 	Instances
	# |    |    |    |--- CIM_FIFOPipeFile 	Instance Names 	Instances
	# |    |    |    |    |--- LMI_FIFOPipeFile 	Instance Names 	Instances
	# |    |    |    |--- CIM_SymbolicLink 	Instance Names 	Instances
	# |    |    |    |    |--- LMI_SymbolicLink 	Instance Names 	Instances
	#
	# OpenPegasus/Windows:
	# Rien
	#
	def SharedLibUri(self,soname):
		return self.UriMake("CIM_DataFile", lib_util.EncodeUri(soname) )

	# TODO: POUR LES DISQUES ET LES PARTITIONS, LES HIERARCHIES SE CROISENT, SANS PLUS.
	# Y PENSER DANS class_type_all.py

	# For a partition. Display the mount point and IO performance.
	# WMI
	#	CIM_ManagedSystemElement
	#		CIM_LogicalElement
	#			CIM_LogicalDevice
	#				CIM_StorageExtent
	# |   |   |    |--- CIM_DiskPartition
	# |   |   |    |    |--- Win32_DiskPartition
	#
	# OpenLMI:
	# |--- CIM_LogicalElement
	# |   |--- CIM_LogicalDevice
	# |   |   |--- CIM_GenericDiskPartition
	# |   |   |    |--- CIM_DiskPartition
	# |   |   |    |    |--- LMI_DiskPartition
	def DiskPartitionUri(self,disk_name):
		return self.UriMake("CIM_DiskPartition",disk_name)
		# return self.UriMake("CIM_LogicalDisk",disk_name)

	# For a hard-disk.
	# WMI
	#	CIM_ManagedSystemElement
	#		CIM_LogicalElement
	#			CIM_LogicalDevice,
	#				CIM_MediaAccessDevice
	# |   |   |    |--- CIM_DiskDrive
	# |   |   |    |    |--- Win32_DiskDrive
	#
	#
	# OpenPegasus: Rien
	# OpenLMI:
	# |--- CIM_LogicalElement
	# |   |--- CIM_LogicalDevice
	# |   |   |--- CIM_StorageExtent
	# |   |   |   |--- CIM_MediaPartition
	# |   |   |   |   |--- CIM_MediaAccessDevice
	# |   |   |   |   |    |--- CIM_CDROMDrive
	# |   |   |   |   |    |--- CIM_DVDDrive
	# |   |   |   |   |    |--- CIM_DiskDrive
	# |   |   |   |   |    |    |--- LMI_DiskDrive
	#
	def DiskUri(self,disk_name):
		return self.UriMake("CIM_DiskDrive",disk_name)

	# smbshare has the form "//HOST/SHARE"
	def SmbShareUri(self,smbshare):
		return self.UriMake("smbshr", smbshare)

	# TODO: IN FACT THIS IS SIMPLY A MACHINE. MAYBE WE SHOULD SUBCLASS TYPES ?????
	# OR MAYBE ADD SEVERAL CLASS NAMES ??? "smbserver+hostname" ?
	# OR MAYBE THE ABSTRACT CONCEPT OF A SERVER, POINTING TO THE MACHINE ITSELF?
	def SmbServerUri(self,smbserver):
		return self.UriMake("smbserver", smbserver)

	def SmbFileUri(self,smbshare,smbfile):
		if smbfile and smbfile[0] != "/":
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
	# times in the same binary. If the file is not defined, this is a system call.
	# TODO: DOES NOT WORK IF REMOTE SYMBOL.
	def SymbolUri(self,symbol_name, file = ""):
		# The URL should never contain the chars "<" or ">".
		symbol_name = lib_util.Base64Encode(symbol_name)
		# TODO: Alphabetical order !!!!
		return self.UriMakeFromDict("symbol", { "Name" : symbol_name, "File" : lib_util.EncodeUri(file) } )

	# Might be a C++ class or a namespace, as there is no way to differentiate from ELF symbols.
	# TODO: Move that to class/__init__.py
	def ClassUri(self,class_name, file = ""):
		# The URL should never contain the chars "<" or ">".
		class_name = lib_util.Base64Encode(class_name)
		return self.UriMakeFromDict("class", { "Name" : class_name, "File" : lib_util.EncodeUri(file) } )

	# CIM_DeviceFile is common to WMI and WBEM.

	# This must be a complete path name.
	# If there is a backslash-L, it will be replaced by "<TABLE>" in graphviz:
	# XML Parsing Error: not well-formed
	# Location: http://127.0.0.1/Survol/htbin/entity.py?xid=file:C%3A%5CUsers%5Crchateau%5CAppData%5CLocal%5CMicrosoft%5CWindows%5CExplorer%5CThumbCacheToDelete%5Cthm9798.tmp
	def FileUri(self,path):
		path = path.replace("\\","/")
		return self.UriMake("CIM_DataFile", lib_util.EncodeUri(path))

		# TODO: Consider this might be even be more powerful.
		# u'some string'.encode('ascii', 'xmlcharrefreplace')

	# If path is terminated by a backslash, it must be stripped otherwise things fail.
	def DirectoryUri(self,path):
		# Normalize a pathname by collapsing redundant separators and up-level references
		# so that A//B, A/B/, A/./B and A/foo/../B all become A/B.
		# This string manipulation may change the meaning of a path that contains symbolic links.
		# On Windows, it converts forward slashes to backward slashes.
		path = os.path.normpath(path)
		# Backslashes are a real problem everywhere.
		# On top of that, escaping the backslash is not enough because strings are sometimes truncated for display.
		# Better have our own "canonical" notation for filenames, so replace them.
		# If needed, they can always be replaced by a normal slash.
		#
		# ATTENTION ! IL Y A UN MOMENT OU CE N EST PAS FAIT ET DONC LA FUSION NE FONCTIONNE PAS
		# Peut-etre dans les mapped memory segments ?
		#
		# To reproduce the problem, for example:
		# Process: "Current working directory" => Directories separated by backslashes.
		# then "File Stat information" => Separator is slashes.
		#
		path = path.replace("\\","/")
		return self.UriMake( "CIM_Directory" , lib_util.EncodeUri(path))

	# TODO: Renvoyer NULL si type MIME invalide ?
	# Ou bien une icone ?
	def FileUriMime(self,filNam):
		return self.UriMakeFromScript('/file_to_mime.py', "CIM_DataFile", lib_util.EncodeUri(filNam) )

	# This creates a node for a socket, so later it can be merged with the same socket.
	#
	# TODO: PROBLEM: How can it be merged with the same address but described "from the other side" ??
	# TODO: WE MUST ADD IN ITS PROPERTY, THE ALLEGED NODE "FROM THE OTHER SIDE".
	# MAYBE IT IS NOT ENOUGH (BUT SO ELEGANT), IF THIS IS THE REMOTE NODE, TO USE THE REMOTE HOST,
	# BECAUSE IT WOULD FORBID ANY INVESTIGATION FROM ANOTHER MACHINE ??
	#
	# If the port is known, we could wrap the associated service in a Python script.
	# On the other hand, it forces the usage of a service.
	# We do not put it in a specific module because it is used everywhere and is unavoidable.
	def AddrUri(self,addr,port,transport="tcp"):
		try:
			portNam = socket.getservbyport( int(port) )
		except socket.error:
			portNam = str(port)

		url = addr + ':' + portNam
		if transport != 'tcp':
			# This will happen rarely.
			url += ":" + transport
		# TODO: THIS IS WHERE WE SHOULD MAYBE ALWAYS USE A RemoteBox().
		return self.UriMake("addr",url)

	# TODO: Maybe this should be a file, nothing else.
	def MemMapUri(self,memmap_path):
		# Because DOT replace "\L" by "<TABLE>".
		# Probably must do that for files also.
		# "xid=memmap:C:\Program Files (x86)Memory mapsoogle\Chrome\Application\39.0.2171.95<TABLE>ocales\fr.pak"
		return self.UriMake("memmap",memmap_path.replace('\\','/') )

	# Win32_Account:	Domain	Name
	#
	# >>> wmi.WMI().Win32_UserAccount()[0].derivation()
	# (u'Win32_Account', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
	# >>> wmi.WMI().Win32_Group()[0].derivation()
	# (u'Win32_Account', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
	#
	# CIM_Account: 	CreationClassName 	Name 	SystemCreationClassName 	SystemName 	Namespace
	#
	# OpenLMI:
	# CIM_ManagedElement 	Instance Names 	Instances
	# |--- CIM_ManagedSystemElement 	Instance Names 	Instances
	# |    |--- CIM_LogicalElement
	# |    |    |--- CIM_EnabledLogicalElement 	Instance Names 	Instances
	# |    |    |    |--- CIM_Account 	Instance Names 	Instances
	# |    |    |    |    |--- LMI_Account 	Instance Names 	Instances
	#
	# CIM_ManagedElement 	Instance Names 	Instances
	# |--- CIM_Collection 	Instance Names 	Instances
	# |    |--- CIM_Group 	Instance Names 	Instances
	# |    |    |--- LMI_Group 	Instance Names 	Instances
	#
	# OpenPegasus/Windows:
	# CIM_Account et CIM_Group pas definis sur OpenPegasus
	#
	# WMI:
	# Win32_Group: "Distributed COM users","Guests", "Backup Operators" etc...
	# Win32_Account: Win32_Group + Win32_SystemAccount + Win32_UserAccount
	# Win32_UserAccount: "Administrator","Guest","HomeGroupUser$","rchateau"
	# Win32_SystemAccount : Tres intern a Windows, on peut laisser de cote.
	# Win32_GroupUser: "HomeUsers", "Administrator" : Association entre Win32_Group et un account
	#
	# Quant a nous: "group" et "user"
	def UserUri(self,username):
		# If Unix "CIM_UnixUser"
		# If Windows "CIM_Win32User"
		if lib_util.isPlatformLinux:
			# TODO: Replace by LMI_Account on Linux ?
			userTp = "user"
		elif lib_util.isPlatformWindows:
			# TODO: DEPRECATED But this is called directly from entity.py.
			# TODO: Should be removed.
			userTp = "Win32_UserAccount"
		else:
			userTp = "user"

		splitUser = username.split("\\")
		if len(splitUser) > 1:
			userHost = splitUser[0]
			userOnly = splitUser[1]
		else:
			userHost = "LocalHost"
			userOnly = username
		return self.UriMake(userTp,userOnly,userHost)

	def GroupUri(self,groupname):
		# CIM_GroupAccount ?
		# Linux only.
		return self.UriMake("group",groupname)

	# TODO: At the moment, keys have this structure: {CE4AACFA-3CFD-4028-B2D9-F272314F07C8}
	# But we need a string to loop in the registry: win32con.HKEY_CLASSES_ROOT, "TypeLib".
	# What about the other thnigs in combrowse.py ? "Registered Categories" and "Running Objects" ?
	def ComRegisteredTypeLibUri(self, keyName ):
		return self.UriMake("com/registered_type_lib", lib_util.EncodeUri(keyName) )

	def ComTypeLibUri(self, fileName ):
		return self.UriMake("com/type_lib", lib_util.EncodeUri(fileName) )


gUriGen = LocalBox()

class RemoteBox (LocalBox):
	def __init__(self,mach):
		self.m_mach = mach

	def TypeMake(self):
		return self.m_mach + "@"

# Ceci est un peu equivalent a:
# select * from LMI_MountedFileSystem where MountPointPath="/sys/fs/cgroup" and FileSystemSpec="tmpfs"
# Dictionnaire des properties ?
