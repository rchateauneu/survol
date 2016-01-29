import os
import sys
import socket
import lib_util
import lib_common

try:
	import wmi
	wmi_imported = True
except ImportError:
	wmi_imported = False

################################################################################
# Just a reminder of what can be done on Linux.
# https://pypi.python.org/pypi/wmi-client-wrapper

if lib_util.isPlatformLinux:
	import wmi_client_wrapper as wmilnx

	wmic = wmilnx.WmiClientWrapper( username="Administrator", password="password", host="192.168.1.149", )

	output = wmic.query("SELECT * FROM Win32_Processor")

################################################################################

# TODO: Reprendre tout ca, c;est complique et lent.

def BuildWmiMoniker( hostname, namespac = "", classNam = "" ):
	return "\\\\" + hostname + "\\" + namespac + ":" + classNam + "."

def WmiAllNamespacesUrl(hostname):
	wmiMoniker = BuildWmiMoniker( hostname )
	wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True, True, True )
	return wmiInstanceUrl

def NamespaceUrl(nskey,cimomUrl):
	wmiMoniker = BuildWmiMoniker( cimomUrl, nskey )
	wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True, True )
	return wmiInstanceUrl

def ClassUrl(nskey,cimomUrl,classNam):
	wmiMoniker = BuildWmiMoniker( cimomUrl, nskey, classNam )
	wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True )
	return wmiInstanceUrl

################################################################################

# connWMI = wmi.WMI(cimomUrl,namespace=nskey)
# TODO: Aller chercher les credentials.
# c = wmi.WMI("MachineB", user=r"MachineB\fred", password="secret")
def WmiConnect(machWithBackSlashes,wmiNamspac):
	# WmiConnect cimom=\\\\rchateau-HP\\:. wmiNamspace=aspnet
	cleanMachNam = machWithBackSlashes.replace("\\","")
	# sys.stderr.write("WmiConnect cimom=%s cleanMachNam=%s wmiNamspace=%s\n" % ( machWithBackSlashes, cleanMachNam, wmiNamspac ) )

	# WMI does not do local connection with the local IP.
	machIP = socket.gethostbyname(cleanMachNam)
	# sys.stderr.write("WmiConnect machIP=%s\n" % ( machIP ) )

	if lib_common.SameHostOrLocal( machIP, "*" ):
		connWMI = wmi.WMI(namespace=wmiNamspac)
	else:
		connWMI = wmi.WMI(machIP,namespace=wmiNamspac)

	return connWMI

################################################################################

# Returns the list of a keys of a given WBEM class. This is is used if the key is not given
# for an entity. This could be stored in a cache for better performance.
def WmiGetClassKeys( wmiNameSpace, wmiClass, cimomSrv ):
	# sys.stderr.write("WmiGetClassKeys wmiNameSpace=%s wmiClass=%s cimomSrv=%s\n" % (wmiNameSpace, wmiClass, cimomSrv ))

	try:
		# TODO: Choose the namespace, remove "root\\" at the beginning.
		# wmi.WMI(namespace="aspnet")
		wmiCnnct = wmi.WMI(cimomSrv)
		wmiClass = getattr(wmiCnnct,wmiClass)
	except Exception:
		exc = sys.exc_info()[1]
		sys.stderr.write("WmiGetClassKeys %s %s %s: Caught:%s\n" % ( cimomSrv, wmiNameSpace, wmiClass, str(exc) ) )
		return None

	wmiKeys = wmiClass.keys
	# sys.stderr.write("WmiGetClassKeys keys=%s\n" % ( str(wmiKeys) ) )
	return wmiKeys

# Normally we must find the right namespace, but default value is OK most of times.
def BuildWmiNamespaceClass( entity_namespace, entity_type ):
	wmiNamespace = "root\\CIMV2"
	# Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
	return ( wmiNamespace, entity_type, wmiNamespace + ":" + entity_type )


def WmiBuildMonikerPath( entity_namespace, entity_type, entity_id, cimomSrv ):
	wmiNameSpace, wmiClass, fullClassPth = BuildWmiNamespaceClass( entity_namespace, entity_type )

	# sys.stderr.write("WmiBuildMonikerPath wmiNameSpace=%s entity_namespace=%s entity_id=%s\n" % (wmiNameSpace, entity_namespace, str(entity_id)))

	return fullClassPth + "." + entity_id

def WmiInstanceUrl( entity_namespace, entity_type, entity_id, entity_host):
	# sys.stderr.write("WmiInstanceUrl %s %s %s %s\n" % (entity_namespace, entity_type, entity_id, entity_host))

	wmiFullPath = WmiBuildMonikerPath( entity_namespace, entity_type, entity_id, entity_host )

	if wmiFullPath is None:
		return None

	# sys.stderr.write("WmiInstanceUrl wmiFullPath=%s\n" % (wmiFullPath))

	# 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
	wmiMoniker = "\\\\" + entity_host + "\\" + wmiFullPath
	wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, entity_id == "" )

	# sys.stderr.write("WmiInstanceUrl wmiInstanceUrl=%s\n" % (wmiInstanceUrl))
	return wmiInstanceUrl



################################################################################

def NormalHostName(entity_host):
	if entity_host == "":
		# Typically returns "RCHATEAU-HP".
		# Could also use platform.node() or socket.gethostname() or os.environ["COMPUTERNAME"]
		entity_host = socket.gethostname()
	return entity_host

################################################################################

# On renvoie une liste de liens.
# Il faut mapper vers CIM et renvoyer un lien qui affiche les categories etc...
# Dans le contenu de ce lien il faut pouvoir revenir vers nos objets
# de facon homogene vis-a-vis de l'appartenance a WBEM (ou WMI) et nos objets.
def GetWmiUrl( entity_host, entity_namespace, entity_type, entity_id ):
	if not wmi_imported:
		return None

	entity_host = NormalHostName(entity_host)

	sys.stderr.write("GetWmiUrl %s %s %s %s\n" % (entity_host, entity_namespace, entity_type, entity_id))

	# TODO: entity_host = NONE si current.

	if entity_type == "":
		# TODO: In fact this should rather display all classes for this namespace.
		wmiUrl = WmiAllNamespacesUrl( entity_host )
	else:
		wmiUrl = WmiInstanceUrl( entity_namespace, entity_type, entity_id, entity_host)

	return wmiUrl

