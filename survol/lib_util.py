# https://bugs.python.org/issue8704
# If there is a Python problem on OVH mutualised hosting, it returns:
# Response header name '<!--' contains invalid characters, aborting request,
# If the CGI script crashes before finishing the headers, cgitb will emit invalid HTTP headers before showing the error message.
# The workaround is to put: HttpProtocolOptions Unsafe line into the apache .conf


import cgitb
cgitb.enable()

import os
import re
import sys
import cgi
import lib_kbase
import socket
import base64
import importlib

# In Python 3, urllib.quote has been moved to urllib.parse.quote and it does handle unicode by default.
# TODO: Use module six.
try:
	from urllib import quote,unquote
except ImportError:
	from urllib.parse import quote,unquote

################################################################################

# Sometimes we have to display many strings of the same type, for example
# filenames or WMI monikers. These strings are mixes of words and numbers.
# They do not sort naturally well, because the numbers are lexicographically
# sorted. The Python module natsort does that.
# Simple yet flexible natural sorting in Python.
try:
	import natsort
	from natsort import natsort_keygen

	natural_sorted = natsort.natsorted

	def natural_sort_list(one_list,**args):

		natsort_key = natsort_keygen()

		try:
			orig_key = args['key']

			# one_list.sort(**args)
			#return

			args['key'] = lambda in_param: natsort_key(orig_key(in_param))

		except KeyError:
			args['key'] = natsort_key
		one_list.sort(**args)

except ImportError:
	sys.stderr.write("WritePatterned Module natsorted not available.")
	natural_sorted = sorted

	def natural_sort_list(one_list,**args):
		one_list.sort(**args)

################################################################################

# This avoids needing the "six" module which is not always available.
# On some environments, it is a hassle to import it.
if sys.version_info >= (3,):
	def six_iteritems(array):
			return array.items()

	def six_u(aStr):
		return aStr

	six_string_types = str,
	six_integer_types = int,
	#six_class_types = type
	six_text_type = str
	six_binary_type = bytes

	# from six.moves import builtins
else:
	def six_iteritems(array):
		return array.iteritems()

	def six_u(aStr):
		return unicode(aStr.replace(r'\\', r'\\\\'), "unicode_escape")

	six_string_types = basestring,
	six_integer_types = (int, long)
	#six_class_types = (type, types.ClassType)
	six_text_type = unicode
	six_binary_type = str

################################################################################

def NodeLiteral(value):
	return lib_kbase.MakeNodeLiteral(value)

def NodeUrl(url):
	# TODO: Apparently, it is called twice, which is not detected
	# because MakeNodeUrl returns the same string.
	return lib_kbase.MakeNodeUrl(url)

################################################################################

# See xidCgiDelimiter = "?xid="
def EncodeEntityId(entity_type,entity_id):
	return "xid=%s.%s" % ( entity_type, entity_id )

################################################################################

# unitSI = "B", "b", "B/s" for example.
# TODO: We need a way to describe a number of items, without unit.
# This is different from an integer ID which should always be displayed "as is",
# just like a string.
# We might have units such as "B/B" which are without dimensions.
def AddSIUnit(number, unitSI):
	if unitSI:
		return str(number) + " " + unitSI
	else:
		return str(number)

################################################################################

def HttpPrefix():

	# Default values for ease of testing, so CGI scripts can be run as is from command line..
	try:
		server_addr = os.environ['SERVER_NAME']

		# This is an attempt to fix a problem when running cgiserver.py:
		# * The URL is 127.0.0.1:8000/index.htm
		# * SERVER_NAME="rchateau-hp"
		# * REMOTE_HOST="rchateau-hp"
		# * Pinging rchateau-HP [fe80::3c7a:339:64f0:2161%11]
		#try:
		#	remote_host = os.environ['REMOTE_HOST']
		#	sys.stderr.write("HTTPPrefix remote_host=%s\n" % remote_host)
		#	if server_addr == remote_host:
		#		server_addr = "127.0.0.1"
		#except KeyError:
		#	pass

		#os.environ['REMOTE_ADDR']=127.0.0.1
		#os.environ['SERVER_NAME']=rchateau-HP
		#os.environ['REMOTE_HOST']=rchateau-HP

	except KeyError:
		# Local use .
		server_addr = "127.0.0.1"
	
	try:
		server_port = os.environ['SERVER_PORT']
	except KeyError:
		# Should not happen.
		server_port = "80"

	# BEWARE: Colons are forbidden in URIs apparently !!!
	# Due to a very strange bug which displays:
	# "http://127.0.0.1:80/PythonStyle/survol/entity.py" ...
	# does not look like a valid URI, trying to serialize this will break.
	# But if we do not add "http:" etc... SVG adds its prefix "127.0.0.1" etc...
	prfx = 'http://' + server_addr + ':' + server_port
	# sys.stderr.write("HttpPrefix server_addr=%s prfx=%s\n"%(server_addr,prfx))
	return prfx


def UriRootHelper():
	try:
		# SCRIPT_NAME=/PythonStyle/survol/internals/print.py
		# SCRIPT_NAME=/survol/print_environment_variables.py
		scriptNam=os.environ['SCRIPT_NAME']
		idx = scriptNam.find('survol')
		sys.stderr.write("UriRootHelper scriptNam=%s idx=%d\n"%(scriptNam,idx))
		if idx >= 0:
			root = scriptNam[:idx] + 'survol'
		else:
			# Should not happen.
			root = "/CANNOT_HAPPEN/" + scriptNam
		sys.stderr.write("UriRootHelper scriptNam=%s root=%s\n"%(scriptNam,root))

	except KeyError:
		# If this runs from the command line and not as a CGI script,
		# then this environment variable is not set.
		sys.stderr.write("No SCRIPT_NAME\n")
		root = "/NotRunningAsCgi"
		root = "/CannotNotHappen"
	urh = HttpPrefix() + root
	sys.stderr.write("UriRootHelper urh=%s\n"%urh)
	return urh

uriRoot = UriRootHelper()

################################################################################

# This returns the hostname as a string. Some special processing because on Windows,
# the returned hostname seems truncated.
# See lib_uris.HostnameUri()
def HostName():
	socketGetHostNam = socket.gethostname()

	# TODO: CONTRADICTION !!!???
	if socketGetHostNam.find('.')>=0:
		# 'rchateau-HP'
		name=socketGetHostNam
	else:
		# 'rchateau-HP.home'
		name=socket.gethostbyaddr(socketGetHostNam)[0]
	return name

# hostName
currentHostname = HostName()

# Beware: The machine might have several IP addresses.
try:
	localIP = socket.gethostbyname(currentHostname)
except Exception:
	# Apparently, it happens if the router is down.
	localIP = "127.0.0.1"

def IsLocalAddress(anHostNam):
	# Maybe entity_host="http://192.168.1.83:5988"
	hostOnly = EntHostToIp(anHostNam)
	if hostOnly in [ None, "", "localhost", "127.0.0.1", currentHostname ]:
		# sys.stderr.write("IsLocalAddress %s TRUE\n"%anHostNam)
		return True

	try:
		ipOnly = socket.gethostbyname(hostOnly)
	# socket.gaierror
	except Exception:
		# Unknown machine
		exc = sys.exc_info()[1]
		# sys.stderr.write("IsLocalAddress anHostNam=%s:%s FALSE\n" % ( anHostNam, str(exc) ) )
		return False

	if ipOnly in [ "0.0.0.0", "127.0.0.1", localIP ]:
		# sys.stderr.write("IsLocalAddress %s TRUE\n"%anHostNam)
		return True

	# sys.stderr.write("IsLocalAddress %s FALSE\n"%anHostNam)
	return False

# Beware: lib_util.currentHostname="Unknown-30-b5-c2-02-0c-b5-2.home"
# socket.gethostname() = 'Unknown-30-b5-c2-02-0c-b5-2.home'
# socket.gethostbyaddr(hst) = ('Unknown-30-b5-c2-02-0c-b5-2.home', [], ['192.168.1.88'])
def SameHostOrLocal( srv, entHost ):
	# if ( entHost == srv ) or ( ( entHost is None or entHost in ["","0.0.0.0"] ) and ( localIP == srv ) ) or ( entHost == "*"):
	if ( entHost == srv ) or ( ( entHost is None or entHost in ["","0.0.0.0"] ) and ( localIP == srv ) ):
		# We might add credentials.
		sys.stderr.write("SameHostOrLocal entHost=%s localIP=%s srv=%s SAME\n" % ( entHost, localIP, srv ) )
		return True
	else:
		sys.stderr.write("SameHostOrLocal entHost=%s localIP=%s srv=%s Different\n" % ( entHost, localIP, srv ) )
		return False

################################################################################

def TopUrl( entityType, entityId ):
	""" This returns the top-level URL"""
	try:
		scriptNam = os.environ['SCRIPT_NAME']
	except KeyError:
		scriptNam = "Hello.py"
	if re.match( ".*/survol/entity.py.*", scriptNam ):
		if entityType == "":
			# topUrl = uriRoot + "/../index.htm" # A VERIFIER.
			topUrl = uriRoot + "/entity.py"
		else:
			# Same as in objtypes.py
			# if entityId in ("","Id=") or entity.endswith("="):
			# Not reliable: What does it mean to have "Id=" or "Name=" ?
			if entityId == "" or re.match( "[a-zA-Z_]*=", entityId ):
				topUrl = uriRoot + "/entity.py"
			else:
				topUrl = EntityUri( entityType, "" )
	else:
		topUrl = uriRoot + "/entity.py"
	return topUrl

################################################################################

# This, because graphviz transforms a "\L" (backslash-L) into "<TABLE>". Example:
# http://127.0.0.1/PythonStyle/survol/entity.py?xid=com_type_lib:C%3A%5CWINDOWS%5Csystem32%5CLangWrbk.dll
# Or if the url contains a file in "App\Local"
def EncodeUri(anStr):
	# sys.stderr.write("EncodeUri str=%s\n" % str(anStr) )

	if anStr:
		strTABLE = anStr.replace("\\L","\\\\L")
	else:
		strTABLE = ""

	# In Python 3, urllib.quote has been moved to urllib.parse.quote and it does handle unicode by default.
	if sys.version_info >= (3,):
		# THIS SHOULD NORMALLY BE DONE. BUT WHAT ??
		###strTABLE = strTABLE.replace("&",";;;")

		return quote(strTABLE,'')
	else:

		# THIS SHOULD NORMALLY BE DONE. BUT WHAT ??
		###strTABLE = strTABLE.replace("&","%26")
		# UnicodeDecodeError: 'ascii' codec can't decode byte 0xe9 in position 32
		# strTABLE = unicode( strTABLE, 'utf-8')
		return quote(strTABLE,'ascii')

################################################################################

# OVH
# REQUEST_URI=/cgi-bin/survol/print_environment_variables.py
# SCRIPT_FILENAME=/home/primhilltc/cgi-bin/survol/print_environment_variables.py
# REQUEST_URI=/cgi-bin/survol/print_environment_variables.py

def RequestUri():
	try:
		# If url = "http://primhillcomputers.ddns.net/Survol/survol/print_environment_variables.py"
		# REQUEST_URI=/Survol/survol/print_environment_variables.py
		#sys.stderr.write("RequestUri\n")
		#for k in os.environ:
		#	sys.stderr.write("    key=%s val=%s\n"%(k,os.environ[k]))
		script = os.environ["REQUEST_URI"]
		#sys.stderr.write("RequestUri script=%s\n"%script)
	except KeyError:
		# Maybe this is started from a minimal http server.
		# If url = "http://127.0.0.1:8000/survol/print_environment_variables.py"
		# SCRIPT_NAME=/survol/print_environment_variables.py
		# QUERY_STRING=
		#
		# "/survol/entity.py"
		try:
			script = os.environ['SCRIPT_NAME']
			# "xid=EURO%5CLONL00111310@process:16580"
			queryString = os.environ['QUERY_STRING']
			if queryString:
				script += "?" + queryString
		except KeyError:
			script = "RequestUri: No value"
	return script

################################################################################


# Apparently getcwd() changes during execution, or at least is not stable.
# "C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\htbin\\sources_top"
# SCRIPT_FILENAME=C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/survol/internals/print.py
# REQUEST_URI=/Survol/survol/internals/print.py
# SCRIPT_NAME=/Survol/survol/internals/print.py
# getcwd=C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\htbin\internals
def TopScriptsFunc():
	# TODO: Use __file__ which might be faster ??
	currDir = os.getcwd()

	# TODO: Should search for the right directory ?
	# This simply looks for "survol" if it contains "sources_types".
	# (1) Looks for sources_types. If yes, exists.
	# (2) Looks for survol. If not. exit with failure.
	# (3) iF YES, CD TO IT, THEN GOTO (1).

	urlPrefix = "survol"
	idx = currDir.find(urlPrefix)
	sys.stderr.write("TopScriptsFunc currDir=%s idx=%s\n"%(currDir,idx))

	# Maybe not running in Apache but in http.server (Python 3) or SimpleHttpServer (Python 2)
	if idx == -1:
		return currDir + "//" + urlPrefix
	else:
		# Maybe this is OVH with survolcgi.py: currDir=/home/primhilltc/survol/survol
		# BEWARE: This is a bit dodgy, not sure what do do.
		if currDir.endswith("survol/survol"):
			return currDir
		elif currDir.endswith("Survol\\survol"):
			# Win10, Py3:  currDir="C:\\Users\\rchat\\Survol\\survol"
			return currDir + "\\survol"
		else:
			return currDir[ : idx + len(urlPrefix) ]

gblTopScripts = TopScriptsFunc()

# TODO: This is necessary because now we import modules from htbin.
# TODO: We will also add survol/revlib so it will not be necessary to set PYTHONPATH in Apache httpd.conf.
sys.path.append(gblTopScripts)
# sys.stderr.write("sys.path=%s\n"%str(sys.path))

################################################################################

# Depending on the category, entity_host can have several forms.
# The name is misleading because it returns a host name,
# Which might or might not be an IP.
# TODO: Must be very fast !
def EntHostToIp(entity_host):
	# WBEM: http://192.168.1.88:5988
	#       https://jdd:test@acme.com:5959
	#       http://192.168.1.88:5988
	# TODO: Not sure this will work with IPV6
	mtch_host_wbem = re.match( "https?://([^/:]*).*", entity_host )
	if mtch_host_wbem:
		#sys.stderr.write("EntHostToIp WBEM=%s\n" % mtch_host_wbem.group(1) )
		return mtch_host_wbem.group(1)

	# WMI : \\RCHATEAU-HP
	mtch_host_wmi = re.match( r"\\\\([-0-9A-Za-z_\.]*)", entity_host )
	if mtch_host_wmi:
		#sys.stderr.write("EntHostToIp WBEM=%s\n" % mtch_host_wmi.group(1) )
		return mtch_host_wmi.group(1)

	# sys.stderr.write("EntHostToIp Custom=%s\n" % entity_host )
	return entity_host

# TODO: Coalesce with EntHostToIp
def EntHostToIpReally(entity_host):
	try:
		hostOnly = EntHostToIp(entity_host)
		return socket.gethostbyname(hostOnly)
	except Exception:
		return hostOnly

################################################################################

def ParseXidLocal(xid ):
	"""
		A machine name can contain a domain name : "WORKGROUP\RCHATEAU-HP", the backslash cannot be at the beginning.
		"WORKGROUP\RCHATEAU-HP@CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2"
		"WORKGROUP\RCHATEAU-HP@oracle/table.Name=MY_TABLE"
		BEWARE: This must NOT match "http://127.0.0.1:8000/survol/namespaces_wbem.py?xid=http://192.168.1.83:5988/."
		that is "http://192.168.1.83:5988/."
		mtch_entity = re.match( r"([-0-9A-Za-z_]*\\?[-0-9A-Za-z_\.]*@)?([a-z0-9A-Z_/]*:?[a-z0-9A-Z_/]*)\.(.*)", xid )
		A class name starts with a letter. There are no consecutives slashes "/".
		TODO: Filter when consecutives slashes.
	"""
	mtch_entity = re.match( r"([-0-9A-Za-z_]*\\?[-0-9A-Za-z_\.]*@)?([a-zA-Z_][a-z0-9A-Z_/]*)\.(.*)", xid )

	if mtch_entity:
		if mtch_entity.group(1) == None:
			entity_host = ""
		else:
			entity_host = mtch_entity.group(1)[:-1]

		entity_type = mtch_entity.group(2)
		entity_id_quoted = mtch_entity.group(3)

		# Everything which comes after the dot which follows the class name.
		entity_id = unquote(entity_id_quoted)

		return ( entity_type, entity_id, entity_host )

	return None

def ParseXidWMI(xid ):
	"""
		WMI : \\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="0"
		Beware ! On Windows, namespaces are separated by backslashes.
		WMI : \\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="0"
		http://127.0.0.1:8000/survol/objtypes_wmi.py?xid=\\rchateau-HP\root\CIMV2\Applications%3A.
		http://127.0.0.1:8000/survol/class_wmi.py?xid=\\rchateau-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.
		http://127.0.0.1:8000/survol/entity_wmi.py?xid=\\RCHATEAU-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.Name%3D%22Default%22
		TODO: BEWARE ! If the host name starts with a L, we have to "triplicate" the back-slash
		TODO: otherwise graphviz replace "\L" par "<TABLE">
	"""

	# This matches for example 'root\cimv2:Win32_Process.Handle="0"'
	wmi_regex_local_part = r"([a-zA-Z0-9_]+)\\([^.]*)(\..*)"

	# mtch_ent_wmi = re.match( r"\\\\\\?([-0-9A-Za-z_\.]*)\\([^.]*)(\..*)", xid )
	mtch_ent_wmi = re.match( r"\\\\\\?([-0-9A-Za-z_\.]*)\\" + wmi_regex_local_part, xid )
	if mtch_ent_wmi:
		grp = mtch_ent_wmi.groups()
		entity_host = grp[0]
		entity_type = grp[1] + "\\" + grp[2]
		entity_id_quoted = grp[3]
		# ( entity_host, entity_type, entity_id_quoted ) = grp
		if entity_id_quoted is None:
			entity_id = ""
			# sys.stderr.write("WMI Class Cimom=%s ns_type=%s\n" % ( entity_host, entity_type ))
		else:
			# Remove the dot which comes after the class name.
			entity_id = unquote(entity_id_quoted)[1:]
			# sys.stderr.write("WMI Object Cimom=%s ns_type=%s path=%s\n" % ( entity_host, entity_type, entity_id ))

		return ( entity_type, entity_id, entity_host )

	# WMI : Maybe the host is missing, and implicitely the local machine.
	# http://127.0.0.1:8000/survol/class_type_all.py?xid=root\CIMV2:Win32_Process.
	mtch_ent_wmi = re.match( wmi_regex_local_part, xid )
	if mtch_ent_wmi:
		grp = mtch_ent_wmi.groups()
		entity_host = ""
		entity_type = grp[0] + "\\" + grp[1]
		entity_id_quoted = grp[2]
		if entity_id_quoted is None:
			entity_id = ""
			# sys.stderr.write("WMI Class Cimom=%s ns_type=%s\n" % ( entity_host, entity_type ))
		else:
			# Remove the dot which comes after the class name.
			entity_id = unquote(entity_id_quoted)[1:]
			# sys.stderr.write("WMI Object Cimom=%s ns_type=%s path=%s\n" % ( entity_host, entity_type, entity_id ))

		return ( entity_type, entity_id, entity_host )

	return None

def ParseXidWBEM(xid ):
	"""
		https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"
		http://192.168.1.88:5988/root/PG_Internal:PG_WBEMSLPTemplate
		"http://127.0.0.1:8000/survol/namespaces_wbem.py?xid=http://192.168.1.83:5988/."
		"xid=http://192.168.1.88:5988/."
	"""
	mtch_ent_wbem = re.match( "(https?://[^/]*)/([^.]*)(\..*)?", xid )
	if mtch_ent_wbem:
		#sys.stderr.write("mtch_ent_wbem\n")
		grp = mtch_ent_wbem.groups()
		( entity_host, entity_type, entity_id_quoted ) = grp
		# TODO: SAME LOGIC FOR THE TWO OTHER CASES !!!!!!!!!!!!!!
		if entity_id_quoted is None:
			entity_id = ""
			# sys.stderr.write("WBEM Class Cimom=%s ns_type=%s\n" % ( entity_host, entity_type ))
		else:
			# Remove the dot which comes after the class name.
			entity_id = unquote(entity_id_quoted)[1:]
			# sys.stderr.write("WBEM Object Cimom=%s ns_type=%s path=%s\n" % ( entity_host, entity_type, entity_id ))

		return ( entity_type, entity_id, entity_host )

	return None

def ParseXid(xid ):
	"""
		BEWARE: This cannot work if the hostname contains a ":", see IPV6. MUST BE VERY FAST !!!
		TODO: Should also parse the namespace.
		TODO: Faudrait savoir, avec ou sans le prop=val ???
		ParseXid xid=CIM_ComputerSystem.Name=rchateau-HP
		ParseXid xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2
	"""
	# sys.stderr.write( "ParseXid xid=%s\n" % (xid) )

	# First, we try to match our terminology.
	# The type can be in several directories separated by slashes: "oracle/table"
	# If suffixed with "/", it means namespaces.

	entity_triplet = ParseXidLocal(xid )
	if entity_triplet:
		return entity_triplet

	# Apparently it is not a problem for the plain old entities.
	xid = unquote(xid)

	entity_triplet = ParseXidWMI(xid )
	if entity_triplet:
		return entity_triplet

	entity_triplet = ParseXidWBEM(xid )
	if entity_triplet:
		return entity_triplet

	# sys.stderr.write( "ParseXid=%s RETURNS NOTHING\n" % (xid) )
	return ( "", "", "" )

################################################################################

# TODO: Would probably be faster by searching for the last "/".
# MUST BE VERY FAST.
# '\\\\RCHATEAU-HP\\root\\cimv2:Win32_Process.Handle="0"'  => "root\\cimv2:Win32_Process"
# https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"  => ""
def ParseNamespaceType(ns_entity_type):
	# sys.stderr.write("ParseEntityType entity_type=%s\n" % ns_entity_type )
	nsSplit = ns_entity_type.split(":")
	if len(nsSplit) == 1:
		entity_namespace = ""
		entity_type = nsSplit[0]
	else:
		entity_namespace = nsSplit[0]
		entity_type = nsSplit[1]
	return ( entity_namespace, entity_type, ns_entity_type )

################################################################################

# A bit temporary.
def ScriptizeCimom(path, entity_type, cimom):
	return uriRoot + path + "?" + EncodeEntityId(cimom + "/" + entity_type,"")

# Properly encodes type and id into a URL.
# TODO: Ca va etre un peu un obstacle car ca code vraiment le type d'URL.
# Ne pas utiliser ca pour les Entity.
def Scriptize(path, entity_type, entity_id):
	return uriRoot + path + "?" + EncodeEntityId(entity_type,entity_id)

################################################################################

xidCgiDelimiter = "?xid="

def EntityClassUrl(entity_type, entity_namespace = "", entity_host = "", category = ""):
	if entity_type is None:
		entity_type = ""

	# WBEM: https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"
	if category == "WBEM":
		monikerClass = entity_host + "/" + entity_namespace + ":" + entity_type + "."
	# WMI : \\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="0"
	elif category == "WMI":
		monikerClass = "\\\\" + entity_host + "\\" + entity_namespace + ":" + entity_type + "."
	# This is temporary.
	else:
		# We could simplify the format, if no namespace nor hostname.
		monikerClass = ""
		if entity_host:
			monikerClass += entity_host + "@"
		# Should not happen.
		if entity_namespace:
			monikerClass += entity_namespace + "/:"
		monikerClass += entity_type + "."

	# TODO: See also EntityUrlFromMoniker.

	url = uriRoot + "/class_type_all.py" + xidCgiDelimiter + EncodeUri(monikerClass)
	return url

def EntityClassNode(entity_type, entity_namespace = "", entity_host = "", category = ""):
	url = EntityClassUrl(entity_type, entity_namespace, entity_host, category)

	# sys.stdout.write("EntityClassUrl url=%s\n" % url)
	return NodeUrl( url )

################################################################################
# TODO: What about the namespace ?

def EntityUriFromDict(entity_type,entity_ids_kvp):
	entity_id = ",".join( "%s=%s" % ( pairKW, entity_ids_kvp[pairKW] ) for pairKW in entity_ids_kvp )

	url = Scriptize("/entity.py", entity_type, entity_id )
	return NodeUrl( url )

# This is the most common case. Shame we call the slower function.
def EntityUri(entity_type,*entity_ids):
	return EntityUriDupl( entity_type, *entity_ids )

def EntityUriDupl(entity_type,*entity_ids,**extra_args):
	# sys.stderr.write("EntityUriDupl %s\n" % str(entity_ids))

	keys = OntologyClassKeys(entity_type)

	if len(keys) != len(entity_ids):
		sys.stderr.write("EntityUriDupl Different lens:%s and %s\n" % (str(keys),str(entity_ids)))
	entity_id = ",".join( "%s=%s" % pairKW for pairKW in zip( keys, entity_ids ) )
	
	# Extra arguments, differentiating duplicates.
	entity_id += "".join( ",%s=%s" % ( extArg, extra_args[extArg] ) for extArg in extra_args )

	url = Scriptize("/entity.py", entity_type, entity_id )
	return NodeUrl( url )

################################################################################

# Probably not necessary because we apparently always know
# if we need a WMI, WBEM or custom scripts. Not urgent to change this.
def EntityScriptFromPath(monikerEntity,is_class,is_namespace,is_hostname):
	if monikerEntity[0] == '\\':
		entIdx = 0
	elif monikerEntity[0:4] == 'http':
		entIdx = 1
	else:
		entIdx = 2

	if is_hostname:
		return ('namespaces_wmi.py','namespaces_wbem.py','entity.py')[ entIdx ]
	elif is_namespace:
		return ('objtypes_wmi.py','objtypes_wbem.py','objtypes.py')[ entIdx ]
	elif is_class:
		return ('class_wmi.py','class_wbem.py','class_type_all.py')[ entIdx ]
	else:
		return ('entity_wmi.py','entity_wbem.py','entity.py')[ entIdx ]

# Le parsing devra etre beaucoup plus performant.
# TODO: Creer trois fonctions un peu comme EntityClassUrl, car on connait toujorus la categorie.
def EntityUrlFromMoniker(monikerEntity,is_class=False,is_namespace=False,is_hostname=False):
	scriptPath = EntityScriptFromPath(monikerEntity,is_class,is_namespace,is_hostname)

	# sys.stderr.write("EntityUrlFromMoniker scriptPath=%s\n"%scriptPath)
	# url = uriRoot + "/" + scriptPath + "?xid=" + EncodeUri(monikerEntity)
	url = uriRoot + "/" + scriptPath + xidCgiDelimiter + EncodeUri(monikerEntity)
	return url

# Full natural path: We must try to merge it with WBEM Uris.
# '\\\\RCHATEAU-HP\\root\\cimv2:Win32_Process.Handle="0"'
# https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"

################################################################################

# This creates a "derived type", on  the fly.
# This could fill the various caches: Ontology etc...
CharTypesComposer = "/"

# TODO: Find another solution more compatible with WBEM and WMI logic.
# Used to define subtypes.
def ComposeTypes(t1,t2):
	return t1 + CharTypesComposer + t2

################################################################################

def CopyFile( mime_type, fileName ):

	# read and write by chunks, so that it does not use all memory.
	filDes = open(fileName, 'rb')

	globalOutMach.HeaderWriter( mime_type )

	outFd = globalOutMach.OutStream()
	while True:
		chunk = filDes.read(1000000)
		if not chunk:
			break
		outFd.write( chunk )
	outFd.flush()
	filDes.close()


################################################################################

# By the way, when calling a RDF source, we should check the type of the
# MIME document and if this is not RDF, the assumes it's an error 
# which must be displayed.
# This is used as a HTML page but also displayed in Javascript in a DIV block.
# TODO: Change this for WSGI.
def InfoMessageHtml(message):
	sys.stderr.write("InfoMessageHtml:%s\n"%message)
	globalOutMach.HeaderWriter("text/html")

	sys.stderr.write("InfoMessageHtml:Sending content\n")
	WrtAsUtf(
		"<html><head><title>Error: Process=%s</title></head>"
		% str(os.getpid()) )

	WrtAsUtf("<body>")

	WrtAsUtf("<b>" + message + "</b><br>")

	# On Linux it says: "OSError: [Errno 2] No such file or directory"
	WrtAsUtf('<table>')

	if sys.version_info >= (3,):
		WrtAsUtf("<tr><td>Login</td><td>%s</td></tr>"%os.getlogin())

	WrtAsUtf("<tr><td>Cwd</td><td>%s</td></tr>" % os.getcwd())
	WrtAsUtf("<tr><td>OS</td><td>%s</td></tr>"%sys.platform)
	WrtAsUtf("<tr><td>Version</td><td>%s</td></tr>"%sys.version)
	
	WrtAsUtf('</table>')

	# http://desktop-ni99v8e:8000/survol/www/configuration.htm
	# envsUrl = uriRoot + "/www/configuration.htm"
	configUrl = uriRoot + "/edit_configuration.py"
	WrtAsUtf('<a href="%s">Setup</a>.<br>'%configUrl)
	envsUrl = uriRoot + "/print_environment_variables.py"
	WrtAsUtf('<a href="%s">Environment variables</a>.<br>'%envsUrl)
	homeUrl = TopUrl( "", "" )
	WrtAsUtf('<a href="%s">Return home</a>.<br>'%homeUrl)

	WrtAsUtf("""
	</body></html>
	""")
	sys.stderr.write("InfoMessageHtml:Leaving\n")

################################################################################

# Returns the list of available object types: ["process", "file," group", etc...]
def ObjectTypesNoCache():
	# directory=C:\\Users\\rchateau\\Developpement\\ReverseEngineeringApps\\PythonStyle\\htbin\\sources_top/sources_types\r:
	directory = gblTopScripts + "/sources_types"
	sys.stderr.write("ObjectTypesNoCache directory="+directory+"\n")

	ld = len(directory)
	for path, dirs, files in os.walk(directory):
		if len(path) == ld:
			prefix = ""
		else:
			prefix = path[ld +1:].replace("\\","/") + "/"
		for dir in dirs:
			if dir != "__pycache__":
				yield prefix + dir

glbObjectTypes = None

# TODO: Should concatenate this to localOntology. Default value is "Id".
def ObjectTypes():
	global glbObjectTypes

	if glbObjectTypes is None:
		glbObjectTypes = set( ObjectTypesNoCache() )
		# sys.stderr.write("ObjectTypes glbObjectTypes="+str(glbObjectTypes)+"\n")

	return glbObjectTypes

################################################################################

# These functions are used in scripts, to tell if it is usable or not.

isPlatformLinux = 'linux' in sys.platform
isPlatformWindows = 'win' in sys.platform

def UsableLinux(entity_type,entity_ids_arr):
	"""Linux only"""
	return isPlatformLinux

def UsableWindows(entity_type,entity_ids_arr):
	"""Windows only"""
	return isPlatformWindows

def UsableAsynchronousSource(entity_type,entity_ids_arr):
	"""Asychronous data source"""
	return False

# Tells if a file is executable code or library.
# TODO: This function should be moved to CIM_DataFile/__init__.py
def UsableWindowsBinary(entity_type,entity_ids_arr):
	"""Windows executable or code file"""
	if not UsableWindows(entity_type,entity_ids_arr):
		return False
	fulFileName = entity_ids_arr[0]
	if os.path.isdir(fulFileName):
		return False
	filename, file_extension = os.path.splitext(fulFileName)
	# TODO: Must add library type for ELF and PE ?
	return file_extension.upper() in [".EXE", ".DLL", ".COM", ".OCX", ".SYS", ".ACM", ".BPL", ".DPL"]

# Applies for nm, dll, elftools.
def UsableLinuxBinary(entity_type,entity_ids_arr):
	"""Linux executable or code file"""
	if not UsableLinux(entity_type,entity_ids_arr):
		return False
	fulFileName = entity_ids_arr[0]
	if os.path.isdir(fulFileName):
		return False
	filename, file_extension = os.path.splitext(fulFileName)
	# TODO: Must add library type for ELF and PE ?
	if file_extension in [".so", ".lib"]:
		return True
	# TODO: Finish this. Use "magic" module ??
	return True
	
	
################################################################################

# This describes for each entity type, the list of parameters names needed
# to define an object of this class. For example:
# "dbus/connection"     : ( ["Bus","Connect"], ),
# "dbus/interface"      : ( ["Bus","Connect","Obj","Itf"], ),
# "symbol"              : ( ["Name","File"], ), # Must be defined here, not in the module.
localOntology = {
}

# The key must match the DMTF standard. It might contain a namespace.
# TODO: Replace this by a single lookup in a single dict
# TODO: ... made of localOntology added to the directory of types.
def OntologyClassKeys(entity_type):
	# sys.stderr.write("OntologyClassKeys entity_type=%s Caller=%s\n"%(entity_type, sys._getframe(1).f_code.co_name))

	try:
		# TODO: Temporarily until we do something more interesting, using the subtype.
		# entity_type = entity_type.split(CharTypesComposer)[0]

		# TODO: If cannot find it, load the associated module and retry.
		return localOntology[ entity_type ][0]
	except KeyError:
		pass

	# Maybe the ontology is defined in the related module if it exists.
	entity_module = GetEntityModule(entity_type)
	if 	entity_module:
		try:
			entity_ontology_all = entity_module.EntityOntology()
			localOntology[ entity_type ] = entity_ontology_all
			# sys.stderr.write("OntologyClassKeys entity_type=%s loaded entity_ontology_all=%s\n" % (entity_type,str(entity_ontology_all)))
			return entity_ontology_all[0]
		except AttributeError:
			pass

	# This could be replaced by a single lookup.
	return []

# Used for calling ArrayInfo. The order of arguments is strict.
def EntityIdToArray( entity_type, entity_id ):
	ontoKeys = OntologyClassKeys(entity_type)
	sys.stderr.write("EntityIdToArray entity_type=%s entity_id=%s\n"%(entity_type,entity_id))
	dictIds = SplitMoniker( entity_id )
	# sys.stderr.write("EntityIdToArray dictIds=%s\n" % ( str(dictIds) ) )
	# For the moment, this assumes that all keys are here.
	# Later, drop this constraint and allow WQL queries.
	try:
		def DecodeCgiArg(aKey):
			sys.stderr.write("DecodeCgiArg aKey=%s type=%s dictIds=%s\n"%(aKey,type(aKey),str(dictIds)))
			aValRaw = dictIds[ aKey ]
			try:
				valDecod = aKey.ValueDecode(aValRaw)
				sys.stderr.write("DecodeCgiArg aKey=%s valDecod=%s\n"%(aKey,valDecod))
				return valDecod
			except AttributeError:
				return aValRaw
		return [ DecodeCgiArg( aKey ) for aKey in ontoKeys ]
		# return [ dictIds[ aKey ] for aKey in ontoKeys ]
	except KeyError:
		sys.stderr.write("EntityIdToArray missing key: type=%s id=%s onto=%s\n"
						 % ( entity_type , entity_id, str(ontoKeys) ) )
		raise


################################################################################

# Adds a key value pair at the end of the url with the right delimiter.
# TODO: Checks that the argument is not already there.
# TODO: Most of times, it is used for changing the mode.
def ConcatenateCgi(url,keyvalpair):
	if url.rfind( '?' ) == -1:
		return url + "?" + keyvalpair
	else:
		return url + "&" + keyvalpair

# This is very primitive and maybe should be replaced by a standard function,
# but lib_util.EncodeUri() replaces "too much", and SVG urls cannot encode an ampersand...
# The problems comes from "&mode=edit" or "&mode=html" etc...
# TODO: If we can fix this, then "xid" can be replaced by "entity_type/entity_id"
def UrlToSvg(url):
	return url.replace( "&", "&amp;amp;" )

################################################################################

# In an URL, this replace the CGI parameter "http://....?mode=XXX" by "mode=YYY".
# If there is no such parameter, then it is removed. If the input parameter is
# an empty string, then it is removed from the URLs.
# Used for example as the root in entity.py, obj_types.py and class_type_all.py.
def RequestUriModed(otherMode):
	script = HttpPrefix() + RequestUri()
	return AnyUriModed(script, otherMode)

def AnyUriModed(script, otherMode):

	# mtch_url = re.match("(.*)([\?\&])mode=[a-zA-Z0-9]*(.*)", script)
	mtch_url = re.match("(.*)([\?\&])mode=[^\&]*(.*)", script)

	# mtch_url = re.match("(.*[\?\&]mode=)([a-zA-Z0-9]*)(.*)", script)

	if otherMode:
		if mtch_url:
			edtUrl = mtch_url.group(1) + mtch_url.group(2) + "mode=" + otherMode + mtch_url.group(3)
		else:
			edtUrl = ConcatenateCgi( script, "mode=" + otherMode )
	else:
		# We want to remove the mode.
		if mtch_url:
			if mtch_url.group(2) == '?':
				# "mode" IS the first argument.
				if mtch_url.group(3):
					edtUrl = mtch_url.group(1) + "?" + mtch_url.group(3)[1:]
				else:
					edtUrl = mtch_url.group(1)
			else:
				# "mode" is NOT the first argument.
				edtUrl = mtch_url.group(1) + mtch_url.group(3)
		else:
			# Nothing to do because it has no cgi arguments.
			edtUrl = script

	# TODO: CA DECONNE SI L URL CONTIENT DES BACKSLASHES COMME:
	# "http://127.0.0.1:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A\Program%20Files%20%28x86%29\NETGEAR\WNDA3100v3\WNDA3100v3.EXE"
	return edtUrl

def RootUri():
	callingUrl = RequestUriModed("")
	callingUrl = callingUrl.replace("&","&amp;")
	return NodeUrl(callingUrl)

################################################################################

# Extracts the mode from an URL.
# https://developer.mozilla.org/fr/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
def GetModeFromUrl(url):
	# sys.stderr.write("lib_util.GetModeFromUrl url=%s\n"%url)
	# Maybe it contains a MIME type: application/java-archive,
	# application/vnd.ms-powerpoint, audio/3gpp2, application/epub+zip

#	mtch_url = re.match(".*[\?\&]mode=(mime:[a-zA-Z0-9]*/[-\.a-zA-Z0-9]*).*", url)
#	if mtch_url:
#		return mtch_url.group(1)
#
#	mtch_url = re.match(".*[\?\&]mode=([a-zA-Z0-9]*).*", url)
#	if mtch_url:
#		return mtch_url.group(1)

	mtch_url = re.match(".*[\?\&]mode=([^\&]*).*", url)
	if mtch_url:
		return mtch_url.group(1)
	return ""

# The display mode can come from the previous URL or from a CGI environment.
def GuessDisplayMode():
	arguments = cgi.FieldStorage()
	try:
		try:
			mode = arguments["mode"].value
		except AttributeError:
			# In case there are several mode arguments,
			# hardcode to "info". Consequence of a nasty Javascript bug.
			mode = "info"
		if mode != "":
			return mode
	except KeyError:
		pass

	try:
		# HTTP_REFERER=http://127.0.0.1/PythonStyle/print.py?mode=xyz
		referer = os.environ["HTTP_REFERER"]
		modeReferer = GetModeFromUrl( referer )
		# If we come from the edit form, we should not come back to id.
		# TODO: HOW CAN WE COME BACK TO THE FORMER DISPLAY MODE ??
		if modeReferer != "":
			if modeReferer == "edit":
				# TODO: Should restore the original edit mode.
				# EditionMode
				return ""
			else:
				return modeReferer

	except KeyError:
		pass

	try:
		# When called from another module, cgi.FieldStorage might not work.
		script = os.environ["SCRIPT_NAME"]
		mode = GetModeFromUrl( script )
		if mode != "":
			return mode
	except KeyError:
		pass

	mode = ""
	return mode

################################################################################

# Concatenate key-value pairs to build the path of a WMI or WBEM moniker.
# TODO: SHOULD WE WRAP VALUES IN DOUBLE-QUOTES ?????
def BuildMonikerPath(dictKeyVal):
	return ','.join( [ '%s=%s' % ( wbemKey, dictKeyVal[wbemKey] ) for wbemKey in dictKeyVal ] )


# Slight modification from  http://stackoverflow.com/questions/16710076/python-split-a-string-respect-and-preserve-quotes
# 'Id=NT AUTHORITY\SYSTEM'         => ['Id=NT AUTHORITY\\SYSTEM']
# 'Id="NT =\\"AUTHORITY\SYSTEM"'   => ['Id=NT AUTHORITY\\SYSTEM']
def SplitMoniker(xid):
	# sys.stderr.write("SplitMoniker xid=%s\n" % xid )

	# spltLst = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', xid)
	spltLst = re.findall(r'(?:[^,"]|"(?:\\.|[^"])*")+', xid)

	# sys.stderr.write("SplitMoniker spltLst=%s\n" % ";".join(spltLst) )

	resu = dict()
	for spltWrd in spltLst:
		mtchEqualQuote = re.match(r'([A-Z0-9a-z_]+)="(.*)"', spltWrd)
		if mtchEqualQuote:
			# If there are quotes, they are dropped.
			resu[ mtchEqualQuote.group(1) ] = mtchEqualQuote.group(2)
		else:
			mtchEqualNoQuote = re.match(r'([A-Z0-9a-z_]+)=(.*)', spltWrd)
			if mtchEqualNoQuote:
				resu[ mtchEqualNoQuote.group(1) ] = mtchEqualNoQuote.group(2)

	# sys.stderr.write("SplitMoniker resu=%s\n" % str(resu) )

	return resu

# Builds a SQL query.
def SplitMonikToWQL(splitMonik,className):
	sys.stderr.write("splitMonik=[%s]\n" % str(splitMonik) )
	aQry = 'select * from %s ' % className
	qryDelim = "where"
	for qryKey in splitMonik:
		qryVal = splitMonik[qryKey]
		aQry += ' %s %s="%s"' % ( qryDelim, qryKey, qryVal )
		qryDelim = "and"

	sys.stderr.write("Query=%s\n" % aQry )
	return aQry

def Base64Encode(text):
	if sys.version_info >= (3,):
		return base64.urlsafe_b64encode(text.encode('utf-8')).decode('utf-8')
	else:
		return base64.urlsafe_b64encode(text)

def Base64Decode(text):
	# The padding might be missing which is not a problem:
	# https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
	missing_padding = len(text) % 4

	try:
		if sys.version_info >= (3,):
			if missing_padding != 0:
				text += '=' * (4 - missing_padding)
			resu = base64.urlsafe_b64decode(text.encode('utf-8')).decode('utf-8')
		else:
			if missing_padding != 0:
				text += b'=' * (4 - missing_padding)
			resu = base64.urlsafe_b64decode(str(text))
		return resu
	except Exception:
		exc = sys.exc_info()[1]
		sys.stderr.write("CANNOT DECODE: symbol=(%s):%s\n"%(text,str(exc)))
		return text + ":" + str(exc)

################################################################################

if sys.version_info >= (3,):
	outputHttp = sys.stdout.buffer
else:
	outputHttp = sys.stdout

################################################################################

# This is for WSGI compatibility.
class OutputMachineCgi:
	def __init__(self):
		pass

	def HeaderWriter(self,mimeType,extraArgs= None):
		sys.stderr.write("OutputMachineCgi.WriteHeadContentType:%s\n"%mimeType)
		HttpHeaderClassic(outputHttp,mimeType,extraArgs)

	def OutStream(self):
		return outputHttp

# WSGI changes this to another object with same interface.
# Overriden in wsgiserver.py.
globalOutMach = OutputMachineCgi()

################################################################################

# This parameter in the display page of an object (entity.py),
# indicates if all scripts which can operate on this object, must be displayed,
# whether they can work or not.
# By default, it is False.
# For example, a script running on a Windows platform should not be displayed
# when running on Linux. Or if a specific Python module is needed,
# scripts using it should not be displayed. Same if the script has a syntax
# error. By setting this flag, it is easy to understand which scripts
# could be used and why they are not displayed.
paramkeyShowAll = "Show all scripts"

################################################################################

# Default destination for the RDF, HTML or SVG output.
def DfltOutDest():
	return globalOutMach.OutStream()

# Needed also because of sockets.
def WrtAsUtf(str):
	# TODO: try to make this faster. Should be conditional just like HttpHeader.
	outputHttp.write( str.encode('utf-8') )

# For asynchronous display.
# TODO: NEVER TESTED, JUST TEMP SYNTAX FIX.
def SetDefaultOutput(wFile):
	outputHttp = wFile

# contentType = "text/rdf", "text/html", "image/svg+xml", "application/json" etc...
def HttpHeaderClassic( out_dest, contentType, extraArgs = None):
	# sys.stderr.write("HttpHeader:%s\n"%contentType)
	# TODO: out_dest should always be the default output.

	stri = "Content-Type: " + contentType + "; charset=utf-8\n"
	if extraArgs:
		for linArg in extraArgs:
			stri += linArg + "\n"
	stri += "\n"

	# Python 3.2
	try:
		out_dest.write( stri )
		return
	except TypeError:
		pass

	out_dest.write( stri.encode() )

#def HttpHeader( out_dest, contentType ):
#	globalOutMach.OutStream()

def WrtHeader(mimeType,extraArgs = None):
	globalOutMach.HeaderWriter(mimeType,extraArgs)

################################################################################

def GetEntityModuleNoCache(entity_type):
	# sys.stderr.write("GetEntityModuleNoCache entity_type=%s\n"%entity_type)

	try:
		# Here, we want: "sources_types/Azure/location/__init__.py"
		# Example: entity_type = "Azure.location"
		# This works.
		# entity_module = importlib.import_module( ".subscription", "sources_types.Azure")

		entity_type_split = entity_type.split("/")
		if len(entity_type_split) > 1:
			entity_package = "sources_types." + ".".join(entity_type_split[:-1])
			entity_name = "." + entity_type_split[-1]
		else:
			entity_package = "sources_types"
			entity_name = "." + entity_type
		# sys.stderr.write("Loading from new hierarchy entity_name=%s entity_package=%s\n:"%(entity_name,entity_package))
		entity_module = importlib.import_module( entity_name, entity_package)
		# sys.stderr.write("Loaded OK from new hierarchy entity_name=%s entity_package=%s\n:"%(entity_name,entity_package))
		return entity_module

	except ImportError:
		exc = sys.exc_info()[1]
		sys.stderr.write("GetEntityModuleNoCache entity_type=%s Loading (%s):%s\n"%(entity_type,entity_package,str(exc)))
		pass

	# sys.stderr.write("Info:Cannot find entity-specific library:"+entity_lib+"\n")
	return None

# So we try to load only once.
cacheEntityToModule = dict()
cacheEntityToModule[""] = None

# Maybe we could return an array because of heritage ?
# Or:  GetEntityModuleFunction(entity_type,functionName):
# ... which would explore from bottom to top.
def GetEntityModule(entity_type):
	# sys.stderr.write("PYTHONPATH="+os.environ['PYTHONPATH']+"\n")
	# sys.stderr.write("sys.path="+str(sys.path)+"\n")
	# sys.stderr.write("GetEntityModule entity_type=%s Caller=%s\n"%(entity_type, sys._getframe(1).f_code.co_name))

	try:
		# Might be None if the module does not exist.
		return cacheEntityToModule[ entity_type ]
	except KeyError:
		pass
	entity_module = GetEntityModuleNoCache(entity_type)
	cacheEntityToModule[ entity_type ] = entity_module
	return entity_module

# This loads a script as a module. Example:
# currentModule="sources_types.win32" fil="enumerate_top_level_windows.py"
def GetScriptModule(currentModule, fil):
	# TODO: IT DOES NOT START FROM "/revlib". DIFFICULTY WITH PYTHONPATH.
	# Sanity check
	if fil[-3:] != ".py":
		sys.stderr.write("GetScriptModule module=%s fil=%s not a Python script" % ( currentModule, fil ))
		return None
	subClass = "." + fil[:-3] # Without the ".py" extension.
	# sys.stderr.write("currentModule=%s fil=%s\n" % ( currentModule, fil ) )
	if sys.version_info >= (3, ):
		# Example: importlib.import_module("sources_top.Databases.mysql_processlist")
		importedMod = importlib.import_module(currentModule + subClass)
	else:
		if currentModule:
			importedMod = importlib.import_module(subClass, currentModule )
		else:
			# Just the file name without the extension ".py"
			importedMod = importlib.import_module(fil[:-3] )
	return importedMod


################################################################################

def FromModuleToDoc(importedMod,filDfltText):
	"""
		Returns the doc string of a module as a literal node. Possibly truncated
		so it can be displayed.
	"""
	try:
		docModuAll = importedMod.__doc__
		# Take only the first non-empty line.
		docModuSplit = docModuAll.split("\n")
		docModu = None
		for docModu in docModuSplit:
			if docModu 	:
				# sys.stderr.write("DOC="+docModu)
				maxLen = 40
				if len(docModu) > maxLen:
					docModu = docModu[0:maxLen] + "..."
				break
	except:
		docModu = ""

	if not docModu:
		# If no doc available, just transform the file name.
		docModu = filDfltText.replace("_"," ").capitalize()

	nodModu = NodeLiteral(docModu)

	return nodModu

# This creates a non-clickable node. The text is taken from __doc__ if it exists,
# otherwise the file name is beautifuled.
def DirDocNode(argDir,dir):
	# sys.stderr.write("DirDocNode argDir=%s dir=%s\n"%(argDir,dir))
	fullModule = argDir + "." + dir

	try:
		importedMod = importlib.import_module(fullModule)
	except ImportError:
		return None

	# Add three characters otherwise it is truncated just like a Python file extension.
	return FromModuleToDoc(importedMod,dir)

def AppendNotNoneHostname(script,hostname):
	strUrl = uriRoot + script
	if hostname:
		# The string "portal" is just there to have a nice title.
		# xidCgiDelimiter
		# strUrl += '?xid=' + hostname + "@portal."
		strUrl += xidCgiDelimiter + hostname + "@portal."
	return strUrl

# Point to the WBEM portal for a given machine.
def UrlPortalWbem(hostname=None):
	strUrl = AppendNotNoneHostname('/portal_wbem.py',hostname)
	sys.stderr.write("UrlPortalWbem strUrl=%s\n"%strUrl)
	nodePortal = NodeUrl( strUrl )
	return nodePortal

# Point to the WMI portal for a given machine.
def UrlPortalWmi(hostname=None):
	strUrl = AppendNotNoneHostname('/portal_wmi.py',hostname)
	nodePortal = NodeUrl( strUrl )
	return nodePortal

# This is used to split a string made of several lines separated by a "\n",
# following multi-line DocString convention.
# "Multi-line docstrings consist of a summary line just like a one-line docstring,
# followed by a blank line, followed by a more elaborate description.
# The summary line may be used by automatic indexing tools;
# it is important that it fits on one line and is separated from the rest of the docstring by a blank line.
# The summary line may be on the same line as the opening quotes or on the next line.
# The entire docstring is indented the same as the quotes at its first line (see example below)."
# The only difference is that the blank line is not needed, but can be there.
def SplitTextTitleRest(title):
	title_split = title.strip().split("\n")

	page_title_first = title_split[0].strip()
	page_title_rest = " ".join( title_split[1:] ).strip()

	return (page_title_first,page_title_rest)

