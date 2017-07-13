import re
import os
import sys
import pywbem # Might be pywbem or python3-pywbem.
import lib_util
import lib_common
import lib_credentials

################################################################################

# TODO: Build a moniker with cimom added at the beginning.
def WbemAllNamespacesUrl(srvr):
	return lib_util.ScriptizeCimom( '/namespaces_wbem.py', "", srvr )

def BuildWbemNamespaceClass( entity_namespace, entity_type ):
	wbemNamespace = entity_namespace
	# Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
	return ( wbemNamespace, entity_type, wbemNamespace + ":" + entity_type )

def BuildWbemMoniker( hostname, namespac = "", classNam = "" ):
	# Sometimes one is null
	# return hostname + "/" + namespac + ":" + classNam + "."
	return "%s/%s:%s." % ( hostname, namespac, classNam )

# TODO: Build a moniker with cimom added at the beginning.
# J ai des doutes sur cette fonction qui est pourtant utilisee deux fois.
def NamespaceUrl(nskey,cimomUrl,classNam=""):
	wbemMoniker = BuildWbemMoniker( cimomUrl, nskey, classNam )
	wbemInstanceUrl = lib_util.EntityUrlFromMoniker( wbemMoniker, True, True )
	return wbemInstanceUrl

def ClassUrl(nskey,cimomUrl,classNam):
	wbemMoniker = BuildWbemMoniker( cimomUrl, nskey, classNam )
	wbemInstanceUrl = lib_util.EntityUrlFromMoniker( wbemMoniker, True )
	return wbemInstanceUrl

def WbemBuildMonikerPath( entity_namespace, entity_type, entity_id ):
	wbemNameSpace, wbemClass, fullClassPth = BuildWbemNamespaceClass( entity_namespace, entity_type )
	# sys.stderr.write("WbemBuildMonikerPath wbemNameSpace=%s entity_namespace=%s entity_id=%s\n" % (wbemNameSpace, entity_namespace, str(entity_id)))
	return fullClassPth + "." + entity_id

def WbemInstanceUrl( entity_namespace, entity_type, entity_id, cimomSrv ):
	# sys.stderr.write("WbemInstanceUrl %s %s %s %s\n" % (entity_namespace, entity_type, entity_id, cimomSrv))

	wbemFullPath = WbemBuildMonikerPath( entity_namespace, entity_type, entity_id )

	if wbemFullPath is None:
		return None

	# 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
	wbemMoniker = cimomSrv + "/" + wbemFullPath

	wbemInstanceUrl = lib_util.EntityUrlFromMoniker( wbemMoniker, entity_id == "" )
	return wbemInstanceUrl

# Returns the list of a keys of a given WBEM class. This is is used if the key is not given
# for an entity. This could be stored in a cache for better performance.
def WbemGetClassKeys( wbemNameSpace, wbemClass, cimomSrv ):
	# sys.stderr.write("WbemGetClassKeys wbemNameSpace=%s wbemClass=%s cimomSrv=%s\n" % (wbemNameSpace, wbemClass, cimomSrv ))
	wbemCnnct = WbemConnection(cimomSrv)

	# >>> conn = pywbem.WBEMConnection( "http://192.168.1.88:5988" , ('pegasus','toto') )
	# >>> conn.GetClass("CIM_MediaPresent",namespace="root/cimv2")
	# CIMClass(classname=u'CIM_MediaPresent', ...)

	try:
		wbemClass = wbemCnnct.GetClass(wbemClass,
				namespace=wbemNameSpace,
				LocalOnly=False,
				IncludeQualifiers=False)
	except Exception:
		exc = sys.exc_info()[1]
		sys.stderr.write("WbemGetClassKeys %s %s %s: Caught:%s\n" % ( cimomSrv, wbemNameSpace, wbemClass, str(exc) ) )
		return None

	keys = wbemClass.properties.keys()
	# sys.stderr.write("WbemGetClassKeys keys=%s\n" % ( str(keys) ) )
	return keys

################################################################################

# TODO: Unfortunately cannot make SLP work properly.
def slp_wbem_services():
	filter = "wbem"
	#  "/drives/c/Program Files (x86)/OpenSLP/slptool.exe"
	cmd = 'slptool findsrvs service:' + filter

	# TODO: DEBUGGING PURPOSE. FIX THIS.
	cmd = '"C:/Program Files (x86)/OpenSLP/slptool.exe" findsrvs service:' + filter

	stream = os.popen(cmd)
	# service:ftp.smallbox://192.168.100.1:21,65535
	for line in stream:
		matchObj = re.match( r'service:([^:]*):/?/?([^,]*)(.*)', line, re.M|re.I)
		if matchObj:
			yield {
					"name" : matchObj.group(1) , # "wbem"
					"url"  : matchObj.group(2) , # Starts with "http:" or "https:"
					"rest" : matchObj.group(3) }
		else:
			raise Exception("Invalid line "+line)
	resu = stream.close()

	if resu is not None:
		raise Exception("Error running "+cmd)

# TODO: Alternate methods to discover WBEM servers:
# TODO:   - Ping machines with WBEM port numbers 5988 and 5989.
# TODO: Will be stored in the cache filled with SLP discovery, with credentials.
# http://192.168.1.83:5988 	index 	Namespaces
# https://192.168.1.83:5989 	index 	Namespaces
# Should use SLP.
# TODO: CHANGE THIS !
# TODO: Emulate the protocol with Jquery and Javascript, if it is HTTP.
def WbemServersList():
	hardcoded_list_of_wbem_servers = [
		( "192.168.1.83", "http://192.168.1.83:5988" ),
		( "192.168.1.88", "http://192.168.1.88:5988" )
	]
	return hardcoded_list_of_wbem_servers

# This returns the WBEM server of a machine.
# TODO: This should try also the SSL port number 5989,
# check if credentials are available etc...
def HostnameToWbemServer(hostname):
	entity_ip_addr = lib_util.EntHostToIpReally(hostname)

	return "http://" + entity_ip_addr + ":5988"

################################################################################


# On renvoie une liste de liens. Eventuellement type est nul.
# On pourrait aussi bien avoir deux fonctions differentes.
# Maybe entity_namespace does not have the right separator, slash or backslash.
def GetWbemUrls( entity_host, entity_namespace, entity_type, entity_id ):
	sys.stderr.write("GetWbemUrls h=%s ns=%s t=%s i=%s\n" % (entity_host, entity_namespace, entity_type, entity_id))
	wbem_urls_list = []

	entity_ip_addr = lib_util.EntHostToIpReally(entity_host)

	# sys.stderr.write("GetWbemUrls entity_ip_addr=%s\n" % (entity_ip_addr))

	# TODO: Ce ne sont pas les bons parametres,
	# mais une possibilite est de passer les autres, dans un RemoteEntityId.

	#entity_wbem.py en plus des parametes CIM a besoin de l url du CIMON
	#Fabriquer un RemoteEntityId ?
	#Mettre dans RemoteEntityId non seulement l id mais les autres proprietes ?
	#On ne peut pas mettre de & dans les liens graphviz apparemment a cause d un bug.

	# TODO: Verifier que l entite existe en tant que class WBEM. Sinon on renvoie une liste vide.
	# TODO: C EST TOUT LE PROBLEME DU MAPPING DES CLASSES ET PROPERTIES.

	for wbemServer in WbemServersList():
		# TODO: Horribly slow.
		if not lib_util.SameHostOrLocal( wbemServer[0], entity_ip_addr ):
			continue

		theCimom = wbemServer[1]

		# TODO: When running from cgiserver.py, and if QUERY_STRING is finished by a dot ".", this dot
		# TODO: is removed. Workaround: Any CGI variable added after.
		# TODO: Also: Several slashes "/" are merged into one.
		# TODO: Example: "xid=http://192.168.1.83:5988/." becomes "xid=http:/192.168.1.83:5988/"
		# TODO: Replace by "xid=http:%2F%2F192.168.1.83:5988/."
		# Maybe a bad collapsing of URL ?
		theCimom = theCimom.replace("http://","http:%2F%2F").replace("https://","https:%2F%2F")

		# On suppose que les classes sont les memes.
		if entity_type == "":
			# TODO: This should rather display all classes for this namespace.
			wbemUrl = WbemAllNamespacesUrl( theCimom )
		else:
			# Unique script for all types of entities.
			# TODO: Pass the cimom as a host !!!
			wbemUrl = WbemInstanceUrl( entity_namespace, entity_type, entity_id, theCimom)

		if wbemUrl is None:
			continue
		wbem_urls_list.append( ( wbemUrl, wbemServer[0] ) )

	return wbem_urls_list

# conn = pywbem.WBEMConnection("http://192.168.1.83:5988" , ('','') )
# wbemKlass = conn.GetClass("oracle_package_body", namespace="", LocalOnly=False, IncludeQualifiers=True)
def WbemConnection(cgiUrl):
	try:
		creden = lib_credentials.GetCredentials( "WBEM", cgiUrl )

		# ATTENTION: Si probleme de connection, on ne le voit pas ici mais au moment du veritable acces.
		conn = pywbem.WBEMConnection(cgiUrl , creden )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Connecting to :"+cgiUrl+" Caught:"+str(exc)+"<br>")

	# TestCookie(url)
	return conn

def WbemGetClassObj(connWbem,entity_type,wbemNamespace):
	try:
		wbemKlass = connWbem.GetClass(entity_type, namespace=wbemNamespace, LocalOnly=False, IncludeQualifiers=True)
		return wbemKlass
	except Exception:
		return None
		# exc = sys.exc_info()[1]
		# lib_common.ErrorMessageHtml("WbemGetClassObj GetClass: ns="+wbemNamespace+" class="+entity_type+". Caught:"+str(exc))

################################################################################

def WbemClassDescrFromClass(wbemKlass):
	try:
		return wbemKlass.qualifiers['Description'].value
	except Exception:
		exc = sys.exc_info()[1]
		return "Caught:"+str(exc)

def WbemClassDescription(connWbem,entity_type,wbemNamespace):
	try:
		wbemKlass = connWbem.GetClass(entity_type, namespace=wbemNamespace, LocalOnly=False, IncludeQualifiers=True)
	except Exception:
		return None
		#exc = sys.exc_info()[1]
		#return "Error: Namespace="+wbemNamespace+" class="+str(entity_type)+". Caught:"+str(exc)
	return WbemClassDescrFromClass(wbemKlass)
	#try:
	#	wbemKlass = connWbem.GetClass(entity_type, namespace=wbemNamespace, LocalOnly=False, IncludeQualifiers=True)
	#	klaDescrip = wbemKlass.qualifiers['Description'].value
	#	return klaDescrip
	#except Exception:
	#	exc = sys.exc_info()[1]
	#	return "Namespace="+wbemNamespace+" class="+entity_type+". Caught:"+str(exc)

################################################################################

# TODO: Il y a de la duplication la-dedans. On fera du menage.

def NamespacesEnumeration(conn):
	"""
	Different brokers have different CIM classes, that can be used to
	enumerate namespaces. And those may be nested under miscellaneous
	namespaces. This method tries all known combinations and returns
	first non-empty list of namespace instance names.
	@return (interopns, nsclass, nsinsts)
	where
		interopns is a instance name of namespace holding namespace CIM
			class
		nsclass is a name of class used to enumerate namespaces
		nsinsts is a list of all instance names of nsclass
	"""
	nsclasses = ['CIM_Namespace', '__Namespace']
	namespaces = ['root/cimv2', 'Interop', 'interop', 'root', 'root/interop']
	interopns = None
	nsclass = None
	nsinsts = []
	for icls in range(len(nsclasses)):
		for ins in range(len(namespaces)):
			try:
				nsins = namespaces[ins]
				nsinsts = conn.EnumerateInstanceNames(nsclasses[icls], namespace=nsins)
				interopns = nsins
				nsclass = nsclasses[icls]
			except Exception:
				exc = sys.exc_info()[1]
				arg = exc.args
				if arg[0] in [pywbem.CIM_ERR_INVALID_NAMESPACE,
							  pywbem.CIM_ERR_NOT_SUPPORTED,
							  pywbem.CIM_ERR_INVALID_CLASS]:
					continue
				else:
					# Caught local variable 'url_' referenced before assignment
					#sys.stderr.write("NamespacesEnumeration Caught %s\n"%str(arg[0]))
					raise
			if len(nsinsts) > 0:
				break
	return (interopns, nsclass, nsinsts)

def EnumNamespacesCapabilities(conn):
	interopns, _, nsinsts = NamespacesEnumeration(conn)

	nslist = [inst['Name'].strip('/') for inst in nsinsts]
	if interopns not in nslist:
		# Pegasus didn't get the memo that namespaces aren't hierarchical.
		# This will fall apart if there exists a namespace <interopns>/<interopns>.
		# Maybe we should check the Server: HTTP header instead.
		nslist = [interopns + '/' + subns for subns in nslist]
		nslist.append(interopns)

	nslist.sort()
	if 'root/PG_InterOp' in nslist or 'root/interop' in nslist:
		nsd = dict([(x, 0) for x in nslist])
		# Bizarrement, ca renvoie zero pour 'root/PG_InterOp' alors que
		# la classe 'PG_ProviderCapabilities' a des instances ?
		# Peut-etre que c'est hard-code, qu'il n'y a pas besoin de provider pour cette classe ?
		caps = conn.EnumerateInstances('PG_ProviderCapabilities',
									   namespace='root/PG_InterOp' if 'root/PG_InterOp' in nslist else 'root/interop',
									   PropertyList=['Namespaces'])
		for cap in caps:
			for _ns in cap['Namespaces']:
				try:
					nsd[_ns] += 1
				except KeyError:
					pass
	else:
		nsd = {}
	return nsd

# Classes might belong to several namespaces ? Not sure.
def GetCapabilitiesForInstrumentation(conn,namSpac):
	caps = None
	last_error = AssertionError("No interop namespace found")
	for interopns in ('root/PG_InterOp', 'root/interop'):
		try:
			# sys.stderr.write("GetCapabilitiesForInstrumentation namSpac=%s interopns=%s\n" % (namSpac,interopns))
			caps = conn.EnumerateInstances(
							ClassName='PG_ProviderCapabilities',
							namespace=interopns,
							PropertyList=['Namespaces', 'ClassName'])
			# sys.stderr.write("GetCapabilitiesForInstrumentation len=%d caps=%s\n" % ( len(caps), str(caps) ) )
			break
		except Exception:
			exc = sys.exc_info()[1]
			sys.stderr.write("GetCapabilitiesForInstrumentation exc=%s\n" % str(exc))
			arg = exc.args
			# TODO Python 3
			if arg[0] != pywbem.CIM_ERR_INVALID_NAMESPACE:
				raise
			last_error = arg
	else:
		raise last_error
	resu = []
	for cap in caps:
		if namSpac in cap['Namespaces']:
			resu.append( cap['ClassName'])
	return resu

###################################################

def EnumerateInstrumentedClasses(conn,namSpac):
    """
    Enumerates only those class names, that are instrumented (there
    is a provider under broker implementing its interface.
    """
    fetched_classes = []
    def get_class(conn,cname):
        """Obtain class from broker and store it in cache."""
        fetched_classes.append(cname)
        return conn.GetClass(ClassName=cname,
                   LocalOnly=True, PropertyList=[],
                   IncludeQualifiers=False, IncludeClassOrigin=False)

    start_class = '.'

    caps = GetCapabilitiesForInstrumentation(conn,namSpac)

    deep_dict = {start_class:[]}

    for cap in caps:
        if namSpac not in cap['Namespaces']:
            continue
        if cap['ClassName'] in fetched_classes:
            continue
        klass = get_class(conn,cap['ClassName'])
        if klass.superclass is None:
            deep_dict[start_class].append(klass.classname)
        else:
            try:
                deep_dict[klass.superclass].append(klass.classname)
            except KeyError:
                deep_dict[klass.superclass] = [klass.classname]
            while klass.superclass is not None:
                if klass.superclass in fetched_classes:
                    break
                klass = get_class(conn,klass.superclass)
                if klass.superclass is None and klass.superclass not in deep_dict[start_class]:
                    deep_dict[start_class].append(klass.classname)
                elif klass.superclass in deep_dict:
                    if klass.classname not in deep_dict[klass.superclass]:
                        deep_dict[klass.superclass].append( klass.classname)
                    break
                else:
                    deep_dict[klass.superclass] = [klass.classname]
    return deep_dict

###################################################

def GetClassesTree(conn,theNamSpace):
    kwargs = {'DeepInheritance': True}
    # kwargs['ClassName'] = None
    kwargs['LocalOnly'] = True
    kwargs['IncludeQualifiers'] = False
    kwargs['IncludeClassOrigin'] = False

    sys.stderr.write("GetClassesTree theNamSpace=%s\n" % theNamSpace)
    klasses = conn.EnumerateClasses(namespace=theNamSpace,**kwargs)
    sys.stderr.write("GetClassesTree klasses %d elements\n" % len(klasses))

    tree_classes = dict()
    for klass in klasses:
        # This does not work. WHY ?
        # tree_classes.get( klass.superclass, [] ).append( klass )
        try:
            tree_classes[klass.superclass].append(klass)
        except KeyError:
            tree_classes[klass.superclass] = [klass]

    sys.stderr.write("GetClassesTree tree_classes %d elements\n" % len(tree_classes))
    return tree_classes

###################################################

# Fills with instrumented classes, i.e. classes with a provider.
def MakeInstrumentedRecu(inTreeClass, outTreeClass, topclassNam, theNamSpac, instrCla):
    try:
        if topclassNam in instrCla:
            # print("top "+topclassNam+" instrumented<br>")
            outTreeClass[topclassNam] = []
        for cl in inTreeClass[topclassNam]:
            clnam = cl.classname
            MakeInstrumentedRecu(inTreeClass, outTreeClass, clnam, theNamSpac, instrCla)

            if clnam in instrCla or clnam in outTreeClass:
                # This does not work. WHY ?
                # outTreeClass.get( klass.superclass, [] ).append( clnam )
                try:
                    outTreeClass[topclassNam].append(cl)
                except KeyError:
                    outTreeClass[topclassNam] = [cl]


    except KeyError:
        # No subclass.
        pass

# This builds a dictionary indexes by class names, and the values are lists of classes objects,
# which are the subclasses of the key class. The root class name is None.
def GetClassesTreeInstrumented(conn,theNamSpace):
	sys.stderr.write("GetClassesTreeInstrumented theNamSpace=%s\n" % theNamSpace)

	try:
		inTreeClass = GetClassesTree(conn,theNamSpace)
		# sys.stderr.write("After GetClassesTree inTreeClass = %d elements\n" % len(inTreeClass))
		outTreeClass = dict()
		instrCla = GetCapabilitiesForInstrumentation(conn,theNamSpace)
		# sys.stderr.write("After GetCapabilitiesForInstrumentation instrCla = %d elements\n" % len(instrCla))
		MakeInstrumentedRecu(inTreeClass, outTreeClass, None, theNamSpace, instrCla)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Instrumented classes: ns="+theNamSpace+" Caught:"+str(exc))
	sys.stderr.write("After MakeInstrumentedRecu outTreeClass = %d elements\n" % len(outTreeClass))

	# print("outTreeClass="+str(outTreeClass)+"<br>")
	return outTreeClass

# Tells if this class for our ontology is in a given WBEM server, whatever the namespace is.
def ValidClassWbem(entity_host, className):
	tpSplit = className.split("_")
	tpPrefix = tpSplit[0]
	# "PG" is Open Pegasus: http://www.opengroup.org/subjectareas/management/openpegasus
	# "LMI" is OpenLmi: http://www.openlmi.org/
	return tpPrefix in ["CIM","PG","LMI"]

