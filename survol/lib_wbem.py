import re
import os
import sys
import pywbem # Might be pywbem or python3-pywbem.
import socket
import lib_util
import lib_common
import lib_credentials

################################################################################

# TODO: Build a moniker with cimom added at the beginning.
def WbemAllNamespacesUrl(srvr):
	return lib_util.ScriptizeCimom( '/namespaces_wbem.py', "", srvr )

def BuildWbemNamespaceClass( wbemNamespace, entity_type ):
	# Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
	# But the namespace is not taken into account if it is empty.
	if wbemNamespace:
		return ( wbemNamespace, entity_type, wbemNamespace + ":" + entity_type )
	else:
		return ( wbemNamespace, entity_type, entity_type )

def BuildWbemMoniker( hostname, namespac = "", classNam = "" ):
	# Apparently the namespace is not correctly parsed. It should not matter as it is optional.
	# This also helps when this is a common class between WBEM, WMI and Survol.
	if namespac:
		return "%s/%s:%s." % ( hostname, namespac, classNam )
	else:
		return "%s/%s." % ( hostname, classNam )

# TODO: Build a moniker with cimom added at the beginning. Must check if really useful.
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
# TODO: It could use SLP.
# TODO: No need to return all WBEM servers.
# TODO: Emulate the protocol with Jquery and Javascript, if it is HTTP.
# But for that, we would need a WBEM server sending Access-Control-Allow-Origin header.
def WbemServersList():
	lstWbemServers = []
	credNames = lib_credentials.GetCredentialsNames( "WBEM" )
	DEBUG("WbemServersList")
	for urlWbem in credNames:
		#sys.stderr.write("WbemServersList urlWbem=%s\n"%(urlWbem))
		# crdNam = "http://192.168.1.83:5988"
		parsed_url = lib_util.survol_urlparse( urlWbem )
		the_host = parsed_url.hostname
		if the_host:
			lstWbemServers.append((the_host,urlWbem))

	return lstWbemServers

# This returns the WBEM server of a machine.
# It checks the credentials to find the best possible Cimom.
# TODO: This should prefer port 5988 over 5989 which does not work with pywbem anyway.
def HostnameToWbemServer(hostname):
	entity_ip_addr = lib_util.EntHostToIpReally(hostname)

	credNames = lib_credentials.GetCredentialsNames( "WBEM" )
	for urlWbem in credNames:
		#sys.stderr.write("HostnameToWbemServer urlWbem=%s\n"%(urlWbem))
		# urlWbem = "http://192.168.1.83:5988"
		parsed_url = lib_util.survol_urlparse( urlWbem )
		the_host = parsed_url.hostname
		if the_host == hostname:
			return urlWbem
		if the_host == entity_ip_addr:
			return urlWbem

	# If no credential can be found, just return a default one.
	return "http://" + entity_ip_addr + ":5988"

################################################################################


# On renvoie une liste de liens. Eventuellement type est nul.
# On pourrait aussi bien avoir deux fonctions differentes.
# Maybe entity_namespace does not have the right separator, slash or backslash.
def GetWbemUrls( entity_host, entity_namespace, entity_type, entity_id ):
	DEBUG("GetWbemUrls h=%s ns=%s t=%s i=%s",entity_host, entity_namespace, entity_type, entity_id)
	wbem_urls_list = []

	# sys.stderr.write("GetWbemUrls entity_host=%s\n" % (entity_host))

	# TODO: Should check that the WBEM class exists in the server ?
	for wbemServer in WbemServersList():
		# wbemServer=(u'vps516494.ovh.net', u'http://vps516494.ovh.net:5988')
		#sys.stderr.write("GetWbemUrls wbemServer=%s\n"%str(wbemServer))
		# If no host specified, returns everything.
		if entity_host:
			# wbemServer[1].lower()=vps516494.ovh.net entity_host.lower()=http://vps516494.ovh.net:5988
			if entity_host.lower() != wbemServer[0].lower():
				#sys.stderr.write("GetWbemUrls different wbemServer=%s entity_host=%s\n"%(str(wbemServer[1].lower()),entity_host.lower()))
				continue

		DEBUG("GetWbemUrls found wbemServer=%s",str(wbemServer))
		theCimom = wbemServer[1]

		# TODO: When running from cgiserver.py, and if QUERY_STRING is finished by a dot ".", this dot
		# TODO: is removed. Workaround: Any CGI variable added after.
		# TODO: Also: Several slashes "/" are merged into one.
		# TODO: Example: "xid=http://192.168.1.83:5988/." becomes "xid=http:/192.168.1.83:5988/"
		# TODO: Replace by "xid=http:%2F%2F192.168.1.83:5988/."
		# Maybe a bad collapsing of URL ?
		theCimom = lib_credentials.KeyUrlCgiEncode(theCimom)

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

# This also takes into account the entity type.
# If this is a CIM_ComputerSystem, it tries to connect to its WBEM server.
# This code is not really mature, but it does not harm.
def GetWbemUrlsTyped( entity_host, nameSpace, entity_type, entity_id ):
	#sys.stderr.write("GetWbemUrlsTyped entity_host=%s nameSpace=%s entity_type=%s entity_id=%s\n"%( entity_host, nameSpace, entity_type, entity_id ))
	# When displaying the WBEM of a computer, this attempts to point to the server of this distant machine.
	# The coding of another machine looks dodgy but is simply a CIM path.
	if (entity_type == 'CIM_ComputerSystem'):
		# TODO:  hostId="Unknown-30-b5-c2-02-0c-b5-2" does not work.
		# This return the WBEM servers associated to this machine.
		if entity_id:
			# Tries to extract the host from the string "Key=Val,Name=xxxxxx,Key=Val"
			# BEWARE: Some arguments should be decoded.
			xidHost = { sp[0]:sp[1] for sp in [ ss.split("=") for ss in entity_id.split(",") ] }["Name"]

			wbem_urls_list = GetWbemUrls( xidHost, nameSpace, entity_type, entity_id)
		else:
			host_alt = lib_util.currentHostname
			wbem_urls_list = GetWbemUrls( host_alt, nameSpace, entity_type, "Name=" + host_alt + ".home")
	else:
		# This returns the current url server of the current machine.
		wbem_urls_list = GetWbemUrls( entity_host, nameSpace, entity_type, entity_id )
	return wbem_urls_list

# conn = pywbem.WBEMConnection("http://192.168.1.83:5988" , ('','') )
# wbemKlass = conn.GetClass("oracle_package_body", namespace="", LocalOnly=False, IncludeQualifiers=True)
def WbemConnection(cgiUrl):
	try:
		# For the moment, it cannot connect to https:
		# https://github.com/Napsty/check_esxi_hardware/issues/7
		creden = lib_credentials.GetCredentials( "WBEM", cgiUrl )

		DEBUG("WbemConnection creden=%s",str(creden))
		# Beware: If username/password is wrong, it will only be detected at the first data access.
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

################################################################################

# TODO: Should remove duplicate code.

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
			ERROR("GetCapabilitiesForInstrumentation exc=%s", str(exc))
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

    DEBUG("GetClassesTree theNamSpace=%s", theNamSpace)
    klasses = conn.EnumerateClasses(namespace=theNamSpace,**kwargs)
    DEBUG("GetClassesTree klasses %d elements", len(klasses))

    tree_classes = dict()
    for klass in klasses:
        # This does not work. WHY ?
        # tree_classes.get( klass.superclass, [] ).append( klass )
        try:
            tree_classes[klass.superclass].append(klass)
        except KeyError:
            tree_classes[klass.superclass] = [klass]

    DEBUG("GetClassesTree tree_classes %d elements", len(tree_classes))
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
	DEBUG("GetClassesTreeInstrumented theNamSpace=%s", theNamSpace)

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
	DEBUG("After MakeInstrumentedRecu outTreeClass = %d elements", len(outTreeClass))

	# print("outTreeClass="+str(outTreeClass)+"<br>")
	return outTreeClass

# Tells if this class for our ontology is in a given WBEM server, whatever the namespace is.
def ValidClassWbem(className):
	tpSplit = className.split("_")
	tpPrefix = tpSplit[0]
	DEBUG("lib_wbem.ValidClassWbem className=%s tpPrefix=%s",className,tpPrefix)
	# "PG" is Open Pegasus: http://www.opengroup.org/subjectareas/management/openpegasus
	# "LMI" is OpenLmi: http://www.openlmi.org/
	return tpPrefix in ["CIM","PG","LMI"]

# This must return the label of an url "entity_wmi.py".
# For example, the name of a process when the PID (Handle) is given.
# Due to performance problems, consider using a cache.
# Or a default value for some "expensive" classes.
def EntityToLabelWbem(namSpac, entity_type_NoNS, entity_id, entity_host):
	# sys.stderr.write("EntityToLabelWbem\n")
	return None
