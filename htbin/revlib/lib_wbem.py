import re
import sys
import pywbem # Might be pywbem or python3-pywbem.
import socket
import lib_util
import lib_common
import lib_credentials

################################################################################

# TODO: Build a moniker with cimom added at the beginning.
def WbemAllNamespacesUrl(srvr):
	return lib_util.ScriptizeCimom( '/namespaces_wbem.py', "", "", srvr )

def BuildWbemNamespaceClass( entity_namespace, entity_type ):
	wbemNamespace = entity_namespace
	# Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
	return ( wbemNamespace, entity_type, wbemNamespace + ":" + entity_type )

def BuildWbemMoniker( hostname, namespac = "", classNam = "" ):
	return hostname + "/" + namespac + ":" + classNam + "."

# TODO: Build a moniker with cimom added at the beginning.
# J ai des doutes sur cette fonction qui est pourtant utilisee deux fois.
def NamespaceUrl(nskey,cimomUrl):
	wbemMoniker = BuildWbemMoniker( cimomUrl, nskey )
	wbemInstanceUrl = lib_util.EntityUrlFromMoniker( wbemMoniker, True, True )

	return wbemInstanceUrl

def WbemBuildMonikerPath( entity_namespace, entity_type, entity_id, cimomSrv ):
	wbemNameSpace, wbemClass, fullClassPth = BuildWbemNamespaceClass( entity_namespace, entity_type )

	sys.stderr.write("WbemBuildMonikerPath wbemNameSpace=%s entity_namespace=%s entity_id=%s\n" % (wbemNameSpace, entity_namespace, str(entity_id)))

	#if entity_id == "":
	#	wbemPath = ""
	#else:
	#	wbemPath = lib_util.BuildPathFromDictOrMoniker(entity_id)
	#	if wbemPath is None:
	#		# If we do not have the property name, let's guess it, if there is one property:
	#		# TODO: If there are several properties, guess one ?
	#		wbemClassKeys = WbemGetClassKeys( wbemNameSpace, wbemClass, cimomSrv )
	#
	#		# The class must exist in this cimom, with one key only.
	#		if ( wbemClassKeys is not None ) and ( len(wbemClassKeys) == 1 ):
	#			# If there is an unique key, this is the one.
	#			# wbemPath = wbemClassKeys[0] + '="' + entity_id + '"'
	#			# TODO: If the entity contains a "="; should be escaped.
	#			wbemPath = wbemClassKeys[0] + '=' + entity_id
	#		else:
	#			sys.stderr.write("No keys or too many of them\n" )
	#			# Otherwise we cannot do much because the objects are not comparable.
	#			return None

	# return fullClassPth + "." + wbemPath
	return fullClassPth + "." + entity_id

def WbemInstanceUrl( entity_namespace, entity_type, entity_id, cimomSrv ):
	sys.stderr.write("WbemInstanceUrl %s %s %s %s\n" % (entity_namespace, entity_type, entity_id, cimomSrv))

	wbemFullPath = WbemBuildMonikerPath( entity_namespace, entity_type, entity_id, cimomSrv )

	if wbemFullPath is None:
		return None

	# 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
	wbemMoniker = cimomSrv + "/" + wbemFullPath

	wbemInstanceUrl = lib_util.EntityUrlFromMoniker( wbemMoniker, entity_id == "" )
	return wbemInstanceUrl

# Returns the list of a keys of a given WBEM class. This is is used if the key is not given
# for an entity. This could be stored in a cache for better performance.
def WbemGetClassKeys( wbemNameSpace, wbemClass, cimomSrv ):
	sys.stderr.write("WbemGetClassKeys wbemNameSpace=%s wbemClass=%s cimomSrv=%s\n" % (wbemNameSpace, wbemClass, cimomSrv ))
	wbemCnnct = WbemConnection(cimomSrv)
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
	sys.stderr.write("WbemGetClassKeys keys=%s\n" % ( str(keys) ) )
	return keys

################################################################################

# TODO: Will be stored in the cache filled with SLP discovery, with credentials.
# http://192.168.1.83:5988 	index 	Namespaces
# https://192.168.1.83:5989 	index 	Namespaces
hardcoded_list_of_wbem_servers = [
	( "192.168.1.83", "http://192.168.1.83:5988" ),
	( "192.168.1.88", "http://192.168.1.88:5988" )
]

# On renvoie une liste de liens. Eventuellement type est nul.
# On pourrait aussi bien avoir deux fonctions differentes.
# Maybe entity_namespace does not have the right separator, slash or backslash.
def GetWbemUrls( entity_host, entity_namespace, entity_type, entity_id ):
	sys.stderr.write("GetWbemUrls %s %s %s %s\n" % (entity_host, entity_namespace, entity_type, entity_id))
	wbem_urls_list = []

	entity_ip_addr = lib_util.EntHostToIp(entity_host)
	sys.stderr.write("GetWbemUrls entity_ip_addr=%s\n" % (entity_ip_addr))

	# TODO: Ce ne sont pas les bons parametres,
	# mais une possibilite est de passer les autres, dans un RemoteEntityId.

	#entity_wbem.py en plus des parametes CIM a besoin de l url du CIMON
	#Fabriquer un RemoteEntityId ?
	#Mettre dans RemoteEntityId non seulement l id mais les autres proprietes ?
	#On ne peut pas mettre de & dans les liens graphviz apparemment a cause d un bug.

	# TODO: Verifier que l entite existe en tant que class WBEM. Sinon on renvoie une liste vide.
	# TODO: C EST TOUT LE PROBLEME DU MAPPING DES CLASSES ET PROPERTIES.

	for wbemServer in hardcoded_list_of_wbem_servers:
		if not lib_common.SameHostOrLocal( wbemServer[0], entity_ip_addr ):
			continue

		theCimom = wbemServer[1]

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

# TODO: Temporary storage for username/password.
# There might be several credentials per server.
def WbemConnection(cgiUrl):
	try:
		creden = lib_credentials.GetCredentials( "WBEM", cgiUrl )

		# ATTENTION: Si probleme de connection, on ne le voit pas ici mais
		# au moment du veritable acces.
		conn = pywbem.WBEMConnection(cgiUrl , creden )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Connecting to :"+cgiUrl+" Caught:"+str(exc)+"<br>")

	# TestCookie(url)
	return conn

# Il y a de la duplication la-dedans.
# On fera du menage.

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
			caps = conn.EnumerateInstances(
							ClassName='PG_ProviderCapabilities',
							namespace=interopns,
							PropertyList=['Namespaces', 'ClassName'])
			break
		except pywbem.CIMError as err:
			# TODO Python 3
			if err.args[0] != pywbem.CIM_ERR_INVALID_NAMESPACE:
				raise
			last_error = err
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
                    if (  klass.classname
                       not in deep_dict[klass.superclass]):
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

    klasses = conn.EnumerateClasses(namespace=theNamSpace,**kwargs)

    tree_classes = dict()
    for klass in klasses:
        # This does not work. WHY ?
        # tree_classes.get( klass.superclass, [] ).append( klass )
        try:
            tree_classes[klass.superclass].append(klass)
        except KeyError:
            tree_classes[klass.superclass] = [klass]

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

	inTreeClass = GetClassesTree(conn,theNamSpace)
	sys.stderr.write("After GetClassesTree inTreeClass = %d elements\n" % len(inTreeClass))
	outTreeClass = dict()
	instrCla = GetCapabilitiesForInstrumentation(conn,theNamSpace)
	sys.stderr.write("After GetCapabilitiesForInstrumentation instrCla = %d elements\n" % len(instrCla))
	MakeInstrumentedRecu(inTreeClass, outTreeClass, None, theNamSpace, instrCla)
	sys.stderr.write("After MakeInstrumentedRecu outTreeClass = %d elements\n" % len(outTreeClass))

	# print("outTreeClass="+str(outTreeClass)+"<br>")
	return outTreeClass

