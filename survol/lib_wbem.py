import re
import os
import sys
import socket
import logging
import pywbem # Might be pywbem or python3-pywbem.
import lib_util
import lib_kbase
import lib_properties
import lib_common
import lib_credentials

################################################################################


# TODO: Build a moniker with cimom added at the beginning.
def WbemAllNamespacesUrl(srvr):
    return lib_util.ScriptizeCimom('/namespaces_wbem.py', "", srvr)


def BuildWbemNamespaceClass(wbem_namespace, entity_type):
    # Normally we should check if this class is defined in this cimom.
    # For the moment, we assume, yes.
    # But the namespace is not taken into account if it is empty.
    if wbem_namespace:
        return wbem_namespace, entity_type, wbem_namespace + ":" + entity_type
    else:
        return wbem_namespace, entity_type, entity_type


def BuildWbemMoniker(hostname, namespac="", class_nam=""):
    # Apparently the namespace is not correctly parsed. It should not matter as it is optional.
    # This also helps when this is a common class between WBEM, WMI and Survol.
    if namespac:
        return "%s/%s:%s." % (hostname, namespac, class_nam)
    else:
        return "%s/%s." % (hostname, class_nam)


# TODO: Build a moniker with cimom added at the beginning. Must check if really useful.
def NamespaceUrl(nskey, cimom_url, class_nam=""):
    wbem_moniker = BuildWbemMoniker(cimom_url, nskey, class_nam)
    wbem_instance_url = lib_util.EntityUrlFromMoniker(wbem_moniker, True, True)
    return wbem_instance_url


def ClassUrl(nskey, cimom_url, class_nam):
    wbem_moniker = BuildWbemMoniker(cimom_url, nskey, class_nam)
    wbem_instance_url = lib_util.EntityUrlFromMoniker(wbem_moniker, True)
    return wbem_instance_url


def WbemBuildMonikerPath( entity_namespace, entity_type, entity_id):
    wbem_name_space, wbem_class, full_class_pth = BuildWbemNamespaceClass(entity_namespace, entity_type)
    return full_class_pth + "." + entity_id


def WbemInstanceUrl(entity_namespace, entity_type, entity_id, cimom_srv):
    # sys.stderr.write("WbemInstanceUrl %s %s %s %s\n" % (entity_namespace, entity_type, entity_id, cimomSrv))

    wbem_full_path = WbemBuildMonikerPath(entity_namespace, entity_type, entity_id)

    if wbem_full_path is None:
        return None

    # 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
    wbem_moniker = cimom_srv + "/" + wbem_full_path

    wbem_instance_url = lib_util.EntityUrlFromMoniker(wbem_moniker, entity_id == "")
    return wbem_instance_url


def WbemGetClassKeys(wbem_name_space, wbem_class, cimom_srv):
    """Returns the list of a keys of a given WBEM class. This is is used if the key is not given for an entity.
    This could be stored in a cache for better performance."""
    try:
        wbem_cnnct = WbemConnection(cimom_srv)
        return WbemGetClassKeysFromConnection(wbem_name_space, wbem_class, wbem_cnnct)
    except Exception as exc:
        logging.warning("WbemGetClassKeys %s %s %s: Caught:%s", cimom_srv, wbem_name_space, wbem_class, str(exc))
        return None


def WbemGetClassKeysFromConnection(wbem_name_space, wbem_class, wbem_cnnct):
    # >>> conn = pywbem.WBEMConnection( "http://192.168.1.88:5988" , ('pegasus','toto') )
    # >>> conn.GetClass("CIM_MediaPresent",namespace="root/cimv2")
    # CIMClass(classname=u'CIM_MediaPresent', ...)

    # https://pywbem.github.io/pywbem/doc/0.8.4/doc/pywbem.cim_operations.WBEMConnection-class.html#GetClass
    wbem_class = wbem_cnnct.GetClass(wbem_class,
                                     namespace=wbem_name_space,
                                     # Indicates that inherited properties, methods, and qualifiers are to be excluded from the returned class.
                                     LocalOnly=False,
                                     IncludeQualifiers=False)

    keys = wbem_class.properties.keys()
    # sys.stderr.write("WbemGetClassKeys keys=%s\n" % ( str(keys) ) )
    return keys

################################################################################


# TODO: Make SLP work properly.
def slp_wbem_services():
    """This returns accessible WBEM services as detected by SLP."""
    filter = "wbem"
    #  "/drives/c/Program Files (x86)/OpenSLP/slptool.exe"
    cmd = 'slptool findsrvs service:' + filter

    # TODO: logging.debugGING PURPOSE. FIX THIS.
    cmd = '"C:/Program Files (x86)/OpenSLP/slptool.exe" findsrvs service:' + filter

    stream = os.popen(cmd)
    # service:ftp.smallbox://192.168.100.1:21,65535
    for line in stream:
        match_obj = re.match(r'service:([^:]*):/?/?([^,]*)(.*)', line, re.M|re.I)
        if match_obj:
            yield {
                    "name": match_obj.group(1), # "wbem"
                    "url" : match_obj.group(2), # Starts with "http:" or "https:"
                    "rest": match_obj.group(3)}
        else:
            raise Exception("Invalid line " + line)
    resu = stream.close()

    if resu is not None:
        raise Exception("Error running " + cmd)


# TODO: Alternate methods to discover WBEM servers:
# TODO:   - Ping machines with WBEM port numbers 5988 and 5989.
# TODO: Will be stored in the cache filled with SLP discovery, with credentials.
# http://192.168.1.83:5988     index     Namespaces
# https://192.168.1.83:5989     index     Namespaces
# TODO: It could use SLP.
# TODO: No need to return all WBEM servers.
# TODO: Emulate the protocol with Jquery and Javascript, if it is HTTP.
# But for that, we would need a WBEM server sending Access-Control-Allow-Origin header.
def WbemServersList():
    lst_wbem_servers = []
    cred_names = lib_credentials.get_credentials_names("WBEM")
    logging.debug("WbemServersList")
    for url_wbem in cred_names:
        # crdNam = "http://192.168.1.83:5988"
        parsed_url = lib_util.survol_urlparse(url_wbem)
        the_host = parsed_url.hostname
        if the_host:
            lst_wbem_servers.append((the_host, url_wbem))

    return lst_wbem_servers


def HostnameToWbemServer(hostname):
    """This returns the WBEM server of a machine.
    It checks the credentials to find the best possible Cimom."""

    # TODO: This should prefer port 5988 over 5989 which does not work with pywbem anyway.
    entity_ip_addr = lib_util.EntHostToIpReally(hostname)

    cred_names = lib_credentials.get_credentials_names("WBEM")
    for url_wbem in cred_names:
        # url_wbem = "http://192.168.1.83:5988"
        parsed_url = lib_util.survol_urlparse(url_wbem)
        the_host = parsed_url.hostname
        if the_host == hostname:
            return url_wbem
        if the_host == entity_ip_addr:
            return url_wbem

    # If no credential can be found, just return a default one.
    return "http://" + entity_ip_addr + ":5988"

################################################################################


def GetWbemUrls(entity_host, entity_namespace, entity_type, entity_id):
    """This returns a list of URLs. entity_type can be None."""
    logging.debug("GetWbemUrls h=%s ns=%s t=%s i=%s",entity_host, entity_namespace, entity_type, entity_id)
    wbem_urls_list = []

    # FIXME: entity_namespace might have a wrong separator, slash or backslash.

    # sys.stderr.write("GetWbemUrls entity_host=%s\n" % (entity_host))

    # TODO: Should check that the WBEM class exists in the server ?
    for wbem_server in WbemServersList():
        # wbem_server=(u'vps516494.ovh.net', u'http://vps516494.ovh.net:5988')
        #sys.stderr.write("GetWbemUrls wbem_server=%s\n"%str(wbem_server))
        # If no host specified, returns everything.
        if entity_host:
            # wbem_server[1].lower()=vps516494.ovh.net entity_host.lower()=http://vps516494.ovh.net:5988
            if entity_host.lower() != wbem_server[0].lower():
                #sys.stderr.write("GetWbemUrls different wbem_server=%s entity_host=%s\n"%(str(wbem_server[1].lower()),entity_host.lower()))
                continue

        logging.debug("GetWbemUrls found wbem_server=%s", str(wbem_server))
        the_cimom = wbem_server[1]

        # TODO: When running from cgiserver.py, and if QUERY_STRING is finished by a dot ".", this dot
        # TODO: is removed. Workaround: Any CGI variable added after.
        # TODO: Also: Several slashes "/" are merged into one.
        # TODO: Example: "xid=http://192.168.1.83:5988/." becomes "xid=http:/192.168.1.83:5988/"
        # TODO: Replace by "xid=http:%2F%2F192.168.1.83:5988/."
        # Maybe a bad collapsing of URL ?
        the_cimom = lib_credentials.key_url_cgi_encode(the_cimom)

        # On suppose que les classes sont les memes.
        if entity_type == "":
            # TODO: This should rather display all classes for this namespace.
            wbem_url = WbemAllNamespacesUrl(the_cimom)
        else:
            # Unique script for all types of entities.
            # TODO: Pass the cimom as a host !!!
            wbem_url = WbemInstanceUrl(entity_namespace, entity_type, entity_id, the_cimom)

        if wbem_url is None:
            continue
        wbem_urls_list.append((wbem_url, wbem_server[0]))

    return wbem_urls_list


def GetWbemUrlsTyped(entity_host, name_space, entity_type, entity_id):
    """This also takes into account the entity type.
    If this is a CIM_ComputerSystem, it tries to connect to its WBEM server.
    This code is not really mature, but it does not harm."""

    #sys.stderr.write("GetWbemUrlsTyped entity_host=%s nameSpace=%s entity_type=%s entity_id=%s\n"%( entity_host, nameSpace, entity_type, entity_id ))
    # When displaying the WBEM of a computer, this attempts to point to the server of this distant machine.
    # The coding of another machine looks dodgy but is simply a CIM path.
    if entity_type == 'CIM_ComputerSystem':
        # TODO:  hostId="Unknown-30-b5-c2-02-0c-b5-2" does not work.
        # This return the WBEM servers associated to this machine.
        if entity_id:
            # Tries to extract the host from the string "Key=Val,Name=xxxxxx,Key=Val"
            # BEWARE: Some arguments should be decoded.
            xid_host = {sp[0]:sp[1] for sp in [ss.split("=") for ss in entity_id.split(",")]}["Name"]

            wbem_urls_list = GetWbemUrls(xid_host, name_space, entity_type, entity_id)
        else:
            host_alt = lib_util.currentHostname
            wbem_urls_list = GetWbemUrls(host_alt, name_space, entity_type, "Name=" + host_alt + ".home")
    else:
        # This returns the current url server of the current machine.
        wbem_urls_list = GetWbemUrls(entity_host, name_space, entity_type, entity_id)
    return wbem_urls_list


def WbemConnection(cgi_url):
    """For the moment, it cannot connect to https:
    #https://github.com/Napsty/check_esxi_hardware/issues/7 """
    creden = lib_credentials.GetCredentials("WBEM", cgi_url)

    #if creden == ('', ''):
    #    raise Exception("WbemConnection: No credentials for %s" % cgi_url)

    logging.debug("WbemConnection creden=%s", str(creden))
    # Beware: If username/password is wrong, it will only be detected at the first data access.
    conn = pywbem.WBEMConnection(cgi_url, creden)
    return conn


def WbemGetClassObj(conn_wbem, entity_type, wbem_namespace):
    try:
        wbem_klass = conn_wbem.GetClass(entity_type, namespace=wbem_namespace, LocalOnly=False, IncludeQualifiers=True)
        return wbem_klass
    except Exception:
        return None


################################################################################


def WbemClassDescrFromClass(wbem_klass):
    try:
        return wbem_klass.qualifiers['Description'].value
    except Exception as exc:
        return "Caught:" + str(exc)


def WbemClassDescription(conn_wbem, entity_type, wbem_namespace):
    try:
        wbem_klass = conn_wbem.GetClass(entity_type, namespace=wbem_namespace, LocalOnly=False, IncludeQualifiers=True)
    except Exception:
        return None
    return WbemClassDescrFromClass(wbem_klass)

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
            except Exception as exc:
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
    return interopns, nsclass, nsinsts


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


def GetCapabilitiesForInstrumentation(conn, nam_spac):
    """Classes might belong to several namespaces ?"""
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
        except Exception as exc:
            logging.error("GetCapabilitiesForInstrumentation exc=%s", str(exc))
            arg = exc.args
            # TODO Python 3
            if arg[0] != pywbem.CIM_ERR_INVALID_NAMESPACE:
                raise
            last_error = arg
    else:
        raise last_error
    resu = []
    for cap in caps:
        if nam_spac in cap['Namespaces']:
            resu.append(cap['ClassName'])
    return resu

###################################################


def EnumerateInstrumentedClasses(conn, nam_spac):
    """
    Enumerates only those class names, that are instrumented (there
    is a provider under broker implementing its interface.
    """
    fetched_classes = []
    def get_class(conn, cname):
        """Obtain class from broker and store it in cache."""
        fetched_classes.append(cname)
        return conn.GetClass(ClassName=cname,
                   LocalOnly=True, PropertyList=[],
                   IncludeQualifiers=False, IncludeClassOrigin=False)

    start_class = '.'

    caps = GetCapabilitiesForInstrumentation(conn, nam_spac)

    deep_dict = {start_class:[]}

    for cap in caps:
        if nam_spac not in cap['Namespaces']:
            continue
        if cap['ClassName'] in fetched_classes:
            continue
        klass = get_class(conn, cap['ClassName'])
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


def GetClassesTree(conn, the_nam_space):
    kwargs = {'DeepInheritance': True}
    # kwargs['ClassName'] = None
    kwargs['LocalOnly'] = True
    kwargs['IncludeQualifiers'] = False
    kwargs['IncludeClassOrigin'] = False

    logging.debug("GetClassesTree theNamSpace=%s", the_nam_space)
    klasses = conn.EnumerateClasses(namespace=the_nam_space, **kwargs)
    logging.debug("GetClassesTree klasses %d elements", len(klasses))

    tree_classes = dict()
    for klass in klasses:
        # This does not work. WHY ?
        # tree_classes.get( klass.superclass, [] ).append( klass )
        logging.debug("klass=%s super=%s", klass.classname, klass.superclass)
        try:
            tree_classes[klass.superclass].append(klass)
        except KeyError:
            tree_classes[klass.superclass] = [klass]

    logging.debug("GetClassesTree tree_classes %d elements", len(tree_classes))
    return tree_classes

###################################################


def MakeInstrumentedRecu(in_tree_class, out_tree_class, topclass_nam, the_nam_spac, instr_cla):
    """Fills with instrumented classes, i.e. classes with a provider."""
    try:
        if topclass_nam in instr_cla:
            # print("top "+topclassNam+" instrumented<br>")
            out_tree_class[topclass_nam] = []
        for cl in in_tree_class[topclass_nam]:
            clnam = cl.classname
            MakeInstrumentedRecu(in_tree_class, out_tree_class, clnam, the_nam_spac, instr_cla)

            if clnam in instr_cla or clnam in out_tree_class:
                # This does not work. WHY ?
                # outTreeClass.get( klass.superclass, [] ).append( clnam )
                try:
                    out_tree_class[topclass_nam].append(cl)
                except KeyError:
                    out_tree_class[topclass_nam] = [cl]
    except KeyError:
        # No subclass.
        pass


def GetClassesTreeInstrumented(conn, the_nam_space):
    """This builds a dictionary indexes by class names, and the values are lists of classes objects,
    which are the subclasses of the key class. The root class name is None."""
    logging.debug("GetClassesTreeInstrumented theNamSpace=%s", the_nam_space)

    try:
        in_tree_class = GetClassesTree(conn, the_nam_space)
        # sys.stderr.write("After GetClassesTree inTreeClass = %d elements\n" % len(inTreeClass))
        out_tree_class = dict()
        instr_cla = GetCapabilitiesForInstrumentation(conn, the_nam_space)
        # sys.stderr.write("After GetCapabilitiesForInstrumentation instr_cla = %d elements\n" % len(instr_cla))
        MakeInstrumentedRecu(in_tree_class, out_tree_class, None, the_nam_space, instr_cla)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Instrumented classes: ns=" + the_nam_space + " Caught:" + str(exc))
    logging.debug("After MakeInstrumentedRecu out_tree_class = %d elements", len(out_tree_class))

    # print("out_tree_class="+str(out_tree_class)+"<br>")
    return out_tree_class


def ValidClassWbem(class_name):
    """Tells if this class for our ontology is in a given WBEM server, whatever the namespace is."""
    tp_split = class_name.split("_")
    tp_prefix = tp_split[0]
    logging.debug("lib_wbem.ValidClassWbem className=%s tp_prefix=%s", class_name, tp_prefix)
    # "PG" is Open Pegasus: http://www.opengroup.org/subjectareas/management/openpegasus
    # "LMI" is OpenLmi: http://www.openlmi.org/
    return tp_prefix in ["CIM", "PG", "LMI"]


# This must return the label of an url "entity_wmi.py".
# For example, the name of a process when the PID (Handle) is given.
# Due to performance problems, consider using a cache.
# Or a default value for some "expensive" classes.
def EntityToLabelWbem(namSpac, entity_type_NoNS, entity_id, entity_host):
    # sys.stderr.write("EntityToLabelWbem\n")
    return None


def WbemLocalConnection():
    """By default, current machine. However, WBEM does not give the possibility
    to connect to the local server with the host set to None."""
    machine_name = socket.gethostname()
    logging.info("WbemLocalConnection machine_name=%s" % machine_name)

    cimom_url = HostnameToWbemServer(machine_name)

    wbem_connection = WbemConnection(cimom_url)
    return wbem_connection


def extract_specific_ontology_wbem():
    """This returns an abstract ontology, which is later transformed into RDFS.
    cimomUrl="http://192.168.1.83:5988" or "http://rchateau-HP:5988" """
    wbem_connection = WbemLocalConnection()
    return _extract_wbem_ontology_from_connection(wbem_connection)


def _extract_wbem_ontology_from_connection(wbem_connection):

    map_classes = {}
    map_attributes = {}

    logging.info("_extract_wbem_ontology_from_connection: Getting class tree.")

    # Note: Survol assumes this namespace everywhere.
    wbem_name_space = 'root/cimv2'

    class_tree = GetClassesTree(wbem_connection, the_nam_space=wbem_name_space)

    for super_class_name in class_tree:
        class_array = class_tree[super_class_name]
        for class_object in class_array:
            class_name = class_object.classname

            logging.debug("class_name=%s", class_name)
            if super_class_name:
                top_class_name = super_class_name
                concat_class_name = super_class_name + "." + class_name
            else:
                top_class_name = ""
                concat_class_name = class_name

            # map_classes[concat_class_name] = {
            map_classes[class_name] = {
                "base_class": top_class_name,
                "class_description": "Class WBEM %s" % concat_class_name}

            # TODO: Do not return all keys !!!
            class_keys = WbemGetClassKeysFromConnection(wbem_name_space, class_name, wbem_connection)
            for key_name in class_keys:
                # The same key might exist for several classes.
                try:
                    key_attributes = map_attributes[key_name]
                except KeyError:
                    key_attributes = {
                        "predicate_type": "survol_string",
                        "predicate_description": "Attribute WBEM %s" % key_name,
                        "predicate_domain": []}
                    map_attributes[key_name] = key_attributes
                assert isinstance(concat_class_name, str)
                key_attributes["predicate_domain"].append(concat_class_name)

    return map_classes, map_attributes


def WbemKeyValues(key_value_items, display_none_values=False):
    """This is conceptually similar to WmiKeyValues"""
    dict_key_values = {}
    for wbem_key_name, wbem_value_literal in key_value_items:
        wbem_property = lib_properties.MakeProp(wbem_key_name)
        if isinstance(wbem_value_literal, lib_util.scalar_data_types):
            wbem_value_node = lib_util.NodeLiteral(wbem_value_literal)
        elif isinstance(wbem_value_literal, (tuple)):
            tuple_joined = " ; ".join(wbem_value_literal)
            wbem_value_node = lib_util.NodeLiteral(tuple_joined)
        elif wbem_value_literal is None:
            if display_none_values:
                wbem_value_node = lib_util.NodeLiteral("None")
        else:
            wbem_value_node = lib_util.NodeLiteral("type=" + str(type(wbem_value_literal)) + ":" + str(wbem_value_literal))
            #try:
            #    refMoniker = str(wbem_value_literal.path())
            #    instance_url = lib_util.EntityUrlFromMoniker(refMoniker)
            #    wbem_value_node = lib_common.NodeUrl(instance_url)
            #except AttributeError as exc:
            #    wbem_value_node = lib_util.NodeLiteral(str(exc))

        dict_key_values[wbem_property] = wbem_value_node
    return dict_key_values


class WbemSparqlCallbackApi:
    """This is used to execute a Sparql query on WBEM objects."""
    def __init__(self):
        # Current host and default namespace.
        self.m_wbem_connection = WbemLocalConnection()

        self.m_classes = None

    # Note: The class CIM_DataFile with the property Name triggers the exception message:
    # "CIMError: 7: CIM_ERR_NOT_SUPPORTED: No provider or repository defined for class"
    def CallbackSelect(self, grph, class_name, predicate_prefix, filtered_where_key_values):
        logging.info("WbemSparqlCallbackApi.CallbackSelect class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
        assert class_name
       
        # This comes from such a Sparql triple: " ?variable rdf:type rdf:type"
        if class_name == "type":
            return
       
        wbem_query = lib_util.SplitMonikToWQL(filtered_where_key_values, class_name)
        logging.debug("WbemSparqlCallbackApi.CallbackSelect wbem_query=%s", wbem_query)

        wbem_objects = self.m_wbem_connection.ExecQuery("WQL", wbem_query, "root/cimv2")

        # This returns a list of CIMInstance.
        for one_wbem_object in wbem_objects:
            # dir(one_wbem_object)
            # ['_CIMComparisonMixin__ordering_deprecated', '__class__', '__contains__', '__delattr__', '__delitem__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_classname', '_cmp', '_path', '_properties', '_property_list', '_qualifiers', 'classname', 'copy', 'get', 'has_key', 'items', 'iteritems', 'iterkeys', 'itervalues', 'keys', 'path', 'properties', 'property_list', 'qualifiers', 'tocimxml', 'tocimxmlstr', 'tomof', 'update', 'update_existing', 'values']

            # one_wbem_object is a CIMInstanceName
            # dir(one_wbem_object.path)
            # ['_CIMComparisonMixin__ordering_deprecated', '__class__', '__contains__', '__delattr__', '__delitem__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setitem__', '__sizeof__', '__slotnames__', '__str__', '__subclasshook__', '__weakref__', '_classname', '_cmp', '_host', '_kbstr_to_cimval', '_keybindings', '_namespace', 'classname', 'copy', 'from_instance', 'from_wbem_uri', 'get', 'has_key', 'host', 'items', 'iteritems', 'iterkeys', 'itervalues', 'keybindings', 'keys', 'namespace', 'to_wbem_uri', 'tocimxml', 'tocimxmlstr', 'update', 'values']

            object_path = one_wbem_object.path.to_wbem_uri()
            # u'//vps516494.ovh.net/root/cimv2:PG_UnixProcess.CSName="vps516494.localdomain",Handle="1",OSCreationClassName="CIM_OperatingSystem",CreationClassName="PG_UnixProcess",CSCreationClassName="CIM_UnitaryComputerSystem",OSName="Fedora"'

            logging.debug("object.path=%s", object_path)
            dict_key_values = WbemKeyValues(one_wbem_object.iteritems())

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral("WBEM")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_util.NodeLiteral("WBEM")

        #     # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)

            logging.debug("dict_key_values=%s", dict_key_values)
            lib_util.PathAndKeyValuePairsToRdf(grph, object_path, dict_key_values)
            yield (object_path, dict_key_values)

    def CallbackAssociator(
            self,
            grph,
            result_class_name,
            predicate_prefix,
            associator_key_name,
            subject_path):
        logging.info("WbemSparqlCallbackApi.CallbackAssociator subject_path=%s result_class_name=%s associator_key_name=%s",
                subject_path,
                result_class_name,
                associator_key_name)
        assert subject_path

        # https://pywbem.readthedocs.io/en/latest/client/operations.html#pywbem.WBEMConnection.Associators
        instances_associators = self.m_wbem_connection.Associators(
            ObjectName=subject_path,
            AssocClass=associator_key_name,
            ResultClass=None, # ResultClass=result_class_name,
            Role=None,
            ResultRole=None,
            IncludeQualifiers=None,
            IncludeClassOrigin=None,
            PropertyList=None)

        for one_instance in instances_associators:
            print("Instance=", one_instance)
            yield one_instance

    def CallbackTypes(self, grph, see_also, where_key_values):
        """This returns the available types"""
        raise NotImplementedError("CallbackTypes: Not implemented yet")

        # # Data stored in a cache for later use.
        # if self.m_classes == None:
        #     self.m_classes = self.m_wbem_connection.classes
        #
        # for one_class_name in self.m_classes:
        #     class_path = "WbemClass:" + one_class_name
        #
        #     dict_key_values = {}
        #     dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral("WBEM")
        #     # Add it again, so the original Sparql query will work.
        #     dict_key_values[lib_kbase.PredicateSeeAlso] = lib_util.NodeLiteral("WBEM")
        #     dict_key_values[lib_kbase.PredicateType] = lib_kbase.PredicateType
        #     dict_key_values[lib_util.NodeLiteral("Name")] = lib_util.NodeLiteral(one_class_name)
        #
        #     class_node = lib_util.NodeUrl(class_path)
        #
        #     if grph:
        #         grph.add((class_node, lib_kbase.PredicateType, lib_kbase.PredicateType))
        #
        #     yield class_path, dict_key_values

    def CallbackTypeTree(self, grph, see_also, class_name, associator_subject):
        raise NotImplementedError("CallbackTypeTree: Not implemented yet")

