"""
Computer system.

Execution of Survol agent, WMI or WBEM requests etc...
"""

import sys
import socket
import lib_wmi
import lib_util
import lib_common
from lib_properties import pc

def EntityOntology():
    return ( ["Name"], )

# This returns a nice name given the parameter of the object.
def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]
    return entity_id

# We do not care about the entity_host as this is simply the machine from which
# this machine was detected, so nothing more than a computer on the same network.
def UniversalAlias(entity_ids_arr,entity_host,entity_class):
    # TOO SLOW !!!
    return "ThisComputer:"+entity_ids_arr[0].lower()


    try:
        # (entity_ids_arr=[u'desktop-ni99v8e'], entity_host='192.168.0.14', entity_class=u'CIM_ComputerSystem')
        # might possibly throw:
        # "[Errno 11004] getaddrinfo failed "
        aHostName = lib_util.GlobalGetHostByName(entity_ids_arr[0])
    except:
        aHostName = entity_host

    # Hostnames are case-insensitive, RFC4343 https://tools.ietf.org/html/rfc4343
    return "ThisComputer:"+aHostName.lower()

# This adds the WBEM and WMI urls related to the entity.
def AddWbemWmiServers(grph,rootNode,entity_host, nameSpace, entity_type, entity_id):
    lib_util.Logger().debug("AddWbemWmiServers entity_host=%s nameSpace=%s entity_type=%s entity_id=%s", entity_host,nameSpace,entity_type,entity_id)

    if entity_host:
        host_wbem_wmi = entity_host
    else:
        host_wbem_wmi = lib_util.currentHostname

    # This receives a map and a RDF property, and must add the correspknding nodes to the rootNode
    # int the given graph. The same callback signature is used elsewhere to generate HTML tables.
    def AddWMap(theMap,propData):
        for urlSubj in theMap:
            grph.add( ( rootNode, propData, urlSubj ) )
            for theProp, urlObj in theMap[urlSubj]:
                grph.add( ( urlSubj, theProp, urlObj ) )


    mapWbem = AddWbemServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
    AddWMap(mapWbem,pc.property_wbem_data)
    mapWmi = AddWmiServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
    AddWMap(mapWmi,pc.property_wmi_data)
    mapSurvol = AddSurvolServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
    AddWMap(mapSurvol,pc.property_survol_agent)



def AddWbemServers(entity_host, nameSpace, entity_type, entity_id):
    lib_util.Logger().debug("AddWbemServers entity_host=%s nameSpace=%s entity_type=%s entity_id=%s",entity_host,nameSpace,entity_type,entity_id)

    mapWbem = dict()
    try:
    # Maybe some of these servers are not able to display anything about this object.
        import lib_wbem


        wbem_servers_desc_list = lib_wbem.GetWbemUrlsTyped( entity_host, nameSpace, entity_type, entity_id )
        # sys.stderr.write("wbem_servers_desc_list len=%d\n" % len(wbem_servers_desc_list))
        for url_server in wbem_servers_desc_list:
            # TODO: Filter only entity_host
            # sys.stderr.write("url_server=%s\n" % str(url_server))

            if lib_wbem.ValidClassWbem(entity_type):
                wbemNode = lib_common.NodeUrl(url_server[0])
                if entity_host:
                    txtLiteral = "WBEM url, host=%s class=%s"%(entity_host,entity_type)
                else:
                    txtLiteral = "WBEM url, current host, class=%s"%(entity_type)

                wbemHostNode = lib_common.gUriGen.HostnameUri( url_server[1] )

                mapWbem[wbemNode] = [
                    ( pc.property_information, lib_common.NodeLiteral(txtLiteral ) ),
                    ( pc.property_host, wbemHostNode )
                ]

                # TODO: This could try to pen a HTTP server on this machine, possibly with port 80.
                # grph.add( ( wbemHostNode, pc.property_information, lib_common.NodeLiteral("Url to host") ) )
    except ImportError:
        pass
    return mapWbem

def AddWmiServers(entity_host, nameSpace, entity_type, entity_id):
    lib_util.Logger().debug("AddWmiServers entity_host=%s nameSpace=%s entity_type=%s entity_id=%s",entity_host,nameSpace,entity_type,entity_id)

    mapWmi = dict()
    if lib_wmi.ValidClassWmi(entity_type):
        # TODO: We may also loop on all machines which may describe this object.
        wmiurl = lib_wmi.GetWmiUrl( entity_host, nameSpace, entity_type, entity_id )
        # sys.stderr.write("wmiurl=%s\n" % str(wmiurl))
        if wmiurl:
            wmiNode = lib_common.NodeUrl(wmiurl)
            if entity_host:
                txtLiteral = "WMI url, host=%s class=%s"%(entity_host,entity_type)
            else:
                txtLiteral = "WMI url, current host, class=%s"%(entity_type)

            mapWmi[wmiNode] = [
                (pc.property_information, lib_common.NodeLiteral(txtLiteral))
            ]

            if entity_host:
                nodePortalWmi = lib_util.UrlPortalWmi(entity_host)

                mapWmi[wmiNode].append(
                    (pc.property_rdf_data_nolist2, nodePortalWmi)
                )
    return mapWmi

def AddSurvolServers(entity_host, nameSpace, entity_type, entity_id):
    lib_util.Logger().debug("AddSurvolServers entity_host=%s nameSpace=%s entity_type=%s entity_id=%s",entity_host,nameSpace,entity_type,entity_id)

    mapSurvol = dict()

    # TODO: Not implemented yet.

    return mapSurvol


# g = geocoder.ip('216.58.206.37')
# g.json
# {'status': 'OK', 'city': u'Mountain View', 'ok': True, 'encoding': 'utf-8', 'ip': u'216.58.206.37',
# 'hostname': u'lhr35s10-in-f5.1e100.net', 'provider': 'ipinfo', 'state': u'California', 'location': '216.58.206.37',
#  'status_code': 200, 'country': u'US', 'lat': 37.4192, 'org': u'AS15169 Google Inc.', 'lng': -122.0574, 'postal': u'94043',
#  'address': u'Mountain View, California, US'}
#
# g = geocoder.ip('192.168.1.22')
# g.json
# {'status': 'ERROR - No results found', 'status_code': 200, 'encoding': 'utf-8', 'ip': u'192.168.1.22',
#  'location': '192.168.1.22', 'provider': 'ipinfo', 'ok': False}
def AddGeocoder(grph,node,ipv4):
    try:
        import geocoder
    except ImportError:
        return

    try:
        geoc = geocoder.ip(ipv4)
        for jsonKey,jsonVal in geoc.json.iteritems():
            # Conversion to str otherwise numbers are displayed as "float".
            grph.add( ( node, lib_common.MakeProp(jsonKey), lib_common.NodeLiteral(str(jsonVal)) ) )
    except Exception:
        # This might be a simple time-out.
        return


# The URL is hard-coded but very important because it allows to visit another host with WMI access.
def AddInfo(grph,node,entity_ids_arr):
    theHostname = entity_ids_arr[0]

    try:
        ipv4 = lib_util.GlobalGetHostByName(theHostname)
    except:
        grph.add( ( node, pc.property_information, lib_common.NodeLiteral("Unknown machine") ) )
        return

    grph.add( ( node, lib_common.MakeProp("IP address"), lib_common.NodeLiteral(ipv4) ) )

    fqdn = socket.getfqdn(theHostname)
    grph.add( ( node, lib_common.MakeProp("FQDN"), lib_common.NodeLiteral(fqdn) ) )

    # No need to do that, because it is done in entity.py if mode!=json.
    # nameSpace = ""
    # AddWbemWmiServers(grph,node,theHostname, nameSpace, "CIM_ComputerSystem", "Name="+theHostname)

    AddGeocoder(grph,node,ipv4)
