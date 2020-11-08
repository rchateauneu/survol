"""
Computer system.

Scripts related to the class CIM_ComputerSystem.
"""

import sys
import socket
import lib_util


# This must be defined here, because dockit cannot load modules from here, and this ontology would not be defined.
def EntityOntology():
    return (["Name"],)


import lib_common
from lib_properties import pc


def EntityName(entity_ids_arr):
    """This returns a nice name given the parameter of the object."""
    entity_id = entity_ids_arr[0]
    return entity_id


def UniversalAlias(entity_ids_arr, entity_host, entity_class):
    """This does not care about the entity_host as this is simply the machine from which
    this machine was detected, so nothing more than a computer on the same network."""
    return "ThisComputer:" + entity_ids_arr[0].lower()

    # TODO: This is too slow and not used yet. Consider using a cache.
    try:
        # (entity_ids_arr=[u'desktop-ni99v8e'], entity_host='192.168.0.14', entity_class=u'CIM_ComputerSystem')
        # might possibly throw:
        # "[Errno 11004] getaddrinfo failed "
        a_host_name = lib_util.GlobalGetHostByName(entity_ids_arr[0])
    except:
        a_host_name = entity_host

    # Hostnames are case-insensitive, RFC4343 https://tools.ietf.org/html/rfc4343
    return "ThisComputer:" + a_host_name.lower()


def AddWbemWmiServers(grph, root_node, entity_host, name_space, entity_type, entity_id):
    """This adds the WBEM and WMI urls related to the entity."""
    if entity_host:
        host_wbem_wmi = entity_host
    else:
        host_wbem_wmi = lib_util.currentHostname

    # This receives a map and a RDF property, and must add the correspknding nodes to the root_node
    # int the given graph. The same callback signature is used elsewhere to generate HTML tables.
    def add_w_map(the_map, prop_data):
        if the_map:
            for url_subj in the_map:
                grph.add((root_node, prop_data, url_subj))
                for the_prop, url_obj in the_map[url_subj]:
                    grph.add((url_subj, the_prop, url_obj))

    map_wbem = AddWbemServers(host_wbem_wmi, name_space, entity_type, entity_id)
    add_w_map(map_wbem, pc.property_wbem_data)
    map_wmi = AddWmiServers(host_wbem_wmi, name_space, entity_type, entity_id)
    add_w_map(map_wmi, pc.property_wmi_data)
    map_survol = AddSurvolServers(host_wbem_wmi, name_space, entity_type, entity_id)
    add_w_map(map_survol, pc.property_survol_agent)


def AddWbemServers(entity_host, name_space, entity_type, entity_id):
    map_wbem = dict()
    try:
        # Maybe some of these servers are not able to display anything about this object.
        import lib_wbem

        wbem_servers_desc_list = lib_wbem.GetWbemUrlsTyped(entity_host, name_space, entity_type, entity_id)
        # sys.stderr.write("wbem_servers_desc_list len=%d\n" % len(wbem_servers_desc_list))
        for url_server in wbem_servers_desc_list:
            # TODO: Filter only entity_host
            # sys.stderr.write("url_server=%s\n" % str(url_server))

            if lib_wbem.ValidClassWbem(entity_type):
                wbem_node = lib_common.NodeUrl(url_server[0])
                if entity_host:
                    txt_literal = "WBEM url, host=%s class=%s"%(entity_host,entity_type)
                else:
                    txt_literal = "WBEM url, current host, class=%s"%(entity_type)

                wbem_host_node = lib_common.gUriGen.HostnameUri(url_server[1])

                map_wbem[wbem_node] = [
                    (pc.property_information, lib_util.NodeLiteral(txt_literal)),
                    (pc.property_host, wbem_host_node)
                ]

                # TODO: This could try to pen a HTTP server on this machine, possibly with port 80.
                # grph.add( ( wbem_host_node, pc.property_information, lib_util.NodeLiteral("Url to host") ) )
    except ImportError:
        pass
    return map_wbem


def AddWmiServers(entity_host, name_space, entity_type, entity_id):
    map_wmi = dict()

    # No WMI implementation is available on Linux.
    if lib_util.isPlatformLinux:
        return map_wmi

    import lib_wmi

    if lib_wmi.ValidClassWmi(entity_type):
        # TODO: We may also loop on all machines which may describe this object.
        wmiurl = lib_wmi.GetWmiUrl(entity_host, name_space, entity_type, entity_id)
        # sys.stderr.write("wmiurl=%s\n" % str(wmiurl))
        if wmiurl:
            wmi_node = lib_common.NodeUrl(wmiurl)
            if entity_host:
                txt_literal = "WMI url, host=%s class=%s"%(entity_host,entity_type)
            else:
                txt_literal = "WMI url, current host, class=%s"%(entity_type)

            map_wmi[wmi_node] = [
                (pc.property_information, lib_util.NodeLiteral(txt_literal))
            ]

            if entity_host:
                node_portal_wmi = lib_util.UrlPortalWmi(entity_host)

                map_wmi[wmi_node].append(
                    (pc.property_rdf_data_nolist2, node_portal_wmi)
                )
    return map_wmi


def AddSurvolServers(entity_host, name_space, entity_type, entity_id):
    map_survol = dict()

    # TODO: Not implemented yet.
    return map_survol


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
        for json_key, json_val in geoc.json.iteritems():
            # Conversion to str otherwise numbers are displayed as "float".
            grph.add((node, lib_common.MakeProp(json_key), lib_util.NodeLiteral(str(json_val))))
    except Exception:
        # This might be a simple time-out.
        return


def AddInfo(grph,node, entity_ids_arr):
    """The URL is hard-coded but very important because it allows to visit another host with WMI access."""
    the_hostname = entity_ids_arr[0]

    try:
        ipv4 = lib_util.GlobalGetHostByName(the_hostname)
    except:
        grph.add((node, pc.property_information, lib_util.NodeLiteral("Unknown machine")))
        return

    grph.add((node, lib_common.MakeProp("IP address"), lib_util.NodeLiteral(ipv4)))

    fqdn = socket.getfqdn(the_hostname)
    grph.add((node, lib_common.MakeProp("FQDN"), lib_util.NodeLiteral(fqdn)))

    # No need to do that, because it is done in entity.py if mode!=json.
    # nameSpace = ""
    # AddWbemWmiServers(grph,node,the_hostname, nameSpace, "CIM_ComputerSystem", "Name="+the_hostname)

    AddGeocoder(grph,node,ipv4)
