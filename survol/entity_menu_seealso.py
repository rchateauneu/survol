#!/usr/bin/env python

"""
Scripts hierarchy

It is used by entity.py as a module, but also as a script with the CGI parameter mode=menu,
by the D3 interface, to build contextual right-click menu.
It is also used by the client library lib_client, to return all the scripts accessible from an object.
It is never displayed directly.
"""

import logging
import lib_util
import lib_common
import lib_dirmenu
import lib_kbase

"""
<rdf:RDF
 xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:dct="http://purl.org/dc/terms/"
 xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#">
    <rdf:Description rdf:about="http://localhost:8765/objects">
        <dct:hasPart rdf:resource="http://localhost:8765/objects/__NODE__.information"/>
        <dct:hasPart rdf:resource="http://localhost:8765/objects/__NODE__.references"/>
        <dct:hasPart rdf:resource="http://localhost:8765/objects/__NODE__.associators"/>
        <rdfs:label>CIM_DataFile</rdfs:label>
    </rdf:Description>
    <rdf:Description rdf:about="http://localhost:8765/objects/__NODE__.information">
        <rdfs:label>Object information</rdfs:label>
        <rdfs:seeAlso rdf:resource="http://localhost:8765/objects/information"/>
    </rdf:Description>
    <rdf:Description rdf:about="http://localhost:8765/objects/__NODE__.references">
        <rdfs:label>Referenced objects</rdfs:label>
        <rdfs:seeAlso rdf:resource="http://localhost:8765/objects/references"/>
    </rdf:Description>
    <rdf:Description rdf:about="http://localhost:8765/objects/__NODE__.associators">
        <rdfs:label>Associator objects</rdfs:label>
        <rdfs:seeAlso rdf:resource="http://localhost:8765/objects/associators"/>
    </rdf:Description>
</rdf:RDF>
"""

"""
http://vps516494.ovh.net/Survol/survol/entity_dirmenu_only.py?xid=CIM_Process.Handle=1209&mode=menu
Mais : On fabrique deja du RDF/seeAlso ??? Mais ca ne marche pas et n'est pas utilise.
Mais pourquoi ca ne marche pas alors qu'on fabrique du RDF ?
C'est parce que ca ajoute l'ontology, c'est un hasard.
Il faut renvoyer le RDF tel quel.
http://vps516494.ovh.net/Survol/survol/entity_dirmenu_only.py?xid=CIM_Process.Handle=2001&mode=rdf

http://192.168.1.105:8000/survol/entity_dirmenu_only.py?xid=CIM_Process.Handle=1209&mode=rdf
"""




toto = {
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/environment_variables.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Environment variables",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/environment_variables.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/events_feeder_system_calls.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Monitor system calls with dockit.",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/events_feeder_system_calls.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/oracle_process_dbs.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Oracle databases accessed",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/oracle_process_dbs.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_command_line.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Command line",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_command_line.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_connections.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Process open sockets",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_connections.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_cwd.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Current working directory",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_cwd.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_gdbstack.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Process callstack with gdb",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_gdbstack.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_memmaps.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Shared memory segments",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_memmaps.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_open_files.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Files opened by process",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/process_open_files.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/single_pidstree.py?xid=CIM_Process.Handle%3D1209": {
    "name": "Parent and sub-processes",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/single_pidstree.py?xid=CIM_Process.Handle%3D1209"
  },
  "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/wbem_process_info.py?xid=CIM_Process.Handle%3D1209": {
    "name": "WBEM CIM_Process information.",
    "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/wbem_process_info.py?xid=CIM_Process.Handle%3D1209"
  },
  "Languages": {
    "items": {
      "Java processes": {
        "items": {
          "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/languages/java/java_mbeans.py?xid=CIM_Process.Handle%3D1209": {
            "name": "Process MBeans",
            "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/languages/java/java_mbeans.py?xid=CIM_Process.Handle%3D1209"
          },
          "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/languages/java/java_system_properties.py?xid=CIM_Process.Handle%3D1209": {
            "name": "System Properties",
            "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/languages/java/java_system_properties.py?xid=CIM_Process.Handle%3D1209"
          },
          "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/languages/java/jdk_jstack.py?xid=CIM_Process.Handle%3D1209": {
            "name": "Full thread dump Java HotSpot (TM)",
            "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/languages/java/jdk_jstack.py?xid=CIM_Process.Handle%3D1209"
          }
        },
        "name": "Java processes",
        "url": "Java processes"
      }
    },
    "name": "Languages",
    "url": "Languages"
  },
  "Regex matching in heap": {
    "items": {
      "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py?xid=CIM_Process.Handle%3D1209": {
        "name": "Extract SQL queries from process heap me...",
        "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py?xid=CIM_Process.Handle%3D1209"
      },
      "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/memory_regex_search/search_filenames.py?xid=CIM_Process.Handle%3D1209": {
        "name": "File names in process memory.",
        "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/memory_regex_search/search_filenames.py?xid=CIM_Process.Handle%3D1209"
      },
      "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/memory_regex_search/search_urls.py?xid=CIM_Process.Handle%3D1209": {
        "name": "Scan process for HTTP urls.",
        "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/memory_regex_search/search_urls.py?xid=CIM_Process.Handle%3D1209"
      }
    },
    "name": "Regex matching in heap",
    "url": "Regex matching in heap"
  },
  "Scripts specific to Linux processes": {
    "items": {
      "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/Linux/process_cgroups.py?xid=CIM_Process.Handle%3D1209": {
        "name": "Process cgroups",
        "url": "http://vps516494.ovh.net:80/Survol/survol/sources_types/CIM_Process/Linux/process_cgroups.py?xid=CIM_Process.Handle%3D1209"
      }
    },
    "name": "Scripts specific to Linux processes",
    "url": "Scripts specific to Linux processes"
  }
}

def Main():
    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.ScriptEnvironment(
                    can_process_remote=True,
                    parameters={lib_util.paramkeyShowAll: False})
    entity_id = cgiEnv.m_entity_id
    entity_host = cgiEnv.GetHost()
    flag_show_all = int(cgiEnv.get_parameters(lib_util.paramkeyShowAll))

    name_space, entity_type = cgiEnv.get_namespace_type()

    if lib_util.is_local_address(entity_host):
        entity_host = ""

    logging.debug("entity: entity_host=%s entity_type=%s entity_id=%s", entity_host, entity_type, entity_id)

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    if entity_id != "" or entity_type == "":
        def callback_grph_add(tripl, depth_call):
            grph.add(tripl)

        lib_dirmenu.recursive_walk_on_scripts(
            callback_grph_add, root_node, entity_type, entity_id, entity_host, flag_show_all, True)

    arr_headers = [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Methods', 'POST,GET,OPTIONS'),
        ('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept'),
    ]
    lib_util.WrtHeader('application/xml', arr_headers)

    out_dest = lib_util.get_default_output_destination()

    lib_kbase.triplestore_to_stream_xml(grph, out_dest, 'xml')
    logging.debug("Grph2Rdf leaving, len(new_grph)=%d", len(grph))


if __name__ == '__main__':
    Main()
