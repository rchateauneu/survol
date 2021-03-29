"""
Windows service
"""

import os
import sys
import logging

# Python for Windows extensions: pywin32
# https://sourceforge.net/projects/pywin32/
import win32service
import win32con
import win32api
import win32security

import lib_win32
import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def EntityOntology():
    return (["Name"],)

_state_dictionary = ('Unknown', 'Stopped', 'Starting', 'Stopping', 'Running',
                        'Continuing', 'Pausing', 'Paused')

# Enumerate Service Control Manager DB
_type_filter = win32service.SERVICE_WIN32
_state_filter = win32service.SERVICE_STATE_ALL

# Maybe similar to SC_MANAGER_ENUMERATE_SERVICE ?
accessSCM = win32con.GENERIC_READ

# It creates a dictionary containing all services keyed by their names.
def _build_srv_dict(hscm, machineName):

    # One node for each service name.
    dict_service_to_node = {}

    try:
        # Old versions of this library do not have this function.
        statuses = win32service.EnumServicesStatusEx(hscm, _type_filter, _state_filter)
        # li={'ControlsAccepted': 0, 'ServiceType': 32, 'DisplayName': 'WWAN AutoConfig', 'ServiceSpecificExitCode': 0,
        # 'ProcessId': 0, 'ServiceFlags': 0, 'CheckPoint': 0, 'ServiceName': 'WwanSvc', 'Win32ExitCode': 1077,
        # 'WaitHint': 0, 'CurrentState': 1},
        for lst in statuses:
            service_name = lst['ServiceName']
            lst["depends_in"] = []
            lst["depends_out"] = []

            dict_service_to_node[service_name] = lst

    # except AttributeError:
    except Exception:
        statuses = win32service.EnumServicesStatus(hscm, _type_filter, _state_filter)
        # li=('wuauserv', 'Windows Update', (32, 4, 453, 0, 0, 0, 0))
        for svc in statuses:
            logging.debug("service=%s", str(svc))
            # TODO: This must match the keys of EnumServicesStatusEx
            # lst = { "ServiceName":service_name, "DisplayName":descript, "CurrentState": status}
            lst = {"ServiceName":svc[0], "DisplayName":svc[1], "CurrentState": svc[2][1]}
            lst["depends_in"] = []
            lst["depends_out"] = []
            # A Win32 service status object is represented by a tuple
            # 0: serviceType
            # 1: serviceState
            # 2: controlsAccepted
            # 3: win32ExitCode
            # 4: serviceSpecificErrorCode
            # 5: checkPoint
            # 6: waitHint

            dict_service_to_node[svc[0]] = lst

            try:
                hsvc = win32service.OpenService(hscm, svc[0], win32service.SERVICE_CHANGE_CONFIG)

                # TODO: WHY DOING THIS ????? MAYBE FOR TESTING THE SERVICE PRESENCE ??

                #win32service.ChangeServiceConfig(hsvc, win32service.SERVICE_NO_CHANGE,
                #    win32service.SERVICE_DISABLED, win32service.SERVICE_NO_CHANGE, None, None,0,
                #    None,None,None,None)
                win32service.CloseServiceHandle(hsvc)
            except Exception:
                # Might receive "Access is denied" if this is on a remote machine.
                lst["ProcessId"] = 999999
                pass

    return dict_service_to_node


# This is a first approach to build the network of services dependencies.
def BuildSrvNetwork(machine_name):
    logging.debug("BuildSrvNetwork machineName=%s localhost=%s", machine_name, lib_util.currentHostname)

    mach_name_or_none, imper = lib_win32.MakeImpersonate(machine_name)

    # SC_MANAGER_ENUMERATE_SERVICE
    hscm = win32service.OpenSCManager(mach_name_or_none, None, accessSCM)

    dict_service_to_node = _build_srv_dict(hscm, machine_name)

    # Now links the services together.
    for service_name in dict_service_to_node:
        # nodeService = dict_service_to_node[ service_name ]

        try:
            hdn_srv = win32service.OpenService(hscm, service_name, win32service.SERVICE_ENUMERATE_DEPENDENTS)
            dep_srv_lst = win32service.EnumDependentServices(hdn_srv, win32service.SERVICE_STATE_ALL)

            for dep_srv in dep_srv_lst:
                sub_service_name = dep_srv[0]
                try:
                    nodeSubService = dict_service_to_node[sub_service_name]
                except KeyError:
                    logging.warning("Main=%s Sub=%s NOT CREATED", service_name, sub_service_name)
                    continue

                dict_service_to_node[sub_service_name]["depends_in"].append(service_name)
                dict_service_to_node[service_name]["depends_out"].append(sub_service_name)
            win32service.CloseServiceHandle(hdn_srv)
        except Exception as exc:
            # With wsgi and maybe cgi, many dependencies not seen. OK with Apache.
            # Why especially these ones which have a lot of dependencies ?
            # BuildSrvNetwork service_name=RpcSs:
            # BuildSrvNetwork service_name=RpcEptMapper
            # BuildSrvNetwork service_name=DcomLaunch:
            # BuildSrvNetwork service_name=pla:
            logging.warning("BuildSrvNetwork service_name=%s: Caught: %s", service_name, str(exc) )
            # pywintypes.error: (5, 'OpenService', 'Access is denied.')

            pass

    return dict_service_to_node


# Writes the key-values dicts of a service into a RDF node.
def DictServiceToNode(grph, service_dict, machine_name=None):
    # TODO: This is a process but not only. How to display that?
    service_name = service_dict['ServiceName']

    # NOTE: SOON, ALL ENTITIES WILL HAVE THEIR HOSTNAME.
    if machine_name in [None, ""]:
        node_service = lib_uris.gUriGen.ServiceUri(service_name)
    else:
        node_service = lib_common.RemoteBox(machine_name).ServiceUri(service_name)

    try:
        current_state_idx = service_dict['CurrentState']
        current_state_nam = _state_dictionary[current_state_idx]
    except KeyError:
        current_state_nam = "Unknown state key"
    except IndexError:
        current_state_nam = "Unknown state index"

    grph.add((node_service, pc.property_information, lib_util.NodeLiteral(service_dict['DisplayName'])))
    # TODO: Change color with the state. ASSOCIATE COLOR TO PAIRS (Property + Literal value) ? SPECIALLY CODED VALUE WITH HTML TAGS ?

    service_pid = service_dict['ProcessId']

    # Display is as compact as possible to help routing. Informaitonal only.
    if service_pid != 0:
        # TODO: Plutot mettre un lien vers le process mais afficher comme un literal.
        state_string = str(service_pid) + "/" + current_state_nam
        # grph.add((node_service, pc.property_pid, lib_util.NodeLiteral(service_pid)))
        grph.add((node_service, pc.property_pid, lib_util.NodeLiteral(state_string)))
    else:
        # grph.add((node_service, pc.property_service_state, lib_util.NodeLiteral(current_state_nam)))
        grph.add((node_service, pc.property_service_state, lib_util.NodeLiteral(current_state_nam)))
    return node_service


def FullServiceNetwork(grph, machine_name):
    logging.debug("FullServiceNetwork machineName=%s enter.", str(machine_name))
    dict_service_to_node = {}
    dict_service_map = BuildSrvNetwork(machine_name)

    # Creates all the RDF nodes.
    for service_name in dict_service_map:
        service_dict = dict_service_map[service_name]
        dict_service_to_node[service_name] = DictServiceToNode(grph, service_dict, machine_name)

    # Now links the services together.
    for service_name in dict_service_map:
        service_dict = dict_service_map[service_name]
        node_service = dict_service_to_node[service_name]
        for sub_service_name in service_dict["depends_in"]:
            node_sub_service = dict_service_to_node[sub_service_name]
            grph.add((node_service, pc.property_service, node_sub_service))
    logging.debug("FullServiceNetwork machineName=%s leaving.", str(machine_name))


def AddInfo(grph,node, entity_ids_arr):
    service_nam = entity_ids_arr[0]
    logging.debug("AddInfo service_nam=%s", service_nam)

    mach_name_or_none, imper = lib_win32.MakeImpersonate("")
    hscm = win32service.OpenSCManager(mach_name_or_none, None, accessSCM)

    try:
        status = win32service.SERVICE_QUERY_CONFIG|win32service.SERVICE_QUERY_STATUS|win32service.SERVICE_INTERROGATE|win32service.SERVICE_ENUMERATE_DEPENDENTS
        hdn_srv = win32service.OpenService( hscm, service_nam, status )
        lst_srv_pairs = win32service.QueryServiceStatusEx(hdn_srv)
        win32service.CloseServiceHandle(hdn_srv)
    except Exception as exc:
        # Probably "Access is denied"
        logging.warning("AddInfo Caught:%s", str(exc))
        lst_srv_pairs = dict()
        try:
            lst_srv_pairs["Status"] = str(exc[2])
        except:
            lst_srv_pairs["Status"] = str(exc)

    # CheckPoint                0
    # ControlsAccepted          1
    # CurrentState              4
    # ProcessId              3176
    # ServiceFlags              0
    # ServiceSpecificExitCode    0
    # ServiceType              16
    # WaitHint                  0
    # Win32ExitCode             0
    for key_srv in lst_srv_pairs:
        logging.debug("AddInfo key_srv:%s", key_srv)
        val_srv = lst_srv_pairs[key_srv]
        if key_srv == "ProcessId":
            if int(val_srv) != 0:
                node_proc = lib_uris.gUriGen.PidUri(val_srv)
                grph.add((node_proc, pc.property_pid, lib_util.NodeLiteral(val_srv)))
                grph.add((node, lib_common.MakeProp(key_srv), node_proc))
        elif key_srv == "ServiceType":
            svc_typ_src = ""
            svc_typ_int = int(val_srv)
            if svc_typ_int & win32service.SERVICE_KERNEL_DRIVER: svc_typ_src += "KERNEL_DRIVER "
            if svc_typ_int & win32service.SERVICE_FILE_SYSTEM_DRIVER: svc_typ_src += "FILE_SYSTEM_DRIVER "
            #if svc_typ_int & win32service.SERVICE_ADAPTER: svc_typ_src += "ADAPTER "
            #if svc_typ_int & win32service.SERVICE_RECOGNIZER_DRIVER: svc_typ_src += "RECOGNIZER_DRIVER "
            if svc_typ_int & win32service.SERVICE_WIN32_OWN_PROCESS: svc_typ_src += "WIN32_OWN_PROCESS "
            if svc_typ_int & win32service.SERVICE_WIN32_SHARE_PROCESS: svc_typ_src += "WIN32_SHARE_PROCESS "
            if svc_typ_int & win32service.SERVICE_WIN32: svc_typ_src += "WIN32 "
            if svc_typ_int & win32service.SERVICE_INTERACTIVE_PROCESS: svc_typ_src += "INTERACTIVE_PROCESS "

            grph.add((node, lib_common.MakeProp(key_srv), lib_util.NodeLiteral(svc_typ_src)))

        elif key_srv == "CurrentState":
            states_array = (
                "SERVICE_STOPPED",
                "SERVICE_START_PENDING",
                "SERVICE_STOP_PENDING",
                "SERVICE_RUNNING",
                "SERVICE_CONTINUE_PENDING",
                "SERVICE_PAUSE_PENDING",
                "SERVICE_PAUSED" )

            # Fetches from the module a constant with this value.
            src_stat_src = val_srv
            for srv_stat_var in states_array:
                if val_srv == getattr(win32service, srv_stat_var):
                    src_stat_src = srv_stat_var
                    break
            grph.add((node, lib_common.MakeProp(key_srv), lib_util.NodeLiteral(src_stat_src)))

        else:
            grph.add((node, lib_common.MakeProp(key_srv), lib_util.NodeLiteral(val_srv)))

    return
