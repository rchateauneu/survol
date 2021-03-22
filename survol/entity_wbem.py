#!/usr/bin/env python

"""
WBEM instance
Display generic properties of a WBEM object.
"""

import sys
import logging
import lib_uris
import lib_common
import lib_util
from lib_properties import pc

try:
    import pywbem
    import lib_wbem
except ImportError:
    lib_common.ErrorMessageHtml("Pywbem Python library not installed")


# If ExecQuery is not supported like on OpenPegasus, try to build one instance.
def WbemPlainExecQuery(conn, class_name, split_monik, name_space):
    a_qry = lib_util.SplitMonikToWQL(split_monik, class_name)
    logging.debug("WbemPlainExecQuery nameSpace=%s a_qry=%s", name_space, a_qry)
    # a_qry = 'select * from CIM_System'
    # a_qry = 'select * from CIM_ComputerSystem'
    try:
        # This does not work on OpenPegasus.
        return conn.ExecQuery("WQL", a_qry, name_space)
    except Exception as exc:
        # Problem on Windows with OpenPegasus.
        # a_qry=select * from CIM_UnitaryComputerSystem ...
		# where CreationClassName="PG_ComputerSystem" ...
		# and Name="rchateau-HP". ns=root/cimv2. Caught:(7, u'CIM_ERR_NOT_SUPPORTED')
        msg_exc_first = str(exc)
        logging.warning("WbemPlainExecQuery a_qry=%s Exc=%s", a_qry, msg_exc_first)
        return None


# If ExecQuery is not supported like on OpenPegasus, try to build one instance.
def WbemNoQueryOneInst(conn, class_name, split_monik, name_space):
    try:
        key_bnds = pywbem.cim_obj.NocaseDict(split_monik)

        # FIXME: Problem with parameters: msgExcFirst=CIMError: header-mismatch, PGErrorDetail:
        # Empty CIMObject value. wbem_inst_name=root/CIMv2:CIM_ComputerSystem.Name="rchateau-HP".
        # ns=. Caught:(4, u'CIM_ERR_INVALID_PARAMETER: Wrong number of keys')

        wbem_inst_name = pywbem.CIMInstanceName(class_name, keybindings=key_bnds, namespace="root/CIMv2")
        logging.debug("key_bnds=%s wbem_inst_name=%s", str(key_bnds), str(wbem_inst_name))

        wbem_inst_obj = conn.GetInstance(wbem_inst_name)

        return [wbem_inst_obj]
    except:
        exc = sys.exc_info()[1]
        logging.warning("WbemNoQueryOneInst className=" + str(class_name) + ". ns=" + name_space + ".\nCaught:" + str(exc))
        return None


# If ExecQuery is not supported like on OpenPegasus, read all instances and filters the good ones. VERY SLOW.
def WbemNoQueryFilterInstances(conn, class_name, split_monik, name_space):
    try:
        # TODO: namespace is hard-coded.
        name_space = "root/CIMv2"
        inst_names_list = conn.EnumerateInstanceNames(ClassName=class_name, namespace=name_space)
    except Exception:
        exc = sys.exc_info()[1]
        lib_common.ErrorMessageHtml("EnumerateInstanceNames: nameSpace=" + name_space
                                  + " className=" + class_name + ". Caught:" + str(exc))

    list_insts = []
    for inst_nam in inst_names_list:
        keys_to_check = []
        is_different = False
        for monik_key in split_monik:
            # TODO: We could check that once only for the whole class, maybe ?
            if inst_nam.has_key(monik_key):
                inst_nam_val = inst_nam.get(monik_key)
                if inst_nam_val != split_monik[monik_key]:
                    is_different = True
                    break
            else:
                keys_to_check.append(monik_key)

        if is_different:
            continue

        # Now we have to load the instance anyway and compare some keys which are not in the InstanceName.
        wbem_inst = conn.GetInstance(inst_nam)

        is_different = False
        for monik_key in keys_to_check:
            if wbem_inst.has_key(monik_key):
                inst_nam_val = wbem_inst.get(monik_key)
                if inst_nam_val != split_monik[monik_key]:
                    is_different = True
                    break

        if is_different:
            continue
        list_insts.append(inst_nam)

    return list_insts


# This adds a link to the namespace of this WBEM class: It shows its inheritance graph.
def AddNamespaceLink(grph, root_node, name_space, cimom_url, class_name):
    url_namespace = lib_wbem.NamespaceUrl(name_space, cimom_url, class_name)
    nod_namespace = lib_common.NodeUrl(url_namespace)
    grph.add((root_node, pc.property_cim_subnamespace , nod_namespace))


def Main():

    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)

    entity_id = cgiEnv.GetId()
    logging.debug("entity_id=%s", entity_id)
    if entity_id == "":
        lib_common.ErrorMessageHtml("No entity_id")

    # Just the path, shorter than cgiEnv.get_parameters("xid")
    cimom_url = cgiEnv.GetHost()

    name_space, class_name = cgiEnv.get_namespace_type()
    logging.debug("entity_wbem.py cimom_url=%s name_space=%s class_name=%s", cimom_url, name_space, class_name)

    if name_space == "":
        name_space = "root/cimv2"
        logging.info("Setting namespace to default value\n")

    if class_name == "":
        lib_common.ErrorMessageHtml("No class name. entity_id=%s" % entity_id)

    grph = cgiEnv.GetGraph()

    try:
        conn = lib_wbem.WbemConnection(cimom_url)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Connecting to :" + cimom_url + " Caught:" + str(exc))

    root_node = lib_util.EntityClassNode(class_name, name_space, cimom_url, "WBEM")
    kla_descrip = lib_wbem.WbemClassDescription(conn, class_name, name_space)
    if not kla_descrip:
        kla_descrip = "Undefined class %s %s" % (name_space, class_name)
    grph.add((root_node, pc.property_information, lib_util.NodeLiteral(kla_descrip)))

    split_monik = cgiEnv.m_entity_id_dict

    logging.debug("entity_wbem.py name_space=%s class_name=%s cimom_url=%s" ,name_space, class_name, cimom_url)

    # This works:
    # conn = pywbem.WBEMConnection("http://192.168.0.17:5988",("pegasus","toto"))
    # conn.ExecQuery("WQL","select * from CIM_System","root/cimv2")
    # conn.ExecQuery("WQL",'select * from CIM_Process  where Handle="4125"',"root/cimv2")
    #
    # select * from CIM_Directory or CIM_DataFile does not return anything.

    inst_lists = WbemPlainExecQuery(conn, class_name, split_monik, name_space)
    logging.debug("entity_wbem.py inst_lists=%s", str(inst_lists))
    if inst_lists is None:
        inst_lists = WbemNoQueryOneInst(conn, class_name, split_monik, name_space)
        if inst_lists is None:
            inst_lists = WbemNoQueryFilterInstances(conn, class_name, split_monik, name_space)

    # TODO: Some objects are duplicated.
    # 'CSCreationClassName'   CIM_UnitaryComputerSystem Linux_ComputerSystem
    # 'CreationClassName'     PG_UnixProcess            TUT_UnixProcess
    num_insts = len(inst_lists)

    # If there are duplicates, adds a property which we hope is different.
    prop_discrim = "CreationClassName"

    # TODO!! WHAT OF THIS IS NOT THE RIGHT ORDER ???
    # Remove the double-quotes around the argument. WHAT IF THEY ARE NOT THERE ??

    for an_inst in inst_lists:

        # TODO: Use the right accessor for better performance.
        # On peut peut etre mettre tout ca dans une fonction sauf l execution de la query.
        dict_inst = dict(an_inst)

        # This differentiates several instance with the same properties.
        if num_insts > 1:
            # TODO: Should check if this property is different for all instances !!!
            with_extra_args = {prop_discrim: dict_inst[prop_discrim]}
            all_args = split_monik.copy()
            all_args.update(with_extra_args)
            dict_props = all_args
        else:
            dict_props = split_monik

        host_only = lib_util.EntHostToIp(cimom_url)
        uri_inst = lib_common.MachineBox(host_only).UriMakeFromDict(class_name, dict_props)

        grph.add((root_node, lib_common.MakeProp(class_name), uri_inst))

        AddNamespaceLink(grph, root_node, name_space, cimom_url, class_name)

        # None properties are not printed.
        for iname_key in dict_inst:
            # Do not print twice values which are in the name.
            if iname_key in split_monik:
                continue
            iname_val = dict_inst[iname_key]
            # TODO: If this is a reference, create a Node !!!!!!!
            if not iname_val is None:
                grph.add((uri_inst, lib_common.MakeProp(iname_key), lib_util.NodeLiteral(iname_val)))

        # TODO: Should call Associators(). Same for References().

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
