#!/usr/bin/env python

"""
WMI instance
"""

import sys
import time
import lib_common
import lib_wmi
import lib_util

try:
    import wmi
except ImportError:
    lib_common.ErrorMessageHtml("WMI Python library not installed")

# Do not use WQL because it filters data after they have been selected by WMI.
# On the contrary, WMI applies its filters on classes.
# A WMI Filter is a set of conditions used against the instances of a WMI Class
# which defines whether or not an instance should be reported or excluded.
def WmiReadWithMoniker( cgiEnv, cgiMoniker ):
    """
        This returns an array of the single object read wrom WMI with the moniker.
        Or null if no such object exists.
    """
    try:
        obj_wmi = wmi.WMI(moniker=cgiMoniker, find_classes=False)
        return [ obj_wmi ]
    except Exception as exc:
        DEBUG("cgiMoniker=%s Caught:%s", cgiMoniker, str(exc))
        return None


def WmiReadWithQuery(cgiEnv, conn_wmi, class_name):
    """
        Maybe reading with the moniker does not work because not all properties.
        This splits the moniker into key value paris, and uses a WQL query.
    """
    split_monik = lib_util.SplitMoniker(cgiEnv.m_entity_id)
    a_qry = lib_util.SplitMonikToWQL(split_monik, class_name)

    try:
        return conn_wmi.query(a_qry)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Query=%s Caught:%s" % (a_qry, str(exc)))


def DispWmiProperties(grph, conn_wmi, wmi_instance_node, obj_wmi, display_none_values, class_name):
    """
        Get the properties and values of a WMI object (Not a class),
        then adds them to the triples graph.
    """

    lst_key_values = lib_wmi.WmiKeyValues(conn_wmi, obj_wmi, display_none_values, class_name)
    for prp_prop, prp_value in lst_key_values:
        grph.add((wmi_instance_node, prp_prop, prp_value))


def ImportSurvolModuleFromWmiClass(conn_wmi, class_name):
    all_base_classes = (class_name,) + lib_wmi.WmiBaseClasses(conn_wmi, class_name)
    for the_class_ascending in all_base_classes:
        # Maybe there is a module without ontology.
        # In this case, try a base class. This is what does this function.
        onto_keys = lib_util.OntologyClassKeys(the_class_ascending)
        if len(onto_keys):
            return (the_class_ascending, onto_keys)
    return None,None


def AddSurvolObjectFromWmi(grph, wmi_instance_node, conn_wmi, class_name, obj_list):
    """
        Must find the url of the object in the Survol terminoloy equivalent to this one in WMI.
        This does not care the namespace which is set to root/cimv2 anyway.
        The reason is that it is the most common one, and the others seem to be used
        for very technical purpose.
    """

    # The first step is to iterate on the base classes until there is one of the Survol classes.
    (survol_equivalent_class, onto_keys) = ImportSurvolModuleFromWmiClass(conn_wmi, class_name)

    # This class nor any of its base classes exists in Survol.
    if survol_equivalent_class is None:
        return

    set_survol_urls = set()

    for obj_wmi in obj_list:
        # sys.stderr.write("obj_wmi=[%s]\n" % str(obj_wmi) )

        prop_values_array = []

        # For each property of the survol ontology, picks the value returned by WMI.
        # Replace missing values by an empty string.
        for surv_key in onto_keys:
            try:
                wmi_val = getattr(obj_wmi, surv_key)
            except KeyError:
                INFO("AddSurvolObjectFromWmi className=%s no value for key=%s", class_name, surv_key)
                wmi_val = ""
            prop_values_array.append(wmi_val)

        entity_module = lib_util.GetEntityModule(survol_equivalent_class)

        # Maybe there is a special function for encoding these arguments.
        try:
            url_survol = entity_module.MakeUri(*prop_values_array)
        except:
            # Otherwise, general case.
            url_survol = lib_common.gUriGen.UriMake(survol_equivalent_class, *prop_values_array)

        set_survol_urls.add(url_survol)

    # There might potentially be several Survol objects for these several WMI objects.
    # It depends on the properties, as Survol takes only a subset of them.
    # Prefixed by hyphens so that it comes first when sorted.
    prop_wmi_to_survol = lib_common.MakeProp("--Survol equivalent object")
    for url_survol in set_survol_urls:
        grph.add((wmi_instance_node, prop_wmi_to_survol, url_survol))
    return


# TESTS:
# OK
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name="machine-hp"')
# _wmi_object: \\MACHINE-HP\root\CIMV2:Win32_ComputerSystem.Name="machine-hp">
# KAPUTT
# wmi.WMI(moniker='\\machine-HP\root\CIMV2:CIM_ComputerSystem.Name="machine-hp"')
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name=machine-hp')
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name="127.0.0.1"')


# All instances that are associated with a particular source instance.
def DisplayObjectAssociators(grph, wmi_instance_node, obj_wmi, cgiMoniker):
    DEBUG("DisplayObjectAssociators\n")
    # It is possible to restrict the associators to a specific class only.
    for an_assoc in obj_wmi.associators():
        # assoc_moniker=\\RCHATEAU-HP\root\cimv2:Win32_ComputerSystem.Name="RCHATEAU-HP"
        assoc_moniker = str(an_assoc.path())
        DEBUG("DisplayObjectAssociators an_assoc Moniker=%s",assoc_moniker)

        # derivation=(u'CIM_UnitaryComputerSystem', u'CIM_ComputerSystem', u'CIM_System',
        # u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
        assoc_derivation = an_assoc.derivation()

        DEBUG("DisplayObjectAssociators an_assoc derivation=%s", str(assoc_derivation))
        # sys.stderr.write("DisplayObjectAssociators an_assoc=%s\n"%str(dir(an_assoc)))

        # TODO: Consider these methods: associated_classes, associators, derivation,
        # id, keys, methods, ole_object, path, properties, property_map, put,
        # qualifiers, references, set, wmi_property

        # BEWARE: For example for CIM_ComputerSystem, the host name must be in lowercase.
        # TODO: This is not done here. Luckily the universal alias does this properly.
        assoc_instance_url = lib_util.EntityUrlFromMoniker(assoc_moniker)
        assoc_instance_node = lib_common.NodeUrl(assoc_instance_url)
        grph.add((wmi_instance_node, lib_common.MakeProp(assoc_derivation[0]), assoc_instance_node))




# WmiExplorer displays the namespace as: "ROOT\CIMV2"
#
# The namespace is converted to lowercase, no idea why.
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa389766%28v=vs.85%29.aspx
# The __Namespace system class has a single property called Name,
# which must be unique within the scope of the parent namespace.
# The Name property must also contain a string that begins with a letter.
# All other characters in the string can be letters, digits, or underscores.
# All characters are case-insensitive.
# refMoniker='\\RCHATEAU-HP\root\cimv2:CIM_DataFile.Name="c:\\windows\\system32\\sspicli.dll"'
# cgiMoniker='\\RCHATEAU-HP\root\CIMV2:CIM_DataFile.Name="c:\\windows\\system32\\sspicli.dll"'
#
# '\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="RCHATEAU-HP",Name="Administrator"'
# '\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="Administrator"'
#
def EqualMonikers(monik_a, monik_b):
    split_a = monik_a.split(':')
    split_b = monik_b.split(':')

    # Maybe we could simply make a case-insensitive string comparison.
    return split_a[0].upper() == split_b[0].upper() and split_a[1:].upper() == split_b[1:].upper()


# The references() retrieves all association instances that refer to a particular source instance.
# It is similar to the associators()statement.
# However, rather than retrieving endpoint instances, it retrieves the intervening association instances.
# Dont do this on a Win32_ComputerSystem object and several other classes; it is VERY SLOW !
# TODO: Test with a small data set.
def DispWmiReferences(grph, wmi_instance_node, obj_wmi, cgi_moniker):
    for obj_ref in obj_wmi.references():
        literal_key_value = dict()
        ref_instance_node = None
        for key_prp in obj_ref.properties:
            val_prp = getattr(obj_ref, key_prp)
            try:
                # references() have one leg pointing to the current object,
                ref_moniker = str(val_prp.path())

                # Maybe it would be better to compare the objects ???
                if not EqualMonikers(ref_moniker, cgi_moniker):
                    # TODO: Disabled for the moment because we do not understand the logic.
                    if False and ref_instance_node is not None:
                        # Inconsistency:\\RCHATEAU-HP\root\cimv2:Win32_LogonSession.LogonId="195361"
                        # != \\192.168.1.83\root\CIMV2:CIM_Process.Handle=7120
                        lib_common.ErrorMessageHtml("Inconsistency:" + ref_moniker + " != " + cgi_moniker)
                    ref_instance_url = lib_util.EntityUrlFromMoniker(ref_moniker)
                    ref_instance_node = lib_common.NodeUrl(ref_instance_url)
                    grph.add((wmi_instance_node, lib_common.MakeProp(key_prp), ref_instance_node))
            except AttributeError:
                # Then it is a literal attribute.
                # TODO: Maybe we could test if the type is an instance.
                # Beware: UnicodeEncodeError: 'ascii' codec can't encode character u'\\u2013'
                try:
                    literal_key_value[key_prp] = str(val_prp)
                except UnicodeEncodeError:
                    literal_key_value[key_prp] = "UnicodeEncodeError"


        # Now the literal properties are attached to the other node.
        if ref_instance_node != None:
            for key_litt in literal_key_value:
                grph.add((
                    ref_instance_node,
                    lib_common.MakeProp(key_litt),
                    lib_common.NodeLiteral(literal_key_value[key_litt])))


def Main():
    paramkey_display_none = "Display none values"
    paramkey_display_associators = "Display Associators"
    cgiEnv = lib_common.CgiEnv(can_process_remote=True,
                               parameters = {paramkey_display_none: False, paramkey_display_associators: False})

    display_none_values = bool(cgiEnv.get_parameters(paramkey_display_none))
    display_associators = bool(cgiEnv.get_parameters(paramkey_display_associators))

    name_space, class_name = cgiEnv.get_namespace_type()
    # If name_space is not provided, it is set to "root/CIMV2" by default.
    if not class_name:
        lib_common.ErrorMessageHtml("Class name should not be empty")

    wmi_host = cgiEnv.GetHost()

    # wmi_host=RCHATEAU-HP ns=root\cimv2 cls=Win32_ComputerSystem id=Name="RCHATEAU-HP"
    DEBUG("wmi_host=%s ns=%s cls=%s id=%s", wmi_host, name_space, class_name, cgiEnv.m_entity_id)

    grph = cgiEnv.GetGraph()

    try:
        conn_wmi = lib_wmi.WmiConnect(wmi_host, name_space)
    except Exception as exc:
        lib_common.ErrorMessageHtml("entity_wmi.py: Cannot connect to WMI server %s with namespace %s: %s"
                                    % (wmi_host,name_space, str(exc)))

    # Try to read the moniker, which is much faster, but it does not always work if we do not have all the properties.
    cgi_moniker = cgiEnv.get_parameters("xid")
    DEBUG("entity_wmi.py cgi_moniker=[%s]", cgi_moniker)

    obj_list = WmiReadWithMoniker(cgiEnv, cgi_moniker)
    if obj_list is None:
        # If no object associated with the moniker, then tries a WQL query which might return several objects.
        # BEWARE: This is slow and less efficient than using WMI filters.
        obj_list = WmiReadWithQuery(cgiEnv, conn_wmi, class_name)

    wmi_instance_url = lib_util.EntityUrlFromMoniker(cgi_moniker)

    # Possible problem because this associates a single URL with possibly several objects ??
    wmi_instance_node = lib_common.NodeUrl(wmi_instance_url)

    # In principle, there should be only one object to display.
    # TODO: If several instances, the instance node must be recreated.
    for obj_wmi in obj_list:
        DEBUG("entity_wmi.py obj_wmi=[%s]", str(obj_wmi) )

        DispWmiProperties(grph, conn_wmi, wmi_instance_node, obj_wmi, display_none_values, class_name)

        # Displaying these classes is very slow, several minutes for 100 elements.
        # It would be better to have another link.
        if not lib_wmi.WmiTooManyInstances(class_name):
            try:
                DispWmiReferences(grph,wmi_instance_node, obj_wmi, cgi_moniker)
            except Exception as exc:
                WARNING("entity_wmi.py Exception=%s", str(exc) )
        else:
            # Prefix with a dot so it is displayed first.
            grph.add((wmi_instance_node, lib_common.MakeProp(".REFERENCES"), lib_common.NodeLiteral("DISABLED")))

        # Displaying the associators is conditional because it slows things.
        # TODO: How to select this option with D3 ?????
        if display_associators:
            # This class appears everywhere, so not not display its references, it would be too long.
            if class_name == "Win32_ComputerSystem":
                grph.add((wmi_instance_node, lib_common.MakeProp(".ASSOCIATORS"), lib_common.NodeLiteral("DISABLED")))
            else:
                DisplayObjectAssociators(grph, wmi_instance_node, obj_wmi, cgi_moniker)

    # Adds the class node to the instance.
    wmi_class_node = lib_wmi.WmiAddClassNode(
        grph,
        conn_wmi,
        wmi_instance_node,
        wmi_host,
        name_space,
        class_name,
        lib_common.MakeProp(class_name))

    # Now displays the base class, up to the top.
    lib_wmi.WmiAddBaseClasses(grph, conn_wmi, wmi_class_node, wmi_host, name_space, class_name)

    # Now tries to find the equivalent object in the Survol terminology.
    AddSurvolObjectFromWmi(grph, wmi_instance_node, conn_wmi, class_name, obj_list)

    # BEWARE: Mustbe done for all classes
    cgiEnv.OutCgiRdf("LAYOUT_TWOPI",
                     [lib_common.MakeProp('PartComponent'),
                      lib_common.MakeProp('Element'),
                      lib_common.MakeProp('Antecedent')])

# TODO: Must add a link to our URL, entity.py etc...

if __name__ == '__main__':
    Main()
