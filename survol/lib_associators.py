import logging

import lib_uris
import lib_properties
import lib_ontology_tools

# This does not take into account WBEM running on Windows, or WMI on Linux, because this is not realistic.
try:
    import lib_wmi
except ImportError:
    lib_wmi = None


def add_associated_instances(grph, root_node, entity_type, entity_id, associator_attribute):
    logging.info("This is implemented for WMI only, yet.")
    logging.debug("entity_type=%s entity_id=%s associator_attribute=%s", entity_type, entity_id, associator_attribute)
    result_class, result_role = lib_ontology_tools.get_associated_attribute(
        "wmi", lib_wmi.extract_specific_ontology_wmi, associator_attribute)

    associator_name, _, input_role = associator_attribute.partition(".")
    if not input_role:
        raise Exception("associator_attribute %s is invalid" % associator_attribute)

    # This path will eventually be reformatted for WMI needs.
    wmi_path = entity_type + "." + entity_id

    iter_objects = lib_wmi.WmiSparqlExecutor().enumerate_associated_instances(
        wmi_path, associator_name, result_class, result_role)

    for associated_dict_key_values in iter_objects:
        script_node = lib_uris.LocalBox().UriMakeFromDict(result_class, associated_dict_key_values)
        property_node = lib_properties.MakeProp(result_role)
        grph((root_node, property_node, script_node))
