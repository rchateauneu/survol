import logging

import lib_uris
import lib_util
import lib_properties
import lib_ontology_tools

# This does not take into account WBEM running on Windows, or WMI on Linux, because this is not realistic.
try:
    import lib_wmi
except ImportError:
    lib_wmi = None


def add_associated_instances(grph, root_node, entity_type, entity_id, associator_attribute):
    assert root_node.find("__associator_attribute__") < 0
    logging.debug("This is implemented for WMI only, yet.")
    logging.debug("entity_type=%s entity_id=%s associator_attribute=%s", entity_type, entity_id, associator_attribute)
    #result_class, result_role = lib_ontology_tools.get_associated_attribute(
    #    "wmi", lib_wmi.extract_specific_ontology_wmi, associator_attribute)

    result_class, result_role = lib_ontology_tools.get_associated_class_role(
        "wmi", lib_wmi.extract_specific_ontology_wmi, associator_attribute)


    associator_name, _, input_role = associator_attribute.partition(".")
    if not input_role:
        raise Exception("associator_attribute %s is invalid" % associator_attribute)

    # This path will eventually be reformatted for WMI needs.
    wmi_path = entity_type + "." + entity_id

    iter_objects = lib_wmi.WmiSparqlExecutor().enumerate_associated_instances(
        wmi_path, associator_name, result_class, result_role)

    # WMI returns the attributes of each associated instances, only for the keys.
    # However, it is needed to iterated on the key-value pairs to trnsform them into strings.
    # So, an extra check is done, to be sure that the simplified ontology of survol
    # (List of keys per class) matches WMI class definition. Survol ontology of classes is much simpler
    # and is just the list of keys, but must be the same as WMI class description.
    result_class_keys = lib_util.OntologyClassKeys(result_class)

    for associated_dict_key_values in iter_objects:
        #logging.debug("associated_dict_key_values=%s", associated_dict_key_values)

        # This key-values dictionary contains all the attributes of each associated instance,
        # at least for the keys
        converted_key_value_dict = {}
        for property_key_node, property_value_node in associated_dict_key_values.items():
            property_key_name = lib_properties.PropToQName(property_key_node)
            property_value = str(property_value_node)
            if property_key_name in result_class_keys:
                converted_key_value_dict[property_key_name] = property_value
                logging.debug("    key=%s value=%s", property_key_name, property_value)
            else:
                logging.debug("Class %s, key %s is not in the ontology", result_class, property_key_name)

        script_node = lib_uris.LocalBox().UriMakeFromDict(result_class, converted_key_value_dict)
        property_node = lib_properties.MakeProp(result_role)
        logging.debug("script_node=%s", script_node)
        grph.add((root_node, property_node, script_node))
