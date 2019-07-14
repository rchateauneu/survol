import sys
import lib_util
import lib_common
import lib_kbase
import lib_client
import lib_properties

##################################################################################


# This returns an iterator on objects of the input class.
# These objects must match the input key-value pairs,
# returned by calling the optional class-specific SelectFromWhere() method.
# Each object is modelled by a key-value dictionary.
# No need to return the class name because it is an input parameter.
def SurvolCallbackSelect(grph, class_name, predicate_prefix, filtered_where_key_values):
    WARNING("SurvolCallbackSelect class_name=%s predicate_prefix=%s where_key_values=%s",
            class_name, predicate_prefix, str(filtered_where_key_values))

    # Maybe there is a script: predicate_prefix="survol:CIM_DataFile/mapping_processes"
    prefix, colon, script_nickname = predicate_prefix.partition(":")
    WARNING("SurvolCallbackSelect script_nickname=%s", script_nickname)

    if script_nickname:
        # For example: script_nickname="CIM_DataFile/mapping_processes"
        # Wildcards or directories are not accepted yet.
        script_name = "sources_types/" + script_nickname + ".py"
        WARNING("SurvolCallbackSelect script_name=%s filtered_where_key_values=%s",
                script_name,
                str(filtered_where_key_values))

        # TODO: Check that there are enough parameters for this script ?

        my_source = lib_client.SourceLocal(script_name, class_name, **filtered_where_key_values)
        WARNING("SurvolCallbackSelect my_source=%s", my_source)
        my_triplestore = my_source.GetTriplestore()

        my_triplestore.CopyToGraph(grph)

        list_instances = my_triplestore.GetInstances()

        # TODO: We filter only the objects of the right type,
        # TODO: ... but we lose all the other objects which could be stored in the output triplestore !!...

        WARNING("SurvolCallbackSelect list_instances=%s", str(list_instances))
        for one_instance in list_instances:
            if one_instance.__class__.__name__ == class_name:
                # 'CIM_DataFile.Name=/usr/lib/systemd/systemd-journald'
                instance_url = one_instance.__class__.__name__ + "." + one_instance.m_entity_id

                one_instance.m_key_value_pairs[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral(predicate_prefix)
                # Add it again, so the original Sparql query will work.
                one_instance.m_key_value_pairs[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral(predicate_prefix)
                yield (instance_url, one_instance.m_key_value_pairs)

    else:
        entity_module = lib_util.GetEntityModule(class_name)
        if not entity_module:
            raise Exception("SurvolCallbackSelect: No module for class:%s"%class_name)

        try:
            enumerate_function = entity_module.SelectFromWhere
        except AttributeError:
            exc = sys.exc_info()[1]
            WARNING("No Enumerate for %s:%s", class_name, str(exc) )
            return

        iter_enumeration = enumerate_function( filtered_where_key_values )
        # for one_key_value_dict in iter_enumeration:
        for one_key_value_dict_nodes in iter_enumeration:
            class_ontology = lib_util.OntologyClassKeys(class_name)
            ontology_key_values = {}
            for key_node, value_node in one_key_value_dict_nodes.items():
                key_str = lib_properties.PropToQName(key_node)
                if key_str in class_ontology:
                    ontology_key_values[key_str] = str(value_node)

            # This reorders the attributes if needed.
            key_value_path = lib_util.KWArgsToEntityId(class_name, **ontology_key_values)

            # key_value_path = ".".join( '%s="%s"' % ( lib_properties.PropToQName(key), str(value) ) for key, value in one_key_value_dict_nodes.items() )
            object_path = "SurvolLocalHost:" + class_name + "." + key_value_path

            one_key_value_dict_nodes[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral(predicate_prefix)
            # Add it again, so the original Sparql query will work.
            one_key_value_dict_nodes[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral(predicate_prefix)

            yield ( object_path, one_key_value_dict_nodes )


def SurvolCallbackAssociator(
    grph,
    result_class_name,
    predicate_prefix,
    associator_key_name,
    subject_path):
    ERROR("SurvolCallbackAssociators Not implemented yet")
    return []

