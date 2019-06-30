import sys
import lib_util
import lib_client
import lib_kbase
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
        script_name = "sources_types/" + script_nickname + ".py"
        WARNING("SurvolCallbackSelect script_name=%s",script_name)

        # Wildcards or directories are not accepted yet.
        list_instances = lib_client.SourceLocal.GetObjectInstancesFromScript(script_name, class_name, **filtered_where_key_values)
        # TODO: We filter only the objects of the right type,
        # TODO: ... but we lose all the other objects which could be stored in the output triplestore !!...

        WARNING("SurvolCallbackSelect list_instances=%s",str(list_instances))
        for one_instance in list_instances:
            if one_instance.__class__.__name__ == class_name:
                # 'CIM_DataFile.Name=/usr/lib/systemd/systemd-journald'
                instance_url = one_instance.__class__.__name__ + "." + one_instance.m_entity_id

                #object_path_node = lib_util.NodeUrl(instance_url)

                # TODO: Add the property "definedBy" to each object.
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
            # one_key_value_dict["rdfs:definedBy"] = class_name + ":" + "SelectFromWhere"
            #yield ( lib_util.NodeUrl("survol_object_path"), one_key_value_dict )

            #lib_util.NodeUrl(val)
            #lib_util.NodeLiteral(val)
            #one_key_value_dict_nodes = {}
            #for key, val in one_key_value_dict.items():
            #    one_key_value_dict_nodes[lib_util.NodeUrl(key)] = lib_util.NodeLiteral(val)
            #one_key_value_dict_nodes[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral(class_name + ":" + "SelectFromWhere")

            # The path must be compatible with WMI associators, e.g. '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="31588"'
            # WARNING("SurvolCallbackSelect one_key_value_dict=%s",one_key_value_dict)

            class_ontology = lib_util.OntologyClassKeys(class_name)
            ontology_key_values = {}
            for key_node, value_node in one_key_value_dict_nodes.items():
                key_str = lib_properties.PropToQName(key_node)
                if key_str in class_ontology:
                    ontology_key_values[key_str] = str(value_node)

            # This reorders the attributes of needed.
            key_value_path = lib_util.KWArgsToEntityId(class_name, **ontology_key_values)

            # key_value_path = ".".join( '%s="%s"' % ( lib_properties.PropToQName(key), str(value) ) for key, value in one_key_value_dict_nodes.items() )
            object_path = "SurvolLocalHost:" + class_name + "." + key_value_path

            yield ( object_path, one_key_value_dict_nodes )


# Quand on a un triplet de cette forme, trouver toutes les proprietes
# litterales relatives au sujet.
# Subj: ('VARIABLE=', 't')
# Pred: ('Predicate', u'rdf:type')
# Obj: ('litt_string', 'CIM_Process')# On peut alors en faire des requetes WMI ou WBEM, eventuellement.
#
# En theorie, c'est toujours possible mais probablement tres lent.
#
# Si on a les bons attributs, on peut executer le script principal dans survol.

def SurvolCallbackAssociator(
    grph,
    result_class_name,
    predicate_prefix,
    associator_key_name,
    subject_path):
    ERROR("SurvolCallbackAssociators Not implemented yet")
    return []

