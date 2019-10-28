import sys
import lib_util
import lib_common
import lib_kbase
import lib_client
import lib_properties

##################################################################################
# This is the implementation of the callback object for the Survol ontology.
# This callback interface
# It is less generic than WBEM and WMI because it cannot implement
# select queries and associators in the general case.
# However, it is much faster.

class SurvolSparqlCallbackApi:

    # This returns an iterator on objects of the input class.
    # These objects must match the input key-value pairs,
    # returned by calling the optional class-specific SelectFromWhere() method.
    # Each object is modelled by a key-value dictionary.
    # No need to return the class name because it is an input parameter.
    def CallbackSelect(self, grph, class_name, predicate_prefix, filtered_where_key_values):
        DEBUG("SurvolCallbackSelect class_name=%s predicate_prefix=%s where_key_values=%s",
                class_name, predicate_prefix, str(filtered_where_key_values))

        # Maybe there is a script: predicate_prefix="survol:CIM_DataFile/mapping_processes"
        prefix, colon, script_nickname = predicate_prefix.partition(":")
        DEBUG("SurvolCallbackSelect script_nickname=%s", script_nickname)

        if script_nickname:
            # For example: script_nickname="CIM_DataFile/mapping_processes"
            # Wildcards or directories are not accepted yet.
            script_name = "sources_types/" + script_nickname + ".py"
            DEBUG("SurvolCallbackSelect script_name=%s filtered_where_key_values=%s",
                    script_name,
                    str(filtered_where_key_values))

            # TODO: Check that there are enough parameters for this script ?

            my_source = lib_client.SourceLocal(script_name, class_name, **filtered_where_key_values)
            DEBUG("SurvolCallbackSelect my_source=%s", my_source)
            my_triplestore = my_source.GetTriplestore()

            # This is returned anyway, as a triplestore that rdflib Sparql can work on.
            my_triplestore.CopyToGraph(grph)

            list_instances = my_triplestore.GetInstances()

            # TODO: We filter only the objects of the right type,
            # TODO: ... but we lose all the other objects which could be stored in the output triplestore !!...

            DEBUG("SurvolCallbackSelect tp=%s class_name=%s", type(list_instances), class_name)
            DEBUG("SurvolCallbackSelect list_instances=%s", str(list_instances))
            for one_instance in list_instances:
                WARNING("SurvolCallbackSelect one_instance.__class__.__name__=%s", one_instance.__class__.__name__)
                if one_instance.__class__.__name__ == class_name:
                    # 'CIM_DataFile.Name=/usr/lib/systemd/systemd-journald'
                    instance_url = one_instance.__class__.__name__ + "." + one_instance.m_entity_id

                    one_instance.m_key_value_pairs[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral(predicate_prefix)
                    # Add it again, so the original Sparql query will work.
                    one_instance.m_key_value_pairs[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral(predicate_prefix)
                    DEBUG("SurvolCallbackSelect instance_url=%s", instance_url)
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


    # Typical input:
    #   result_class_name=CIM_Process
    #   predicate_prefix=survol
    #   associator_key_name=ppid
    #   subject_path=SurvolLocalHost:CIM_Process.Handle=29352
    # This executes "entity.py?xid=" then filters the RDF output for this attribute
    # and for an pbject of the given result class.
    # The script is executed locally.
    def CallbackAssociator(
        self,
        grph,
        result_class_name,
        predicate_prefix,
        associator_key_name,
        subject_path):

        DEBUG("SurvolCallbackAssociator result_class_name=%s "
            + "predicate_prefix=%s associator_key_name=%s subject_path=%s.",
              result_class_name,
              predicate_prefix,
              associator_key_name,
              subject_path)

        # This is the only example we have for the moment.
        # This constraint will probably be relaxed later.
        #assert( prefix_host == "SurvolLocalHost")

        # subject_path=CIM_Process.Handle=2092
        class_name, dot, entity_id = subject_path.partition(".")

        cim_object = lib_client.EntityIdToInstance(None, class_name, entity_id)


        # This should be a local script.
        list_sources = cim_object.GetScripts()

        for my_source in list_sources:
            if my_source.IsVerySlow():
                continue
            try:
                my_triplestore = my_source.GetTriplestore()
            except Exception as ex:
                # We have no idea about the script, because we run every possible script,
                # so it is not an issue it it fails.
                WARNING("Script:%s Exception:%s",str(my_source),ex)
                continue

            # mysource="Script:sources_types/CIM_Process/xyz.py?xid=CIM_Process.Handle=7652"
            # TODO: Add the script as "IsDefinedBy"

            # This is returned anyway, as a triplestore that rdflib Sparql can work on.
            # TODO: This should be done in one loop instead of THREE !!!!!!!
            my_triplestore.CopyToGraph(grph)
            iter_objects = my_triplestore.FilterObjectsWithPredicateClass(associator_key_name, result_class_name)

            for object_path, one_key_value_dict_nodes in iter_objects:
                DEBUG("SurvolCallbackAssociator object_path=%s one_key_value_dict_nodes=%s",
                        object_path,
                        one_key_value_dict_nodes)
                yield (object_path, one_key_value_dict_nodes)

    def CallbackTypes(self, grph, see_also, where_key_values):
        raise NotImplementedError("CallbackTypes: Not implemented yet")

    def CallbackTypeTree(self, grph, see_also, associator_subject):
        raise NotImplementedError("CallbackTypeTree: Not implemented yet")

