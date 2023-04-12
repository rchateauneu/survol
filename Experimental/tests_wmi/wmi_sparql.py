import sys
import os
import io
import ast
import time
import itertools
import logging
import urllib

import wmi
import win32com
import pywintypes
import win32com.client

import rdflib
from rdflib import plugins
from rdflib.plugins import sparql

logging.getLogger().setLevel(logging.DEBUG)

debug_mode = True

# http://sawbuck.googlecode.com/svn/trunk/sawbuck/py/etw/generate_descriptor.py
# Generate symbols for the WbemScripting module so that we can have symbols
# for debugging and use constants throughout the file.
# Without this, win32com.client.constants are not available.
win32com.client.gencache.EnsureModule('{565783C6-CB41-11D1-8B02-00600806D9B6}', 0, 1, 1)

# These queries work correctly. Please note how back-slashes are escaped. They are doubled between quotes.
# select * from CIM_DirectoryContainsFile where GroupComponent="Win32_Directory.Name=\"C:\\\\Users\\\\rchat\""
# select * from CIM_DirectoryContainsFile where PartComponent="CIM_DataFile.Name=\"C:\\\\Users\\\\desktop.ini\""
# select * from CIM_DirectoryContainsFile where PartComponent="CIM_DataFile.Name=\"\\\\\\\\LAPTOP-R89KG6V1\\\\root\\\\cimv2:C:\\\\Users\\\\desktop.ini\""


wmi_conn = wmi.WMI()

survol_url_prefix = "http://www.primhillcomputers.com/ontology/survol#"

SURVOLNS = rdflib.Namespace(survol_url_prefix)

property_association_node = rdflib.URIRef(SURVOLNS["is_association"])
property_key_node = rdflib.URIRef(SURVOLNS["is_key"])
property_unit_node = rdflib.URIRef(SURVOLNS["unit"])

VARI = rdflib.term.Variable
LITT = rdflib.term.Literal


def _strip_prefix(rdflib_node):
    """
    Helper function to display a short name of a node defined in a CIM ontology.
    :param rdflib_node: rdlib term.
    :return: A string
    """
    if str(rdflib_node).startswith(survol_url_prefix):
        return rdflib_node[len(survol_url_prefix):]
    return str(rdflib_node)


class _CimPattern:
    """
    This models all properties related to the same subject, when the type of the subject is a CIM class.
    Such an object is created by parsing a sparql query and grouping basic graph patterns with the same subject.
    """

    def __init__(self, part_subject, class_short, properties_dict=dict()):
        assert isinstance(part_subject, VARI)
        assert isinstance(class_short, str)
        assert isinstance(properties_dict, dict)
        self.m_subject = part_subject
        self.m_class = class_short
        self.m_properties = properties_dict.copy()

    def __str__(self):
        "This is needed only for testing and displaying results."
        return "%s %s {%s}" % (
            str(self.m_subject),
            self.m_class,
            ", ".join(
                "%s: %s" % (_strip_prefix(key), _strip_prefix(value)) for key, value in self.m_properties.items()))

    def __lt__(self, other):
        """
        Needed for comparing a list of objects with expected results.
        """
        if str(self.m_subject) < str(other.m_subject):
            return True
        elif str(self.m_subject) > str(other.m_subject):
            return False
        if str(self.m_class) < str(other.m_class):
            return True
        elif str(self.m_class) > str(other.m_class):
            return False
        if str(self.m_properties) < str(other.m_properties):
            return True
        return False

    def __eq__(self, other):
        # Properties are converted to strings because of values.
        # Do not worry about performance because this is used for tests only.
        return str(self.m_subject) == str(other.m_subject) \
            and self.m_class == other.m_class \
            and str(sorted(self.m_properties)) == str(sorted(other.m_properties))

    def variable_properties(self):
        """
        This returns a set of the property names whose value is a vatiable.
        :return: A set of strings.
        """
        return set(key for key, value in self.m_properties.items() if isinstance(value, VARI))


def _query_header(sparql_query):
    """
    Returns the variable names of an sparql query given as input.

    :param sparql_query:
    :return: List of the names of the variables returned by a sparql query.
    """
    try:
        parsed_query = rdflib.plugins.sparql.parser.parseQuery(sparql_query)
    except:
        print("Error parsing query:", sparql_query)
        raise

    list_vars = parsed_query[1]['projection']
    list_names = [str(one_var['var']) for one_var in list_vars]
    return list_names


def _part_triples_to_instances_list(part_triples):
    """
    This takes as input the basic graph pattern (BGP) of a sparql query, which is the list of triples patterns
    extracted from this query.
    It returns a list of instances of CIM classes, each of them containing the triples using its instances.
    The association is done based on the variable representing the instance.
    There might be several instances of the same class.

    Basically, this groups triple patterns with the same subject.
    This requires that the class of instances is known.
    This is a reasonable requirement because CIM queries have to work on concrete objects:
    A file cannot be a process or a socket etc...
    """
    instances_dict = dict()
    logging.debug("len(triples)=%d" % len(part_triples))
    for part_subject, part_predicate, part_object in part_triples:
        logging.debug("    spo=%s %s %s" % (part_subject, part_predicate, part_object))
        if part_predicate == rdflib.namespace.RDF.type:
            if isinstance(part_subject, rdflib.term.Variable):
                class_as_str = str(part_object)
                if class_as_str.startswith(survol_url_prefix):
                    # This is the class name without the Survol prefix which is not useful here.
                    class_short = class_as_str[len(survol_url_prefix):]
                    # object_factory can also tell the difference between an associator and a property
                    instances_dict[part_subject] = _CimPattern(part_subject, class_short)

    if not instances_dict:
        # If it does not contain any instance defined by a type which can be mapped to a WMI class,
        # then this query applies to non-instance content, which can only be the WMI ontology.
        # This ontology should be returned anyway: Classes, properties etc...
        logging.warning("No instance found. Possibly a meta-data query.")
        return instances_dict
        # raise Exception("No instance found")
    logging.debug("Created instances:%s" % instances_dict.keys())

    # Second pass on the BGP: The keys of instances_dict are URL variables whose values must be found.
    for part_subject, part_predicate, part_object in part_triples:
        current_instance = instances_dict.get(part_subject, None)
        if not current_instance:
            # This is not the pattern of a Survol instance, and therefore is not usable here.
            continue
        assert isinstance(current_instance, _CimPattern)

        predicate_as_str = str(part_predicate)
        if predicate_as_str.startswith(survol_url_prefix):
            # This applies only to CIM properties which can be used in a WQL query.
            current_instance.m_properties[_strip_prefix(part_predicate)] = part_object

    return list(instances_dict.values())


class CustomEvalEnvironment:
    """
    This contains utilities for the custom eval function passed to rdflib sparql query execution.
    """

    def __init__(self, test_description, sparql_query, expected_patterns):
        self.m_test_description = test_description
        self.m_sparql_query = sparql_query
        self.m_output_variables = _query_header(self.m_sparql_query)
        self.m_expected_patterns = expected_patterns
        self.m_graph = rdflib.Graph()

        if debug_mode:
            print("Output variables=", self.m_output_variables)

    def _best_snippet(self, function_name, instances_list):
        # The order of objects in the instances list gives the order of enumerations of WMI objects
        # with WQL queries or WQL-like loops.
        # These enumerations should all return the same instances but their performances can be drastically different.
        # This is in test stage now.
        # TODO: Try all possible combinations ?
        # Criterias to find the best ordering.
        # - Do not do a full scan on some classes such as CIM_DataFile : Except if there is a customised implementation.
        # - Associators of CIM_ComputerSystem.
        # - Limit the number of nested loops.

        # The number of permutations if factorial(n), but there should not be many objects, practically.
        # Querying over, for example, five or six different loops is very big in itself.
        # If this happens, for example with singletons, then it is possible to reduce the number of permutations
        # by forcing these singletons to be at the beginning of the list of instances,
        # then do permutations on the rest.
        # This is the same concept as sorting the list of instances by their number.
        # It is impossible to have the number of elements of each WMI class, but it is possible to have a magnitude,
        # such as {"CIM_ComputerSystem": 1, "CIM_Process": 100, "CIM_DataFile": 1000000}
        # For the moment, all iterations are done, for testing purpose.

        all_snippets = []
        for one_permutation in itertools.permutations(instances_list):
            code_description, result_as_str = objects_list_to_python_code(
                self.m_output_variables, one_permutation, function_name)
            all_snippets.append((code_description, result_as_str))

        best_snippet_index = 0
        for snippet_index in range(1, len(all_snippets)):
            if all_snippets[best_snippet_index][0]["total_cost"] > all_snippets[snippet_index][0]["total_cost"]:
                best_snippet_index = snippet_index

        print("best query:", self.m_test_description, all_snippets[best_snippet_index][0])
        best_generated_python_code = all_snippets[best_snippet_index][1]
        assert best_generated_python_code
        # This works but it can be very slow.
        # TODO: Execute only if not too slow.
        # TODO: Execute in a sub-process.
        # Create performance statistics which are later used to choose the best enumeration.
        print("Best code snippet:")
        print(best_generated_python_code)
        return best_generated_python_code

    def _insert_wmi_results_in_graph(self, ctx_graph, instances_list, eval_results):
        # These results are now used to generate triples inserted in the triplestore.
        # This triplestore is later used to run the Sparql query.
        counter = 0
        length_before = len(ctx_graph)
        for one_result_dict in eval_results:
            # FIXME: This is temporary logging.
            if counter % 100 == 0:
                print("one_result_dict=", ",".join(["%s=>%s" % one_result for one_result in one_result_dict.items()]))
            counter += 1
            # FIXME: Finish earlier to ease profiling.
            if counter == 1000000:
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                print("FINITO @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                break

            def _evaluate_value_to_node(property_value):
                """
                This is used to build a node which os added as-is in a graph.
                :param property_value: Property of an object.
                :return: A rdflib term
                """
                if isinstance(property_value, VARI):
                    eval_val = one_result_dict[str(property_value)]

                    # Maybe these are not litteral data, but objects like CIM_Process, Win32_Directory etc...
                    if isinstance(eval_val, PseudoWmiObject):
                        # This is a node which was created by a specialised generator in _specialised_generators_dict.
                        as_node = _wmi_moniker_to_rdf_node(eval_val.m_wmi_moniker.upper())
                    elif isinstance(eval_val, wmi._wmi_object):
                        # This is a WMI object, its WMI moniker is available.
                        as_node = _wmi_moniker_to_rdf_node(str(eval_val.path()).upper())
                    else:
                        assert isinstance(eval_val, (bool, int, float, str))
                        as_node = LITT(eval_val)
                else:
                    assert isinstance(property_value, (bool, int, float, str))
                    as_node = LITT(property_value)
                assert isinstance(as_node, (rdflib.term.URIRef, LITT)), "as_node=%s type=%s should be a node" \
                                                                        "" % (as_node, type(as_node))
                return as_node

            def _pattern_instance_to_moniker(the_pattern_instance):
                if isinstance(the_pattern_instance, PseudoWmiObject):
                    # This is a node which was created by a specialised generator in _specialised_generators_dict.
                    the_moniker = the_pattern_instance.m_wmi_moniker.upper()
                    assert isinstance(the_moniker, str)
                elif isinstance(the_pattern_instance, wmi._wmi_object):
                    # This is a WMI object, its WMI moniker is available.
                    the_moniker = str(the_pattern_instance.path()).upper()
                    assert isinstance(the_moniker, str)
                elif issubclass(the_pattern_instance.__class__, win32com.client.DispatchBaseClass):
                    # Class= <class 'win32com.gen_py.565783C6-CB41-11D1-8B02-00600806D9B6x0x1x2.ISWbemObject'>
                    # Base classes= (<class 'win32com.client.DispatchBaseClass'>,)
                    the_moniker = str(the_pattern_instance.Path_).upper()
                    #print("Moniker from win32com.client.DispatchBaseClass:", the_moniker)
                    assert isinstance(the_moniker, str), "Moniker is %s" % type(the_moniker)
                else:
                    raise Exception("Type %s has no moniker" % type(the_pattern_instance))

                assert isinstance(the_moniker, str)
                return the_moniker

            def _evaluate_value_to_moniker(property_value):
                """
                This is used to build another moniker.
                :param property_value: Property of an object.
                :return: A string
                """
                if isinstance(property_value, VARI):
                    eval_val = one_result_dict[str(property_value)]

                    if isinstance(eval_val, (bool, int, float, str)):
                        as_str = str(eval_val)
                    else:
                        as_str = _pattern_instance_to_moniker(eval_val)
                else:
                    assert isinstance(property_value, (bool, int, float, str))
                    as_str = property_value
                assert isinstance(as_str, str), "as_str=%s type=%s should be a str" % (as_str, type(as_str))
                return as_str

            for one_instance in instances_list:
                assert isinstance(one_instance, _CimPattern)

                # Some values might be nodes. Their monikers is needed to build monikers of associations.
                #evaluated_key_values_to_monikers = {
                #    property_key: _evaluate_value_to_moniker(property_value)
                #    for property_key, property_value in one_instance.m_properties.items()
                #}

                assert isinstance(one_instance.m_class, str)

                assert str(one_instance.m_subject) in one_result_dict, "%s not in %s" % (one_instance.m_subject, str(one_result_dict))
                # win32com.gen_py.Microsoft WMI Scripting V1.2 Library.ISWbemObject
                # Class= <class 'win32com.gen_py.565783C6-CB41-11D1-8B02-00600806D9B6x0x1x2.ISWbemObject'>
                # Base classes= (<class 'win32com.client.DispatchBaseClass'>,)
                the_instance = one_result_dict[str(one_instance.m_subject)]
                assert isinstance(the_instance, (PseudoWmiObject, wmi._wmi_object)) or issubclass(the_instance.__class__, win32com.client.DispatchBaseClass), "Wrong type for %s:%s" % (one_instance.m_subject, the_instance)

                alt_moniker = _pattern_instance_to_moniker(the_instance)
                #rebuilt_moniker = _create_wmi_moniker(one_instance.m_class, **evaluated_key_values_to_monikers)

                #if rebuilt_moniker:
                #    assert isinstance(rebuilt_moniker, str)
                assert isinstance(alt_moniker, str)

                #if rebuilt_moniker and alt_moniker != rebuilt_moniker:
                #    print("DIFFERENT:     alt_moniker=", alt_moniker)
                #    print("         : rebuilt_moniker=", rebuilt_moniker)

                # CA EVITE DE RECREER LE MONIKER.
                new_object_node = _wmi_moniker_to_rdf_node(alt_moniker)

                if not new_object_node:
                    # Keys are not available to create the moniker and hence the node of this object.
                    print("WARNING: No keys to build an object for CimPattern=", one_instance)
                    continue

                class_node = rdflib.URIRef(SURVOLNS[one_instance.m_class])
                ctx_graph.add((new_object_node, rdflib.namespace.RDF.type, class_node))

                for property_key, property_value in one_instance.m_properties.items():
                    assert isinstance(property_key, str)
                    value_node = _evaluate_value_to_node(property_value)
                    property_node = rdflib.URIRef(SURVOLNS[property_key])
                    assert isinstance(new_object_node, rdflib.term.URIRef)
                    assert isinstance(property_node, rdflib.term.URIRef)
                    ctx_graph.add((new_object_node, property_node, value_node))
        length_after = len(ctx_graph)
        print("length_before=", length_before, "length_after=", length_after)

        """
        Verifier si toutes les variables sont la, y compris les variables intermediaires,
        et pas seulement les variables selectionnees par la query sparql.

        Ca serait peut-etre plus rapide si on reordonnait avec une liste par variable.
        Ensuite, on boucle en premier lieu sur les triples.    
        Autrement dit, les snippets, au lieu de faire yield, vont remplir une liste par variable.
        Mais ca complique le parallelisme. Sauf si on agrege plusieurs listes a la fin.
        On pourrait aussi avoir des arbres pour eviter la redondance des variables sur lesquelles on boucle.
        Mais ca aussi gene le parallelisme et force a stocker explictement.
        Ne pas recalculer les class_node et property_node.
        En premier lieu ... PROFILER !
        Ca pourrait aussi appeler une callback.
        Bref: Pour le moment, on fait au plus simple: Ca yield des dictionnaires de key-values.
        """

    def _fetch_wmi_objects_in_graph(self, ctx_graph, instances_list, snippet_name):
        """
        This executes WMI queries on the list of instances.
        It is indirectly called by rdflib custom eval functions when executing a sparql query.

        It must first generate Python code with execution of WQL queries.
        It tries different orders of the list of CIM objects, to find the most efficient one.

        After that, the generated code must be executed and it inserts triples in the context.

        :param ctx:
        :param instances_dict:
        :return: Nothing.
        """

        # Name of the function which is about to be generated.
        # best_generated_python_code = self._best_snippet("my_results_generator", instances_list)
        start_time = time.time()
        best_generated_python_code = self._best_snippet(snippet_name, instances_list)
        optim_time = time.time()
        optim_seconds = optim_time - start_time

        snippet_headers = []

        def log_snippet_details(extra_line):
            if debug_mode:
                snippet_headers.append(extra_line)
                with open(snippet_name + ".py", "w") as snippet_log:
                    for one_line in snippet_headers:
                        snippet_log.write(one_line)
                    snippet_log.write(best_generated_python_code)

        # It is written once in case it would be too slow to finish.
        log_snippet_details("# Optimisation time %f\n" % optim_seconds)

        print("Definition of", snippet_name)
        exec_result = exec(best_generated_python_code, globals())
        assert exec_result is None
        # This is the name of the created Python function which returns variables calculated from WMI
        assert globals()[snippet_name]
        print("Execution of", snippet_name)
        snippet_results = globals()[snippet_name]()

        exec_time = time.time()
        exec_seconds = exec_time - optim_time

        # It is rewritten in case it is too slow to be finished.
        log_snippet_details("# Execution time : %f\n" % exec_seconds)

        self._insert_wmi_results_in_graph(ctx_graph, instances_list, snippet_results)
        # Log file written again for performance testing.
        log_snippet_details("# Graph size : %d\n" % len(ctx_graph))
        insertion_time = time.time()
        insertion_seconds = insertion_time - exec_time
        log_snippet_details("# Insertion time : %f\n" % insertion_seconds)

    def _check_objects_list(self, instances_list):
        # Any order will do for this comparison, as long as it is consistent.
        ordered_actual_instances = sorted(instances_list)
        ordered_expected_instances = sorted(self.m_expected_patterns)
        print("ACTUAL PATTERNS", type(ordered_actual_instances), len(ordered_actual_instances))
        for one_pattern in ordered_actual_instances:
            print("    ", one_pattern)
        print("EXPECTED PATTERNS", type(ordered_expected_instances), len(ordered_expected_instances))
        for one_pattern in ordered_expected_instances:
            print("    ", one_pattern)
        for left, right in zip(ordered_actual_instances, ordered_expected_instances):
            print("left=", left)
            print("right=", right)
            assert left == right
        assert ordered_actual_instances == ordered_expected_instances

    def _custom_eval_bgp(self, ctx_graph, part_triples, snippet_name):
        # Possibly add the ontology to ctx.graph

        logging.debug("Instances:")
        # This extracts the list of object patterns from the BGPs, by grouping them by common subject,
        # if this subject has a CIM class as rdf:type.
        instances_list = _part_triples_to_instances_list(part_triples)
        #print("INSTANCES_LIST A START ========================")
        #for one_pattern in instances_list:
        #    print("    ", one_pattern)
        #print("INSTANCES_LIST A END   ========================")
        if debug_mode:
            self._check_objects_list(instances_list)

        if instances_list:
            self._fetch_wmi_objects_in_graph(ctx_graph, instances_list, snippet_name)
        else:
            logging.warning("No instances. Maybe a meta-data query.")

    def run_query_in_rdflib(self, snippet_name):
        def _wmi_custom_eval_function(ctx, part):
            """
            Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html

            This is a callback given to rdflib sparql evaluation.
            """

            logging.debug("_wmi_custom_eval_function part.name=%s" % part.name)
            # part.name = "SelectQuery", "Project", "BGP"
            # BGP stands for "Basic Graph Pattern", which is a set of triple patterns.
            # A triple pattern is a triple: RDF-term or value, IRI or value, RDF term or value.
            if part.name == 'BGP':
                # part.name = "SelectQuery", "Project", "BGP"
                # BGP stands for "Basic Graph Pattern", which is a set of triple patterns.
                # A triple pattern is a triple: RDF-term or value, IRI or value, RDF term or value.
                self._custom_eval_bgp(ctx.graph, part.triples, snippet_name)

                # Normal execution of the Sparql engine on the graph with many more triples.
                ret_bgp = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
                return ret_bgp

            raise NotImplementedError()

        print("Run query")
        print(self.m_sparql_query)

        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function'] = _wmi_custom_eval_function
        try:
            query_results = self.m_graph.query(self.m_sparql_query)
        except Exception:
            print("Error self.m_sparql_query=", self.m_sparql_query)
            raise
        if 'custom_eval_function' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function']
        query_results_as_list = list(query_results)
        print("run_query_in_rdflib returning %d elements" % len(query_results_as_list))
        return query_results_as_list


#################################################################################################

def _convert_wmi_type_to_xsd_type(predicate_type_name):
    """
    This converts a WMI type name to RDF types.

    WMI types: https://powershell.one/wmi/datatypes
    RDF types: https://rdflib.readthedocs.io/en/stable/rdf_terms.html
    """
    wmi_type_to_xsd = {
        'string': rdflib.namespace.XSD.string,
        'boolean': rdflib.namespace.XSD.boolean,
        'datetime': rdflib.namespace.XSD.dateTime,
        'sint64': rdflib.namespace.XSD.integer,
        'sint32': rdflib.namespace.XSD.integer,
        'sint16': rdflib.namespace.XSD.integer,
        'sint8': rdflib.namespace.XSD.integer,
        'uint64': rdflib.namespace.XSD.integer,
        'uint32': rdflib.namespace.XSD.integer,
        'uint16': rdflib.namespace.XSD.integer,
        'uint8': rdflib.namespace.XSD.integer,
        'real64': rdflib.namespace.XSD.double,
        'real32': rdflib.namespace.XSD.double,
    }
    try:
        return wmi_type_to_xsd[predicate_type_name.lower()]
    except KeyError:
        return None


# L'objectif est de remplir le graph avec l'ontologie mais aussi de sortir les clefs
# dont on a besoin pour trouver la meilleure query.
# Est-ce que la meme property peut etre clef dans une classe et pas dans une autre ?
# Le modele ne matche pas: Les proprietes dans WMI sont dependantes d'une classe.
"""
class_node rdflib.namespace.RDF.type rdflib.namespace.RDFS.Class
class_node rdflib.namespace.RDFS.label "MyClasse"
class_node rdflib.namespace.RDFS.comment "MyClasse is a classe"
class_node cim.is_associator true

property_node rdflib.namespace.RDF.type rdflib.namespace.RDF.Property
property_node rdflib.namespace.RDFS.domain class_node
property_node rdflib.namespace.RDFS.range [ rdflib.namespace.XSD.string, .integer, .boolean, .double, .dateTime ]
property_node rdflib.namespace.RDFS.label "MyClasse.MyProp"
property_node rdflib.namespace.RDFS.comment "MyProp belongs to MyClass"
class_node cim.is_key true
class_node cim.unit "meter"
"""


def _convert_ontology_to_rdf(wmi_conn, rdf_graph):
    """
    This creates a RDF graph containing the WMI ontology.
    """

    # Build dict of WMI objects for each class.
    wmi_class_objects = dict()
    for class_name in wmi_conn.classes:
        wmi_class_obj = getattr(wmi_conn, class_name)
        if class_name in wmi_class_objects:
            # Maybe it is already done because of derivation.
            continue
        class_base_classes = wmi_class_obj.derivation()
        try:
            base_class = class_base_classes[0]
        except IndexError:
            base_class = ""

        # wbemFlagUseAmendedQualifiers WMI to return class amendment data along with the base class definition.
        try:
            subclasses = wmi_conn.SubclassesOf(base_class, win32com.client.constants.wbemFlagUseAmendedQualifiers)
            for subclass_obj in subclasses:
                if subclass_obj.Path_.Class not in wmi_class_objects:
                    wmi_class_objects[subclass_obj.Path_.Class] = subclass_obj
        except pywintypes.com_error:
            if class_name not in wmi_class_objects:
                # If the current class could not be found, insert what we can.
                wmi_class_objects[class_name] = wmi_class_obj

    for class_name, wmi_class_obj in wmi_class_objects.items():
        # print("class_name=", class_name)
        class_node = rdflib.URIRef(SURVOLNS[class_name])
        rdf_graph.add((class_node, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
        rdf_graph.add((class_node, rdflib.namespace.RDFS.label, rdflib.Literal(class_name)))

        try:
            class_description = str(wmi_class_obj.Qualifiers_("Description"))
            rdf_graph.add((class_node, rdflib.namespace.RDFS.comment, rdflib.Literal(class_description)))
        except:
            pass

        try:
            is_association = wmi_class_obj.Qualifiers_('Association')
            if is_association:
                print("association class_name=%s is_association=%s" % (class_name, is_association))
                rdf_graph.add((class_node, property_association_node, rdflib.Literal(is_association)))
        except:
            pass

        for wmi_property_obj in wmi_class_obj.Properties_:
            property_name = wmi_property_obj.Name
            # print("    property_name=", property_name)
            full_property_name = "%s.%s" % (class_name, property_name)
            property_node = rdflib.URIRef(SURVOLNS[full_property_name])

            rdf_graph.add((property_node, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
            # Several different WMI properties may have the same name.
            rdf_graph.add((property_node, rdflib.namespace.RDFS.label, rdflib.Literal(full_property_name)))
            try:
                property_description = str(wmi_property_obj.Qualifiers_("Description"))
                rdf_graph.add((property_node, rdflib.namespace.RDFS.comment, rdflib.Literal(property_description)))
            except:
                pass

            rdf_graph.add((property_node, rdflib.namespace.RDFS.domain, class_node))

            wmi_type_name = str(wmi_property_obj.Qualifiers_('CIMTYPE'))
            if wmi_type_name.startswith("ref:"):
                predicate_type_class_name = wmi_type_name[4:]
                # Then it can only be a class
                predicate_type_node = rdflib.URIRef(SURVOLNS[predicate_type_class_name])
            else:
                # Other possible values: "ref:__Provider", "ref:Win32_LogicalFileSecuritySetting",
                # "ref:Win32_ComputerSystem",
                # "ref:CIM_DataFile", "ref:__EventConsumer", "ref:CIM_LogicalElement",
                # "ref:CIM_Directory" but also "ref:Win32_Directory".
                # "Win32_DataFile" never appears.

                # Sometimes the datatype is wrongly cased: "string", "String, "STRING".
                predicate_type_node = _convert_wmi_type_to_xsd_type(wmi_type_name)
            if predicate_type_node:
                rdf_graph.add((property_node, rdflib.namespace.RDFS.range, predicate_type_node))
            else:
                # Example: Unknown XSD type: object / Representative / __AggregateEvent
                logging.error("Unknown XSD type: %s / %s / %s", wmi_type_name, property_name, class_name)

            try:
                is_key = wmi_property_obj.Qualifiers_('key')
                if is_key:
                    rdf_graph.add((property_node, property_key_node, rdflib.Literal(True)))
            except Exception:
                # (-2147352567, 'Exception occurred.', (0, 'SWbemQualifierSet', 'Not found ', None, 0, -2147217406), None)
                pass

            # https://it.semweb.ch/lod/2016/12/unitsofmeasure.rdf
            try:
                unit_name = str(wmi_property_obj.Qualifiers_("Units"))
                rdf_graph.add((property_node, property_key_node, rdflib.Literal(unit_name)))
            except:
                pass


# https://docs.microsoft.com/en-us/windows/win32/wmisdk/key-qualifier
# If more than one property has the Key qualifier, then all such properties collectively form the key (a compound key).
# ou can use any property type except for the following:
# - Arrays
# - Real and floating-point numbers
# - Embedded objects
# - Characters lower than ASCII 32 (that is, white space characters)
# - Character strings of type char16 or character strings that are defined as keys must contain values
# greater than U+0020. This is because WMI uses key values in object monikers,
# and you cannot use nonprinting characters in an object moniker.
#
# Because monikers use keys, they can be safely used in URLs, plus maybe some URL escaping.
#
# But what about access speed ?


def _get_wmi_class_properties(class_name):
    """
    Given a WMI class name, it fetches its properties.
    FIXME: "Properties_", "Name", "Qualifiers", SubclassesOf" do not appear in dir()
    :param class_name: A WMI class name.
    :return: A dict containing the class names and types.
    """
    cls_obj = getattr(wmi_conn, class_name)
    class_props = {}
    keys_list = []
    for prop_obj in cls_obj.Properties_:
        # It is possible to loop like this:
        # for qualifier in prop_obj.Qualifiers_:
        #    print("    qualifier.Name / Value=", qualifier.Name, qualifier.Value)
        # or:
        # all_qualifiers = {one_qual.Name: one_qual.Value for one_qual in prop_obj.Qualifiers_}

        # It is also possible to write: str(prop_obj.Qualifiers_('CIMTYPE'))
        # This is the conversion to str otherwise the value of 'CIMTYPE' is:
        # <win32com.gen_py.Microsoft WMI Scripting V1.2 Library.ISWbemQualifier instance at 0x1400534310432>

        # Beware to this documentation, the keys are not valid when called from Python:
        # https://docs.microsoft.com/en-us/windows/win32/wmisdk/standard-wmi-qualifiers

        property_type = str(prop_obj.Qualifiers_('CIMTYPE'))

        try:
            is_key = prop_obj.Qualifiers_('key')
            if is_key:
                keys_list.append(prop_obj.Name)
        except Exception:
            # (-2147352567, 'Exception occurred.', (0, 'SWbemQualifierSet', 'Not found ', None, 0, -2147217406), None)
            pass

        class_props[prop_obj.Name] = property_type
    return class_props, keys_list


# Calculer le moniker d'un objet qui est reference d'un associator,
# si on connait toutes les keys de cet objet.
# Notons que c'est conceptuellement la meme chose que boucler d'abord sur la class de cette reference,
# ce qui devrait etre immediat si on en a toutes les keys.
# Si, dans known_variables, on a toutes les clefs d'un node,
# normallement, on ajouterai "select * from <class> where keys=".
# Mais il suffit de reconstruire le moniker.
# On met une boucle bidon: for x in [<moniker just recalculated>]


def _keys_list_to_tuple(keys_list):
    """
    The keys of a class are in a specific order in stored in a tuple, used as a key.
    :param keys_list: The input list of keys.
    :return: A tuple containing the keys.
    """
    return tuple(sorted(keys_list))


def _create_classes_dictionary():
    # Typical values.
    #    'CIM_ProcessExecutable': {'Antecedent': 'ref:CIM_DataFile', 'BaseAddress': 'uint64', 'Dependent': 'ref:CIM_Process', 'GlobalProcessCount': 'uint32', 'ModuleInstance': 'uint32', 'ProcessCount': 'uint32'},
    #    'CIM_DirectoryContainsFile': {'GroupComponent': 'ref:CIM_Directory', 'PartComponent': 'ref:CIM_DataFile'},
    #    'CIM_DataFile': {'AccessMask': 'uint32', 'Archive': 'boolean', 'Caption': 'string', 'Compressed': 'boolean', 'CompressionMethod': 'string', 'CreationClassName': 'string', 'CreationDate': 'datetime', 'CSCreationClassName': 'string', 'CSName': 'string', 'Description': 'string', 'Drive': 'string', 'EightDotThreeFileName': 'string', 'Encrypted': 'boolean', 'EncryptionMethod': 'string', 'Extension': 'string', 'FileName': 'string', 'FileSize': 'uint64', 'FileType': 'string', 'FSCreationClassName': 'string', 'FSName': 'string', 'Hidden': 'boolean', 'InstallDate': 'datetime', 'InUseCount': 'uint64', 'LastAccessed': 'datetime', 'LastModified': 'datetime', 'Manufacturer': 'string', 'Name': 'string', 'Path': 'string', 'Readable': 'boolean', 'Status': 'string', 'System': 'boolean', 'Version': 'string', 'Writeable': 'boolean'},
    #    'CIM_Process': {'Caption': 'string', 'CreationClassName': 'string', 'CreationDate': 'datetime', 'CSCreationClassName': 'string', 'CSName': 'string', 'Description': 'string', 'ExecutionState': 'uint16', 'Handle': 'string', 'InstallDate': 'datetime', 'KernelModeTime': 'uint64', 'Name': 'string', 'OSCreationClassName': 'string', 'OSName': 'string', 'Priority': 'uint32', 'Status': 'string', 'TerminationDate': 'datetime', 'UserModeTime': 'uint64', 'WorkingSetSize': 'uint64'},
    classes_dict = {}
    keys_dict = {}

    if debug_mode:
        classes_list = ['CIM_ProcessExecutable', 'CIM_DirectoryContainsFile', 'Win32_SubDirectory',
                        'Win32_Directory', 'CIM_Directory', 'CIM_DataFile', 'CIM_Process', 'Win32_Process']
    else:
        classes_list = wmi_conn.classes

    for one_class in classes_list:
        the_properties, the_keys = _get_wmi_class_properties(one_class)
        #if debug_mode:
        #    print(one_class, "the_properties=", the_properties)
        #    print(one_class, "the_keys=", the_keys)
        classes_dict[one_class] = the_properties
        keys_dict[one_class] = _keys_list_to_tuple(the_keys)
    return classes_dict, keys_dict


classes_dictionary, keys_dictionary = _create_classes_dictionary()


#  _convert_ontology_to_rdf(classes_dictionary, map_attributes, rdf_graph)

#################################################################################################

moniker_prefix = r"\\LAPTOP-R89KG6V1\root\cimv2:"


def _create_wmi_moniker(class_name, **kwargs):
    """
    This recreates the moniker of an objet, given the values of its keys.
    :param class_name:
    :param kwargs: key-value pairs of its keys.
    :return: The moniker as a string.
    """
    valid_keys = keys_dictionary[class_name]

    """
    Les monikers sont en principe case-insensitive.
    https://docs.microsoft.com/en-us/windows/win32/wmisdk/constructing-a-moniker-string
    "select * from CIM_DirectoryContainsFile" renvoie "kernel32.dll" ce qui est exact.
    Mais "select Antecedent from CIM_ProcessExecutable" renvoie CIM_Datafile.Name="KERNEL32.DLL" ce qui est faux
    Et "select * from CIM_DataFile where Name="C:\\windows\\system32\\kernel32.DLL"'" renvoie ce qu'on a mis.
    Donc il faut convertir a priori les monikers en majuscules.
    """

    def _value_to_str(the_value):
        # The values passed as parameter are plain literal values for non-associator classes.
        # But for associator classes, such as CIM_DirectoryContainsFile, the values of the two keys
        # GroupComponent and PartComponent are also objects. These values are passed as PseudoWmiObject
        # or possibly wmi._wmi_object.
        if isinstance(the_value, PseudoWmiObject):
            # Validity check, to avoid confusion with a node.
            assert not the_value.m_wmi_moniker.startswith("http")

            # FIXME: This is not necessary because PseudoWmiObject.__str__ returns m_wmi_moniker anyway.
            return the_value.m_wmi_moniker.replace("\\", "\\\\").upper()
        # FIXME: IS IT CALLED ?
        else:
            assert isinstance(the_value, (bool, int, float, str))
            assert not isinstance(the_value, wmi._wmi_object)
            assert not issubclass(the_value.__class__, win32com.client.DispatchBaseClass)

            # Validity check, to avoid confusion with a node.
            assert not str(the_value).startswith("http"), "%s should not be a node" % the_value

            # This conversion to str would be done anyway.
            # BEWARE: Backslahes must be escaped in arguments of WMI monikers !!!
            result = str(the_value).replace("\\", "\\\\") # .replace('"', '\\"')
            # print("_value_to_str result=", result)
            return result

    # The keys must be sorted.
    # FIXME: Which order is used by WMI ?
    # FIXME: Maybe the monikers should always be rebuilt for this reason.
    try:
        properties_as_str = ",".join(
            '%s="%s"' % (key, _value_to_str(kwargs[key]).replace('"', '\\"'))
            for key in sorted(valid_keys))
    except KeyError:
        # Maybe some keys are missing.
        print("WARNING: Missing keys for %s from %s" % (class_name, valid_keys))
        return None
    #print("properties_as_str=", properties_as_str)

    # print("properties_as_str=", properties_as_str)
    # This is just to ensure that only key properties are used. "Caption" is never a key property.
    assert properties_as_str.find("Caption") < 0
    wmi_moniker = moniker_prefix + class_name + "." + properties_as_str
    return wmi_moniker.upper()


def _wmi_moniker_to_rdf_node(object_wmi_moniker):
    # This transforms non-alphanumeric chars (roughly) into %hexa pairs.
    quoted_moniker = urllib.parse.quote(object_wmi_moniker)
    rdf_node = rdflib.URIRef(SURVOLNS[quoted_moniker])
    return rdf_node


def wmi_attributes_to_rdf_node(class_name, **kwargs):
    #print("kwargs1=", kwargs)
    #for k, v in kwargs.items():
    #    print("    ", k, v, len(v), type(v))
    unquoted_moniker = _create_wmi_moniker(class_name, **kwargs)
    print("unquoted_moniker=", unquoted_moniker)
    if not unquoted_moniker:
        print("WARNING: Missing keys for %s in %s" % (class_name, list(kwargs.keys())))
        return None
    return _wmi_moniker_to_rdf_node(unquoted_moniker)

#################################################################################################

class PseudoWmiObject:
    """
    This behaves like an object returned by a wmi query, but it is returned by a Python function.
    TODO: It would be possible and cleaner to recreate the WMI object from the moniker with the syntax:
    TODO:    the_object = wmi.WMI(moniker=the_path)
    TODO: This would be simpler and ensure that no attribute is missing. Check performance.

    TODO: Get only the needed properties. See ISWbemObject_to_value and its extractor.
    """
    def __init__(self, class_name, key_values):
        self.m_wmi_moniker = _create_wmi_moniker(class_name, **key_values)
        for key, value in key_values.items():
            setattr(self, key, value)

    def __str__(self):
        return self.m_wmi_moniker.upper()

    def get_node(self):
        assert False

#################################################################################################



# https://marketplace.atlassian.com/apps/1216286/gitlab-connector?tab=overview&hosting=datacenter


"""
Integrer d autres classes.
Si on prend du recul, on mappe le modele de donnees WMI dans Sparql.
On pourrait generaliser ca en mappant les classes d'autres packages Python dans Sparql aussi.
Ca donnerait une approche generale plus simple a comprendre.
Ca donnerait aussi le prefixe de maniere naturelle.
Et l URL pointerait peut-etre sur Pypi.
Les scripts sont differents de ceux qui existent, et ne seront pas la que pour accelerer.
Plus rapide que de faire des federated queries sur un serveur par package.

Mais encore faut-il que les packages s'y pretent.
psutil
pyelf
sqlite


"""

# These functions are executed in place of a WQL query.
_specialised_generators_dict = dict()


def _specialised_generator_dir_to_subdirs(class_name, where_clause):
    """
    This returns the files contained in a directory.
    Similar to the WQL query: "select * from Win32_SubDirectory where GroupComponent='xyz'", but faster.
    :param class_name: Should be CIM_Directory or Win32_Directory.
    :param where_clauses: {"Name": "xyz"}
    :return: A dictionary containing the sub-directories.
    """
    assert class_name == 'Win32_SubDirectory'
    dir_name = where_clause['GroupComponent'].Name

    group_component = PseudoWmiObject("Win32_Directory", {"Name": dir_name})

    subobjects = []

    if dir_name.endswith(":"):
        dir_name += "\\"
    for root_dir, directories, files in os.walk(dir_name):
        for one_dir in directories:
            full_dir_path = os.path.join(root_dir, one_dir)
            part_component = PseudoWmiObject("Win32_Directory", {"Name": full_dir_path})
            associator = PseudoWmiObject("Win32_SubDirectory",
                                         {"PartComponent": part_component, "GroupComponent": group_component})
            print("Adding associator", str(associator))
            subobjects.append(associator)
        # Then stop at first level.
        break

    # This must return objects with the same interface as instances of Win32_SubDirectory
    return subobjects


def _specialised_generator_subdir_to_dir(class_name, where_clause):
    """
    This returns the directory containing a directory.
    Similar to the WQL query: "select * from Win32_SubDirectory where PartComponent='xyz'", but faster.
    :param class_name: Should be CIM_Directory or Win32_Directory.
    :param where_clauses: {"Name": "xyz"}
    :return: A single-element dictionary containing the directory containing the input dir.
    """
    assert class_name == 'Win32_SubDirectory', "Class should not be %s" % class_name
    file_name = where_clause['PartComponent'].Name

    part_component = PseudoWmiObject("Win32_Directory", {"Name": file_name})

    base_dir_name = os.path.dirname(file_name)

    group_component = PseudoWmiObject("Win32_Directory", {"Name": base_dir_name})
    associator = PseudoWmiObject("Win32_SubDirectory",
                                 {"PartComponent": part_component, "GroupComponent": group_component})
    subobjects = [associator]

    # This must return one object with the same interface as instances of Win32_SubDirectory
    return subobjects


def _specialised_generator_dir_to_files(class_name, where_clause):
    """
    This returns the files contained in a directory.
    Similar to the WQL query: "select * from CIM_DirectoryContainsFile where GroupComponent='xyz'", but faster.
    :param class_name: Should be CIM_Directory or Win32_Directory.
    :param where_clauses: {"Name": "xyz"}
    :return: A dictionary containing the files.
    """
    assert class_name == 'CIM_DirectoryContainsFile'
    dir_name = where_clause['GroupComponent'].Name

    group_component = PseudoWmiObject("Win32_Directory", {"Name": dir_name})

    subobjects = []

    if dir_name.endswith(":"):
        dir_name += "\\"
    for root_dir, directories, files in os.walk(dir_name):
        for one_file in files:
            full_file_path = os.path.join(root_dir, one_file)
            part_component = PseudoWmiObject("CIM_DataFile", {"Name": full_file_path})

            associator = PseudoWmiObject("CIM_DirectoryContainsFile",
                                         {"PartComponent": part_component, "GroupComponent": group_component})
            print("Adding associator", str(associator))
            subobjects.append(associator)

        # Then stop at first level.
        break

    # This must return objects with the same interface as instances of CIM_DirectoryContainsFile
    return subobjects


def _specialised_generator_file_to_dir(class_name, where_clause):
    """
    This returns the files and directories contained in a directory.
    Similar to the WQL query: "select * from CIM_DirectoryContainsFile where PartComponent='xyz'", but faster.
    :param class_name: Should be CIM_DataFile.
    :param where_clauses: {"Name": "xyz"}
    :return: A single-element dictionary containing the directory of the file.
    """
    assert class_name == 'CIM_DirectoryContainsFile'
    file_name = where_clause['PartComponent'].Name

    part_component = PseudoWmiObject("CIM_DataFile", {"Name": file_name})

    base_dir_name = os.path.dirname(file_name)

    group_component = PseudoWmiObject("Win32_Directory", {"Name": base_dir_name})
    associator = PseudoWmiObject("CIM_DirectoryContainsFile",
                                 {"PartComponent": part_component, "GroupComponent": group_component})
    subobjects = [associator]

    # This must return objects with the same interface as instances of CIM_DirectoryContainsFile
    return subobjects

_specialised_generators_dict[("Win32_SubDirectory", ("GroupComponent",))] = "_specialised_generator_dir_to_subdirs"
_specialised_generators_dict[("Win32_SubDirectory", ("PartComponent",))] = "_specialised_generator_subdir_to_dir"
_specialised_generators_dict[("CIM_DirectoryContainsFile", ("GroupComponent",))] = "_specialised_generator_dir_to_files"
_specialised_generators_dict[("CIM_DirectoryContainsFile", ("PartComponent",))] = "_specialised_generator_file_to_dir"


#################################################################################################


def _where_clauses_python(where_clauses):
    return ", ".join(["'%s': %s" % where_clause for where_clause in where_clauses.items()])


# Typical moniker:
# \\LAPTOP-R89KG6V1\root\cimv2:CIM_ProcessExecutable.Antecedent="\\\\LAPTOP-R89KG6V1\\root\\cimv2:CIM_DataFile.Name=\"C:\\\\WINDOWS\\\\System32\\\\DriverStore\\\\FileRepository\\\\iigd_dch.inf_amd64
#                      _ea63d1eddd5853b5\\\\igdinfo64.dll\"",Dependent="\\\\LAPTOP-R89KG6V1\\root\\cimv2:Win32_Process.Handle=\"32308\""

# Real examples in Powershell - they are quite fast:
# PS C:\Users\rchat> Get-WmiObject -Query 'select * from CIM_ProcessExecutable where Antecedent="\\\\LAPTOP-R89KG6V1\\root\\cimv2:CIM_DataFile.Name=\"C:\\\\WINDOWS\\\\System32\\\\DriverStore\\\\FileRepository\\\\iigd_dch.inf_amd64_ea63d1eddd5853b5\\\\igdinfo64.dll\""'
# PS C:\Users\rchat> Get-WmiObject -Query 'select * from CIM_ProcessExecutable where Dependent="\\\\LAPTOP-R89KG6V1\\root\\cimv2:Win32_Process.Handle=\"32308\""'

def _dyn_format(where_variable):
    if isinstance(where_variable, wmi._wmi_object):
        # The moniker is also called "path".
        return str(where_variable.path()).upper()
    else:
        return where_variable


def _where_clauses_wql(where_clauses):
    """
    This concatenates key-value pairs to build the "where" part of a WQL query.
    The values are Python variables names which will be evaluated during execution.
    :param where_clauses:
    :return:
    """
    if not where_clauses:
        return "\""
    where_keys = where_clauses.keys()

    # In WQL, it is probably not necessary to wrap a number in double-quotes.
    # These queries work:
    # select * from CIM_ProcessExecutable where Dependent="\\\\LAPTOP-R89KG6V1\\root\\cimv2:Win32_Process.Handle=32308"
    # select * from CIM_ProcessExecutable where Dependent="\\\\LAPTOP-R89KG6V1\\root\\cimv2:Win32_Process.Handle=\"32308\""
    # select * from CIM_Process where Handle=32308
    def _format_where_value(where_value):
        if isinstance(where_value, VARI):
            # return "str(%s.path())" % where_value
            # We can know only during execution, that this variable is not a simple value, but a WMI object.
            return "_dyn_format(%s)" % where_value
        elif isinstance(where_value, LITT):
            return '"%s"' % where_value
        else:
            raise Exception("Invalid where value type:%s / %s" % (where_value, type(where_value)))

    formatted_where_values = [_format_where_value(where_value) for where_value in where_clauses.values()]

    return " where " \
           + " and ".join(["%s='%%s'" % one_property for one_property in where_keys]) \
           + "\" % (" + ", ".join(formatted_where_values) + ")"


# This might be a full scan, so it depends on the estimated number of elements.
# Unusual numbers, easier to find in debug logs.
cost_per_class_dict = {
    'CIM_ProcessExecutable': 999,
    'CIM_DirectoryContainsFile': 999999,
    'Win32_SubDirectory': 999999,
    'Win32_Directory': 9999,
    'CIM_Directory': 9999,
    'CIM_DataFile': 88888,
    'CIM_Process': 111,
    'Win32_Process': 111,
}

"""
Pour le cost, on va faire comme ca.
Chaque classe a un nombre estime qui est le cout d un full-scan.
Si on a une clef, le cost devient 1.
Si on a un champ qui n est pas une clef, sqrt(num elements).

Pour les associations, ca devrait etre num-elts-classA * num-elts-class-B = num-elts-assoc
mais en pratique, ca serait idiot d avoir le prdt cartesien complet.

Donc on dit sqrt(num-elts-classA * num-elts-class-B) = num-elts-assoc
A la place de sqrt, on pourrait avoir LOG. L idee est de reduire "proprtionnellement".

Si on a une clef de la table A de l'assoc, le cost devient sqrt(num-elts-class-B).
Si on a les deux clefs, ca devient 1.
Pour les specialized et wincom32 on applique simplement un ratio.
Et puis le cost devient un double, ca evitera les arrondis.

Donc on va ajouter une passe qui calcule le cost des assoc.

VERIFIER SI CA A DU SENS:


"""


def _wql_query_to_cost(class_name, where_clauses):
    """
    The execution cost of this query could be experimentally evaluated.
    FIXME: This is just an estimate.
    :param class_name:
    :param where_clauses:
    :return: The cost of the execution of the query, estimated in number of loops.
    """

    if _contains_one_key(class_name, where_clauses):
        return 10
    else:
        return cost_per_class_dict.get(class_name, 999)


def _contains_all_keys(class_name, where_clauses):
    """
    This checks that the keys of "where" clauses are a subset of the clauses.

    It is used to determine that the moniker of an instance can be calculated,
    and therefore that no query is needed.

    :param class_name: The class
    :param where_clauses: Key value pairs. Only the keys are important.
    :return: True or False.
    """
    where_keys = set(where_clauses.keys())
    class_keys = set(keys_dictionary.get(class_name, tuple()))
    return class_keys.issubset(where_keys)


def _contains_one_key(class_name, where_clauses):
    """
    A single element is defined in a class by an unique value of all its keys taken together.
    However, speed tests tend yto show that an access on a single key benefits of better performance.
    This is specifically relevant for associators where it makes sense to ease access from one reference only.
    :param class_name: The class
    :param where_clauses: Key value pairs. Only the keys are important.
    :return: True or False.
    """
    all_keys = set(where_clauses.keys())
    class_keys = keys_dictionary[class_name]

    keys_intersection = all_keys.intersection(class_keys)

    return len(keys_intersection) > 0

##############################################################################################################


def python_property_extractor(python_object_name, class_name, property_name):
    return "%s.%s" % (python_object_name, property_name)


def pseudo_object_property_extractor(pseudo_wmi_object_name, class_name, property_name):
    return "%s.%s" % (pseudo_wmi_object_name, property_name)


def wmi_object_property_extractor(wmi_object_name, class_name, property_name):
    return "%s.%s" % (wmi_object_name, property_name)


_moniker_to_wmi_object_cache = dict()


def _moniker_to_wmi_object(wmi_moniker):
    try:
        return _moniker_to_wmi_object_cache[wmi_moniker]
    except KeyError:
        wmi_object = wmi.WMI(moniker=wmi_moniker)
        _moniker_to_wmi_object_cache[wmi_moniker] = wmi_object
        return wmi_object


def ISWbemObject_to_value(win32com_object_name, class_name, property_name):
    # win32com_object type is something like win32com.gen_py.565783C6-CB41-11D1-8B02-00600806D9B6x0x1x2.ISWbemObject,
    # Base class is <class 'win32com.client.DispatchBaseClass'>
    if classes_dictionary[class_name][property_name].startswith("ref:"):
        # If this is a reference, then rebuild the WMI object, because later, its properties are needed.
        # TODO: Get only the needed properties.
        # FIXME: This takes all WMI properties, but most of them are not needed.
        # FIXME; Consider a cache if the same objet is built several times because of nested loops.
        # return "wmi.WMI(moniker=%s.Properties_('%s').Value.upper())" % (win32com_object_name, property_name)
        return "_moniker_to_wmi_object(%s.Properties_('%s').Value.upper())" % (win32com_object_name, property_name)
    else:
        return "%s.Properties_('%s').Value" % (win32com_object_name, property_name)

##############################################################################################################


def _build_generator_wmi(class_name, where_clauses, needed_variables):
    # TODO: https://techgenix.com/UsingWMIfiltersinGroupPolicy/
    # TODO: https://evilgpo.blogspot.com/2014/11/wmi-filter-queries-and-thoughts-on.html
    # TODO: Instead of selecting everythin with a "*", it is faster to select only named properties,
    # TODO: and even faster a key property.
    #
    # TODO: https://python-list.python.narkive.com/lCzvZyOh/speeding-up-python-when-using-wmi
    # TODO: Consider this speed up:
    # TODO: l=[x.Properties_("Antecedent").Value for x in win32com.client.GetObject("winmgmts:").InstancesOf("CIM_ProcessExecutable")]
    # TODO: ... or:
    # TODO: for os in win32com.client.GetObject ("winmgmts:").InstancesOf("Win32_OperatingSystem"):
    # TODO:     my_caption = os.Properties_ ("Caption").Value

    query_cost = _wql_query_to_cost(class_name, where_clauses)
    print("where_clauses=", where_clauses)
    if where_clauses:
        # TODO: For better performance, consider this syntax which might be faster:
        # TODO: for myTime in myWMI.Win32_LocalTime ():
        # TODO: for s in c.Win32_Service(StartMode="Auto", State="Stopped"):

        generic_column = ", ".join(needed_variables) if needed_variables else "*"
        query_generator = "wmi_conn.query(\"select %s from %s%s)" % (
            generic_column, class_name, _where_clauses_wql(where_clauses))
        property_extractor = wmi_object_property_extractor
        query_cost = _wql_query_to_cost(class_name, where_clauses)
    else:
        print("QUERY win32com")
        query_generator = "win32com.client.GetObject('winmgmts:').InstancesOf('%s')" % class_name
        property_extractor = ISWbemObject_to_value
        # The cost should be lower : This is an estimate.
        query_cost /= 5

    return query_generator, query_cost, property_extractor


def _build_generator(class_name, where_clauses, needed_variables):
    where_keys = _keys_list_to_tuple(where_clauses.keys())
    generator_key = (class_name, where_keys)

    if False and _contains_all_keys(class_name, where_clauses):
        print("TODO: SI TOUTES LES CLEFS SONT LA, CONSTRUIRE LE MONIKER ET SIMPLEMENT: '[wmi.WMI(moniker='bla bla bla')]' ")

        # If all keys are defined in the where clauses, then the moniker can be recalculated.
        # This avoids a call to wmi.
        # TODO: Implement this.
        # This will produce for example: "for the_moniker in [_build_moniker_from_key('CIM_DataFile', Name='C:'})
        created_generator = "[ _build_moniker_from_key('%s', %s),]" % (class_name, where_clauses)
        generator_origin = "build_moniker_from_keys"
        generator_cost = 1
    elif generator_key in _specialised_generators_dict:
        # If there is a Python function doing the same as a WQL query.
        generator_name = _specialised_generators_dict[generator_key]
        created_generator = "%s('%s', {%s})" % (generator_name, class_name, _where_clauses_python(where_clauses))
        generator_origin = "customization"
        # TODO: The cost of specialized generators should be evaluated.
        generator_cost = 1
        property_extractor = pseudo_object_property_extractor
    else:
        created_generator, generator_cost , property_extractor = _build_generator_wmi(class_name, where_clauses, needed_variables)
        generator_origin = "wmi"

    return {
        "generator": created_generator,
        "origin": generator_origin,
        "cost": generator_cost,
        "property_extractor_name": property_extractor
    }


def _generate_wql_code(output_stream, lst_output_variables, lst_objects, function_name):
    known_variables = set()
    total_cost = 1

    generated_loop_counter = 0
    objects_loop_counter = 0

    # This is used for debugging: It summarizes the order of loops and input variables.
    loops_report = []

    def output_code_line(code_string):
        margin = "    " * generated_loop_counter
        output_stream.write("%s%s\n" % (margin, code_string))

    def output_comment(comment_string):
        output_code_line(comment_prefix + comment_string)

    #output_code_line("cnt = 0")
    output_code_line("def %s():" % function_name)
    generated_loop_counter = 1
    #new_nested_loop = True

    for one_obj in lst_objects:
        obj_subject, obj_class, obj_properties = one_obj.m_subject, one_obj.m_class, one_obj.m_properties
        comment_prefix = "# %d : " % objects_loop_counter
        assigns_list = []
        filters_list = []
        if obj_subject in known_variables:
            # The object is known: We just need to assign the value of its properties,
            # if they are variables (not literals) and their value is not known.
            # There is no need to insert a query to iterate on the possible values of the object.
            # output_comment("Variable %s is known" % node_variable)
            # The node is known:
            #     var1 = the_node.Member1
            #     var2 = the_node.Member2
            # No query is generated.
            for one_property, one_variable in obj_properties.items():
                if isinstance(one_variable, VARI):
                    if one_variable in known_variables:
                        # No need to assign this variable.
                        # FIXME: Add a restriction ?
                        print("ADD FILTER ???")
                        pass
                    else:
                        assigns_list.append((one_variable, obj_subject, one_property, "%s is known" % one_variable))
                        known_variables.add(one_variable)
                elif isinstance(one_variable, LITT):
                    # This is not a variable
                    print("ADD FILTER ???")
                    filters_list.append((one_variable, obj_subject, one_property, "%s is filtered" % one_variable))
                    pass
                else:
                    raise Exception("Invalid type for variable %s / %s" % (one_variable, type(one_variable)))
            property_extractor = python_property_extractor
        else:
            # The object is not known: A query must be added which will iterate on its possible values.
            # Build the WHERE clause with literal values or known variables.
            where_clauses = {}
            for one_property, one_variable in obj_properties.items():
                if isinstance(one_variable, VARI):
                    if one_variable in known_variables:
                        where_clauses[one_property] = one_variable
                    else:
                        # Now this variable will be known after the execution.
                        known_variables.add(one_variable)
                        assigns_list.append(
                            (one_variable, obj_subject, one_property, " %s is now known" % one_variable))
                elif isinstance(one_variable, LITT):
                    where_clauses[one_property] = one_variable
                else:
                    raise Exception("Invalid type: %s / %s" % (one_variable, type(one_variable)))

            output_comment("known_variables=%s" % ", ".join([str(one_var) for one_var in known_variables]))

            # TODO: Use the syntax offered by wmi Python module, for example:
            # TODO:      fixed_disks = wmi.WMI ().Win32_LogicalDisk (DriveType=3)

            # This selects only needed variables for performance reasons, see:
            # http://www.primordialcode.com/blog/post/optimizing-wmi-query-performances-avoid-nasty-select
            variable_properties = one_obj.variable_properties()
            known_variables_as_str = set(str(one_var) for one_var in known_variables)
            where_clauses_keys = set(where_clauses.keys())
            needed_variables = variable_properties.difference(known_variables_as_str, where_clauses_keys)

            loops_report.append((obj_class, where_clauses))
            instances_generator_description = _build_generator(obj_class, where_clauses, needed_variables)
            generator_cost = instances_generator_description["cost"]
            property_extractor = instances_generator_description["property_extractor_name"]
            # The total cost is the product of each individual loop.
            # A small number is added to model the cost of the overhead of the loop.
            # It prioritizes small loops first.
            total_cost = total_cost * (1 + generator_cost)
            output_comment("Cost: %d, total: %d" % (generator_cost, total_cost))
            loop_line = "for %s in %s:" % (obj_subject, instances_generator_description["generator"])
            output_code_line(loop_line)
            generated_loop_counter += 1
        objects_loop_counter += 1

        if assigns_list:
            # The variable is just a moniker if it is created by a loop using win32com.
            # If so, transforms this moniker into a WMI object.

            # Getting the value might throw "OLE error 0x80041002"
            output_code_line("try:")
            for assign_tuple in assigns_list:
                property_expression = property_extractor(assign_tuple[1], obj_class, assign_tuple[2])
                output_code_line("    %s = %s # %s" % (assign_tuple[0], property_expression, assign_tuple[3]))
            output_code_line("except Exception as exc:")
            # TODO : Store the exception somewhere.
            output_code_line("    print('EXCEPTION:', exc)")
            # output_code_line("    traceback.print_exc()")
            output_code_line("    continue")

        if filters_list:
            # Getting the value might throw "OLE error 0x80041002"
            output_comment("Filters")
            output_code_line("try:")
            for filter_tuple in filters_list:
                property_expression = property_extractor(filter_tuple[1], obj_class, filter_tuple[2])
                output_code_line("    if '%s' != %s : # %s" % (filter_tuple[0], property_expression, filter_tuple[3]))
                output_code_line("        print('Filter %%s', %s)" % property_expression)
                output_code_line("        continue")
            output_code_line("except Exception as exc:")
            # TODO : Store the exception somewhere.
            output_code_line("    print('EXCEPTION:', exc)")
            output_code_line("    continue")

        known_variables.add(obj_subject)

    # This is the last line of the generated code.
    # It is called in the most nested loop.

    # FIXME: No, it must be all variables, and we can list these explicitely.

    resulting_variables = [str(one_var) for one_var in known_variables]
    output_code_line(
        "yield {"
        + ", ".join(
            ["'%s': %s" % (output_variable, output_variable) for output_variable in resulting_variables])
        + "}"
    )
    generated_loop_counter = 1
    output_comment("end of generated code")

    # This dict evaluates the efficiency of the generated code,
    # so it is possible to choose between different implementations.
    code_description = {"total_cost": total_cost, "depth": generated_loop_counter, "loops": loops_report}

    return code_description


def objects_list_to_python_code(output_variables, shuffled_lst_objects, function_name):
    print("run_lst_objects")
    for one_obj in shuffled_lst_objects:
        print("    ", one_obj)
        assert isinstance(one_obj, _CimPattern)

    my_stream = io.StringIO()

    # The returned dict gives criterias to compare different implementations of the nested loops
    # enumerating WQL objects. The performance can be completely different.
    code_description = _generate_wql_code(my_stream, output_variables, shuffled_lst_objects, function_name)
    my_stream.seek(0)
    result_as_str = my_stream.read()
    print("Generated code:", code_description)
    print(result_as_str)
    # Tests if the generated Python code is correct.
    ast.parse(result_as_str)

    return code_description, result_as_str



#################################################################################################

