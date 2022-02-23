import sys
import os
import io
import ast
import itertools
import logging

import wmi
import rdflib
from rdflib import plugins
from rdflib.plugins import sparql

logging.getLogger().setLevel(logging.DEBUG)

if False:
    import win32com.client

    # http://sawbuck.googlecode.com/svn/trunk/sawbuck/py/etw/generate_descriptor.py
    # Generate symbols for the WbemScripting module so that we can have symbols
    # for debugging and use constants throughout the file.
    # Without this, win32com.client.constants are not available.
    win32com.client.gencache.EnsureModule('{565783C6-CB41-11D1-8B02-00600806D9B6}', 0, 1, 1)


# These queries work correctly. Please note how back-slashes are escaped.
# select * from CIM_DirectoryContainsFile where GroupComponent="Win32_Directory.Name=\"C:\\\\Users\\\\rchat\""
# select * from CIM_DirectoryContainsFile where PartComponent="CIM_DataFile.Name=\"C:\\\\Users\\\\desktop.ini\""
# select * from CIM_DirectoryContainsFile where PartComponent="CIM_DataFile.Name=\"\\\\\\\\LAPTOP-R89KG6V1\\\\root\\\\cimv2:C:\\\\Users\\\\desktop.ini\""


wmi_conn = wmi.WMI()

survol_url_prefix = "http://www.primhillcomputers.com/ontology/survol#"

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


class _CimObject:
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
            ", ".join("%s: %s" % (_strip_prefix(key), _strip_prefix(value)) for key, value in self.m_properties.items()))

    def __lt__(self, other):
        """
        Needed only for comparing a list of objects with expected results.
        In an object list, it is not possible to have twice the same subject,
        therefore the sorting function just compares the subject.
        """
        return str(self.m_subject) < str(other.m_subject)

    def __eq__(self, other):
        return str(self.m_subject) == str(other.m_subject)


def _query_header(sparql_query):
    """
    Returns the variable names of an sparql query given as input.

    :param sparql_query:
    :return: List of the names of the variables returned by a sparql query.
    """
    parsed_query = rdflib.plugins.sparql.parser.parseQuery(sparql_query)

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
                    instances_dict[part_subject] = _CimObject(part_subject, class_short)

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
        assert isinstance(current_instance, _CimObject)

        predicate_as_str = str(part_predicate)
        if predicate_as_str.startswith(survol_url_prefix):
            # This applies only to CIM properties whcih can be used in a WQL query.
            current_instance.m_properties[_strip_prefix(part_predicate)] = part_object

    return list(instances_dict.values())


class CustomEvalEnvironment:
    """
    This contains utilities for the custom eval function passed to rdflib sparql query execution.
    """
    def __init__(self, test_description, sparql_query, expected_objects_list):
        self.m_test_description = test_description
        self.m_sparql_query = sparql_query
        self.m_output_variables = _query_header(self.m_sparql_query)
        self.m_expected_objects_list = expected_objects_list
        self.m_debug_mode = True
        print("Output variables=", self.m_output_variables)

    def _run_lst_objects(self, shuffled_lst_objects):
        print("run_lst_objects")
        for one_obj in shuffled_lst_objects:
            print("    ", one_obj)
            assert isinstance(one_obj, _CimObject)

        my_stream = io.StringIO()

        # The returned dict gives criterias to compare different implementations of the nested loops
        # enumerating WQL objects. The performance can be completely different.
        code_description = _generate_wql_code(my_stream, self.m_output_variables, shuffled_lst_objects)
        my_stream.seek(0)
        result_as_str = my_stream.read()
        print("Generated code:", code_description)
        print(result_as_str)
        # Tests if correct Python code.
        ast.parse(result_as_str)

        return code_description, result_as_str

    def _fetch_wmi_objects_in_graph(self, ctx_graph, instances_list):
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

        all_queries = []
        for one_permutation in itertools.permutations(instances_list):
            code_description, result_as_str = self._run_lst_objects(one_permutation)
            all_queries.append((code_description, result_as_str))

        best_query_index = 0
        for query_index in range(1, len(all_queries)):
            #print("all_queries[query_index][0]=", all_queries[best_query_index][0])
            if all_queries[best_query_index][0]["total_cost"] > all_queries[query_index][0]["total_cost"]:
                best_query_index = query_index

        print("best query:", self.m_test_description)
        result_as_str = all_queries[best_query_index][1]
        print(result_as_str)

        # This works but it can be very slow.
        # TODO: Execute only if not too slow.
        # TODO: Execute in a sub-process.
        # Create performance statistics which are later used to choose the best enumeration.
        print("Execution")

        if False:
            for my_assoc in wmi_conn.query("select * from CIM_ProcessExecutable"):
                my_file = my_assoc.Antecedent  # my_file is now known
                my_process = my_assoc.Dependent  # my_process is now known
                my_file_name = my_file.Name  # my_file_name is known
                my_process_handle = my_process.Handle  # my_process_handle is known
                print({'my_file_name': my_file_name, 'my_process_handle': my_process_handle})

        eval_result = exec(result_as_str)
        print("eval_result=", eval_result)

    def _check_objects_list(self, instances_list):
        for one_instance in instances_list:
            logging.debug("    Instance=%s" % one_instance)
        # Any order will do for this comparison, as long as it is consistent.
        ordered_actual_instances = sorted(instances_list)
        ordered_expected_instances = sorted(self.m_expected_objects_list)
        assert ordered_actual_instances == ordered_expected_instances

    def my_evaluator(self, ctx_graph, part_triples):
        # Possibly add the ontology to ctx.graph

        logging.debug("Instances:")
        # This extracts builds the list of objects from the BGPs, by grouping them by common subject,
        # if this subject has a CIM class as rdf:type.
        instances_list = _part_triples_to_instances_list(part_triples)
        if self.m_debug_mode:
            self._check_objects_list(instances_list)

        if instances_list:
            self._fetch_wmi_objects_in_graph(ctx_graph, instances_list)
        else:
            logging.warning("No instances. Maybe a meta-data query.")

    def run_tests(self):
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
                self.my_evaluator(ctx.graph, part.triples)

                # Normal execution of the Sparql engine on the graph with many more triples.
                ret_bgp = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
                return ret_bgp

            raise NotImplementedError()

        print("Run query")
        print(self.m_sparql_query)

        grph = rdflib.Graph()

        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function'] = _wmi_custom_eval_function
        query_result = grph.query(self.m_sparql_query)
        if 'custom_eval_function' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function']
        return query_result


def _get_wmi_class_properties(class_name):
    """
    Given a WMI class name, it fetches its properties.
    FIXME: "Properties_", "Name", "Qualifiers", SubclassesOf" do not appear in dir()
    :param class_name: A WMI class name.
    :return: A dict containing the class names and types.
    """
    cls_obj = getattr(wmi_conn, class_name)
    class_props = {}
    for prop_obj in cls_obj.Properties_:
        # This is the conversion to str otherwise the value of 'CIMTYPE' is:
        # <win32com.gen_py.Microsoft WMI Scripting V1.2 Library.ISWbemQualifier instance at 0x1400534310432>
        class_props[prop_obj.Name] = str(prop_obj.Qualifiers_('CIMTYPE'))
        # It is possible to loop like this:
        #for qualifier in prop_obj.Qualifiers_:
        #    print("    qualifier.Name / Value=", qualifier.Name, qualifier.Value)
    return class_props


def _create_classes_dictionary():
    # Typical values.
    #    'CIM_ProcessExecutable': {'Antecedent': 'ref:CIM_DataFile', 'BaseAddress': 'uint64', 'Dependent': 'ref:CIM_Process', 'GlobalProcessCount': 'uint32', 'ModuleInstance': 'uint32', 'ProcessCount': 'uint32'},
    #    'CIM_DirectoryContainsFile': {'GroupComponent': 'ref:CIM_Directory', 'PartComponent': 'ref:CIM_DataFile'},
    #    'CIM_DataFile': {'AccessMask': 'uint32', 'Archive': 'boolean', 'Caption': 'string', 'Compressed': 'boolean', 'CompressionMethod': 'string', 'CreationClassName': 'string', 'CreationDate': 'datetime', 'CSCreationClassName': 'string', 'CSName': 'string', 'Description': 'string', 'Drive': 'string', 'EightDotThreeFileName': 'string', 'Encrypted': 'boolean', 'EncryptionMethod': 'string', 'Extension': 'string', 'FileName': 'string', 'FileSize': 'uint64', 'FileType': 'string', 'FSCreationClassName': 'string', 'FSName': 'string', 'Hidden': 'boolean', 'InstallDate': 'datetime', 'InUseCount': 'uint64', 'LastAccessed': 'datetime', 'LastModified': 'datetime', 'Manufacturer': 'string', 'Name': 'string', 'Path': 'string', 'Readable': 'boolean', 'Status': 'string', 'System': 'boolean', 'Version': 'string', 'Writeable': 'boolean'},
    #    'CIM_Process': {'Caption': 'string', 'CreationClassName': 'string', 'CreationDate': 'datetime', 'CSCreationClassName': 'string', 'CSName': 'string', 'Description': 'string', 'ExecutionState': 'uint16', 'Handle': 'string', 'InstallDate': 'datetime', 'KernelModeTime': 'uint64', 'Name': 'string', 'OSCreationClassName': 'string', 'OSName': 'string', 'Priority': 'uint32', 'Status': 'string', 'TerminationDate': 'datetime', 'UserModeTime': 'uint64', 'WorkingSetSize': 'uint64'},
    classes_dict = {}

    for one_class in ['CIM_ProcessExecutable', 'CIM_DirectoryContainsFile', 'CIM_DataFile', 'CIM_Process']:
        the_properties = _get_wmi_class_properties(one_class)
        print(one_class, "the_properties=", the_properties)
        classes_dict[one_class] = the_properties
    return classes_dict


if False:
    # This is not needed yet.
    classes_dictionary = _create_classes_dictionary()


#################################################################################################

# These functions are executed in place of a WQL query.
_generators_by_key = dict()


class PseudoWmiObject:
    """
    This behaves like an object returned by a wmi query.
    """
    def __init__(self, path, class_name, key_values):
        self.m_path = path
        for key, value in key_values:
            setattr(self, key, value)

    def __str__(self):
        return self.m_path


def _dir_to_files(class_name, where_clauses):
    """
    This returns the files and directories contained in a directory.
    It does the same as the WQL query: "select * from CIM_Directory where Name='xyz'", but much faster.
    :param class_name: Should be CIM_Directory.
    :param where_clauses: {"Name": "xyz"}
    :return: A dictionary containing the files and dirs.
    """
    dir_name = where_clauses["GroupComponent"].Name

    subobjects = []
    for root, directories, files in os.walk(dir_name):
        break

    for one_dir in directories:
        # The creation of the path is hard-coded because it depends on the class.
        # It would be possible to use the list of keys for each class,
        # but there are also formatting specific details.
        # So, because this function is specialised for a class, it makes sense to speciliase the path too.
        dir_subject = '\\\\root\\cimv2\\CIM_Directory.Name="%s"' % one_dir
        subobjects.append(PseudoWmiObject(dir_subject, "CIM_Directory", {"Name": one_dir}))

    for one_file in files:
        # The creation of the path is hard-coded because it depends on the class.
        # It would be possible to use the list of keys for each class,
        # but there are also formatting specific details.
        # So, because this funciton is specialised for a class, it makes sense to speciliase the path too.
        file_subject = '\\\\root\\cimv2\\CIM_DataFile.Name="%s"' % one_file
        subobjects.append(PseudoWmiObject(file_subject, "CIM_DataFile", {"Name": one_file}))


_generators_by_key[("CIM_DirectoryContainsFile", ("GroupComponent",))] = "_dir_to_files"
_generators_by_key[("CIM_DirectoryContainsFile", ("PartComponent",))] = "_file_to_dir"


#################################################################################################


def _where_clauses_python(where_clauses):
    if not where_clauses:
        return ""

    return ", " \
           + ", ".join(["%s=%s" % where_clause for where_clause in where_clauses])


def _where_clauses_wql(where_clauses):
    """
    This concatenates key-value pairs to build the "where" part of a WQL query.
    The values are Python variables names which will be evaluated during execution.
    :param where_clauses:
    :return:
    """
    if not where_clauses:
        return "\""
    where_keys = [where_clause[0] for where_clause in where_clauses]

    def format_value(a_where_value):
        if isinstance(a_where_value, VARI):
            return str(a_where_value)
        elif isinstance(a_where_value, LITT):
            return "'%s'" % a_where_value
        else:
            raise Exception("Invalid where value type:%s" % a_where_value)

    where_values = [format_value(where_clause[1]) for where_clause in where_clauses]

    return " where " \
         + " and ".join(["%s='%%s'" % one_property for one_property in where_keys]) \
         + "\" % (" + ", ".join(where_values) + ")"


def _build_query(class_name, where_clauses):
    # A tuple can be used as a key
    where_keys = tuple(sorted(key for key, value in where_clauses))
    query_key = (class_name, where_keys)

    try:
        generator_name = _generators_by_key[query_key]
        created_query = "%s('%s'%s)" % (generator_name, class_name, _where_clauses_python(where_clauses))
        query_origin = "customization"
        query_cost = 1
    except KeyError:
        created_query = "wmi_conn.query(\"select * from %s%s)" % (class_name, _where_clauses_wql(where_clauses))
        query_origin = "wmi"
        # The execution cost of this query could be experimentally evaluated.
        if class_name in ["CIM_DataFile", "CIM_Directory", "Win32_Directory"]:
            if "Name" in where_clauses:
                # Queries based on the name are not too slow.
                query_cost = 2
            else:
                # A query on a file executed on any other criteria is very slow.
                query_cost = 10
        else:
            # Any value will do for the moment.
            query_cost = 5

    return {
        "query": created_query,
        "origin": query_origin,
        "cost": query_cost
    }


def _generate_wql_code(output_stream, lst_output_variables, lst_objects):
    known_variables = set()
    total_cost = 1

    generated_loop_counter = 0
    objects_loop_counter = 0

    def output_code_line(code_string):
        margin = "    " * generated_loop_counter
        output_stream.write("%s%s\n" % (margin, code_string))

    for one_obj in lst_objects:
        node_variable, class_name, variables_map = one_obj.m_subject, one_obj.m_class, one_obj.m_properties
        comment_prefix = "# %d : " % objects_loop_counter
        assigns_list = []
        if node_variable in known_variables:
            # The object is known: We just need to assign the value of its properties,
            # if they are variables (not literals) and their value is not known.
            # There is no need to insert a query to iterate on the possible values of the object.
            # output_code_line(comment_prefix + "Variable %s is known" % node_variable)
            # The node is known:
            #     var1 = the_node.Member1
            #     var2 = the_node.Member2
            for one_property, one_variable in variables_map.items():
                if isinstance(one_variable, VARI) and one_variable not in known_variables:
                    assigns_list.append(
                        (one_variable, node_variable, one_property, "%s is known" % one_variable))
                    known_variables.add(one_variable)
        else:
            # The object is not known: A query must be added which will iterate on its possible values.
            # Build the WHERE clause with literal values or known variables.
            where_clauses = []
            for one_property, one_variable in variables_map.items():
                if isinstance(one_variable, VARI):
                    if one_variable in known_variables:
                        where_clauses.append((one_property, one_variable))
                    else:
                        # Now this variable will be known after the execution.
                        known_variables.add(one_variable)
                        assigns_list.append(
                            (one_variable, node_variable, one_property, " %s is now known" % one_variable))
                elif isinstance(one_variable, LITT):
                    where_clauses.append((one_property, one_variable))

            output_code_line(
                comment_prefix +
                "known_variables=%s" % ", ".join([str(one_var) for one_var in known_variables]))

            instances_query_description = _build_query(class_name, where_clauses)
            total_cost *= instances_query_description["cost"]
            current_query = "for %s in %s:" % (node_variable, instances_query_description["query"])
            output_code_line(current_query)
            generated_loop_counter += 1

            # Now, assign the variables which now are known.
            for one_property, one_variable in variables_map.items():
                pass
                if isinstance(one_variable, VARI):
                    if not one_variable in known_variables:
                        known_variables.add(one_variable)
        objects_loop_counter += 1

        # output_code_line(comment_prefix + "%d in assigns_list" % len(assigns_list))
        for assign_tuple in assigns_list:
            output_code_line("%s = %s.%s # %s" % assign_tuple)
        known_variables.add(node_variable)

    # This is the last line of the generated code.
    # It is called in the most nested loop.
    output_code_line(
        "print({"
        + ", ".join(
            ["'%s': %s" % (output_variable, output_variable) for output_variable in lst_output_variables])
        + "})"
    )

    # This dict evaluates the efficiency of the generated code,
    # so it is possible to choose between different implementations.
    code_description = {"total_cost": total_cost, "depth": generated_loop_counter}

    return code_description

#################################################################################################


test_data = dict()

test_data["CIM_Directory"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_directory
    where {
    ?my_directory rdf:type cim:CIM_Directory .
    ?my_directory cim:Name "C:" .
    }
    """,
    [
        _CimObject(VARI('my_directory'), 'CIM_Directory', {'Name': LITT('C:')}),
    ]
)

test_data["CIM_Process"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_name ?my_process_handle
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle ?my_process_handle .
    ?my_process cim:Name ?my_process_name .
    }
    """,
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle'), 'Name': VARI('my_process_name')}),
    ]
)

test_data["CIM_DirectoryContainsFile"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_file_name
    where {
    ?my_assoc_dir rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir cim:GroupComponent ?my_dir .
    ?my_assoc_dir cim:PartComponent ?my_file .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    ?my_dir rdf:type cim:Win32_Directory .
    ?my_dir cim:Name 'C:' .
    }
    """,
    [
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': LITT('C:')}),
    ]
)

test_data["CIM_ProcessExecutable"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_file_name ?my_process_handle
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle ?my_process_handle .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    }
    """,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
    ]
)

test_data["CIM_ProcessExecutable CIM_DirectoryContainsFile"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_dir_name
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_assoc_dir rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir cim:GroupComponent ?my_dir .
    ?my_assoc_dir cim:PartComponent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    ?my_dir rdf:type cim:Win32_Directory .
    ?my_dir cim:Name ?my_dir_name .
    }
    """,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
    ]
)

current_pid = os.getpid()
test_data["CIM_Process"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle %s .
    ?my_process cim:Caption ?my_process_caption .
    }
    """ % current_pid,
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT(current_pid), 'Caption': VARI('my_process_caption')}),
    ]
)

test_data["CIM_Process CIM_DataFile"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?same_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Caption ?same_caption .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Caption ?same_caption .
    }
    """,
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Caption': VARI('same_caption')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Caption': VARI('same_caption')}),
    ]
)

test_data["Win32_Directory CIM_DirectoryContainsFile CIM_DirectoryContainsFile"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_dir_name3
    where {
    ?my_dir1 rdf:type cim:Win32_Directory .
    ?my_dir1 rdf:Name "C:" .
    ?my_assoc_dir1 rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir1 cim:GroupComponent ?my_dir1 .
    ?my_assoc_dir1 cim:PartComponent ?my_dir2 .
    ?my_dir2 rdf:type cim:Win32_Directory .
    ?my_assoc_dir2 rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir2 cim:GroupComponent ?my_dir2 .
    ?my_assoc_dir2 cim:PartComponent ?my_dir3 .
    ?my_dir3 rdf:type cim:Win32_Directory .
    ?my_dir3 cim:Name ?my_dir_name3 .
    }
    """,
    [
        _CimObject(VARI('my_assoc_dir1'), 'CIM_DirectoryContainsFile', {'Caption': VARI('same_caption')}),
        _CimObject(VARI('my_assoc_dir2'), 'CIM_DirectoryContainsFile', {'Caption': VARI('same_caption')}),
        _CimObject(VARI('my_dir1'), 'Win32_Directory', {}),
        _CimObject(VARI('my_dir2'), 'Win32_Directory', {}),
        _CimObject(VARI('my_dir3'), 'Win32_Directory', {'Name': VARI('my_dir_name3')}),
    ]
)

"""
Ajouter un test avec deux full scans mais au lieu de faire deux boucles imbriquees, on les fait separament:
select oa from ClassA:
    select ob from ClassB:
        select oc from ClassC where oc.f1 = oa.f1 and oc.f2 = ob.f2

... devient:
la = select oa from ClassA
lb = select ob from ClassB
for oa in la:
    for ob in lb:
        select oc from ClassC where oc.f1 = oa.f1 and oc.f2 = ob.f2
        
        
Autrement dit, on deplace les boucles de WMI vers Python.
C'est a dire qu on decouple une boucle en deux phases:
- Aller chercher le generateur ou la liste.
- Boucler dessus.

Ca permet alors d'entrecroiser deux boucles qui n'ont pas de dependance.
Creer une forme intermediaire pour exprimer ceci
"""

#################################################################################################


def shuffle_lst_objects(test_description, test_details):
    print("")
    print("#########################################################################################")

    custom_eval = CustomEvalEnvironment(test_description, test_details[0], test_details[1])

    custom_eval.run_tests()


for test_description, test_details in test_data.items():
    shuffle_lst_objects(test_description, test_details)

