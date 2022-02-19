import sys
import io
import ast
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
    if str(rdflib_node).startswith(survol_url_prefix):
        return rdflib_node[len(survol_url_prefix):]
    return str(rdflib_node)


class _CimObject:
    def __init__(self, part_subject, class_short, properties_dict=dict()):
        assert isinstance(part_subject, VARI)
        assert isinstance(class_short, str)
        assert isinstance(properties_dict, dict)
        self.m_subject = part_subject
        self.m_class = class_short
        self.m_properties = properties_dict.copy()

    def __str__(self):
        return "%s %s {%s}" % (
            str(self.m_subject),
            self.m_class,
            ", ".join("%s: %s" % (_strip_prefix(key), _strip_prefix(value)) for key, value in self.m_properties.items()))


def _query_header(sparql_query):
    """
    Returns the variable names of an input sparql query.

    :param sparql_query:
    :return: A list of strings which are variable names.
    """
    parsed_query = rdflib.plugins.sparql.parser.parseQuery(sparql_query)

    list_vars = parsed_query[1]['projection']
    list_names = [str(one_var['var']) for one_var in list_vars]
    return list_names


def _part_triples_to_instances_list(part):
    """
    This takes the basic graph pattern (BGP), which is the list of triples patterns
    extracted from the Sparql query, and returns a list of instances of CIM classes,
    each of them containing the triples using its instances.
    The association is done based on the variable representing the instance.
    There might be several instances of the same class.

    Basically, this groups triple patterns by instances.
    This requires that the class of instances is known,
    which is reasonable because Sparql Survol queries are not abstract:
    A file cannot be a process or a socket etc...

    See lib_sparql_custom_eval.py which does something similar.
    """
    instances_dict = dict()
    logging.debug("len(triples)=%d" % len(part.triples))
    for part_subject, part_predicate, part_object in part.triples:
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
    for part_subject, part_predicate, part_object in part.triples:
        current_instance = instances_dict.get(part_subject, None)
        if not current_instance:
            # This is not the pattern of a Survol instance,
            # so we do not care because we cannot do anything with it.
            continue
        assert isinstance(current_instance, _CimObject)

        predicate_as_str = str(part_predicate)
        if predicate_as_str.startswith(survol_url_prefix):
            # This applies only to CIM properties whcih can be used in a WQL query.
            # print("Adding to %s prop=%s pred=%s" % (part_subject, _strip_prefix(predicate_as_str), part_object))
            current_instance.m_properties[part_predicate] = part_object

    return instances_dict.values()


def _fetch_wmi_objects_in_graph(ctx, instances_list):
    """
    This executes WMI queries on the list of instances.
    The order of input instances is not important because they must be sorted to find the most efficient
    suite of WQL queries.

    It inserts triples in the graph of the context.

    :param ctx:
    :param instances_dict:
    :return: Nothing.
    """
    print("instances_list")
    for one_obj in instances_list:
        print("    ", str(one_obj))


def _wmi_custom_eval_function(ctx, part):
    """
    Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
    """

    logging.debug("_wmi_custom_eval_function part.name=%s" % part.name)
    # part.name = "SelectQuery", "Project", "BGP"
    # BGP stands for "Basic Graph Pattern", which is a set of triple patterns.
    # A triple pattern is a triple:
    # RDF-term or value, IRI or value, RDF term or value.
    if part.name == 'BGP':
        # part.name = "SelectQuery", "Project", "BGP"
        # BGP stands for "Basic Graph Pattern", which is a set of triple patterns.
        # A triple pattern is a triple:
        # RDF-term or value, IRI or value, RDF term or value.

        # Possibly add the ontology to ctx.graph

        # This inserts triples in the graph.
        logging.debug("Instances:")
        instances_list = _part_triples_to_instances_list(part)
        for one_instance in instances_list:
            logging.debug("    Instance=%s" % one_instance)

        if instances_list:
            _fetch_wmi_objects_in_graph(ctx, instances_list)
        else:
            logging.warning("No instances. Maybe a meta-data query.")

        # Normal execution of the Sparql engine on the graph with many more triples.
        # <type 'generator'>
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP

    raise NotImplementedError()


def __run_sparql_query(sparql_query):
    grph = rdflib.Graph()

    # add function directly, normally we would use setuptools and entry_points
    rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function'] = _wmi_custom_eval_function
    query_result = grph.query(sparql_query)
    if 'custom_eval_function' in rdflib.plugins.sparql.CUSTOM_EVALS:
        del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function']
    return query_result


def get_wmi_class_properties(class_name):
    """
    FIXME: "Properties_", "Name", "Qualifiers", SubclassesOf" do not appear in dir()
    :param class_name:
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


for one_class in ['CIM_ProcessExecutable', 'CIM_DirectoryContainsFile', 'CIM_DataFile', 'CIM_Process']:
    the_properties = get_wmi_class_properties(one_class)
    print(one_class, "the_properties=", the_properties)

# Short hard-coded dictionary of classes and associators.
dictionary_classes = {
    'CIM_ProcessExecutable': {'Antecedent': 'ref:CIM_DataFile', 'BaseAddress': 'uint64', 'Dependent': 'ref:CIM_Process', 'GlobalProcessCount': 'uint32', 'ModuleInstance': 'uint32', 'ProcessCount': 'uint32'},
    'CIM_DirectoryContainsFile': {'GroupComponent': 'ref:CIM_Directory', 'PartComponent': 'ref:CIM_DataFile'},
    'CIM_DataFile': {'AccessMask': 'uint32', 'Archive': 'boolean', 'Caption': 'string', 'Compressed': 'boolean', 'CompressionMethod': 'string', 'CreationClassName': 'string', 'CreationDate': 'datetime', 'CSCreationClassName': 'string', 'CSName': 'string', 'Description': 'string', 'Drive': 'string', 'EightDotThreeFileName': 'string', 'Encrypted': 'boolean', 'EncryptionMethod': 'string', 'Extension': 'string', 'FileName': 'string', 'FileSize': 'uint64', 'FileType': 'string', 'FSCreationClassName': 'string', 'FSName': 'string', 'Hidden': 'boolean', 'InstallDate': 'datetime', 'InUseCount': 'uint64', 'LastAccessed': 'datetime', 'LastModified': 'datetime', 'Manufacturer': 'string', 'Name': 'string', 'Path': 'string', 'Readable': 'boolean', 'Status': 'string', 'System': 'boolean', 'Version': 'string', 'Writeable': 'boolean'},
    'CIM_Process': {'Caption': 'string', 'CreationClassName': 'string', 'CreationDate': 'datetime', 'CSCreationClassName': 'string', 'CSName': 'string', 'Description': 'string', 'ExecutionState': 'uint16', 'Handle': 'string', 'InstallDate': 'datetime', 'KernelModeTime': 'uint64', 'Name': 'string', 'OSCreationClassName': 'string', 'OSName': 'string', 'Priority': 'uint32', 'Status': 'string', 'TerminationDate': 'datetime', 'UserModeTime': 'uint64', 'WorkingSetSize': 'uint64'},
}


if False:
    cnt = 30
    for my_process in wmi_conn.query("select * from CIM_Process"):
        print("my_process.path()=", my_process.path())
        # \\LAPTOP-R89KG6V1\root\cimv2:Win32_Process.Handle="4"
        process_path = str(my_process.path())
        # The prefix containing the machine and the namespace must be stripped.
        process_path = process_path.partition(':')[2]
        print("process_path=", process_path)
        #process_path = process_path.replace('"', '')
        #print("process_path=", process_path)
        print("my_process.Handle=", my_process.Handle)
        qry = r'associators of {%s} where AssocClass = CIM_ProcessExecutable ResultClass=CIM_DataFile ResultRole=Antecedent Role=Dependent' % process_path
        print("qry=", qry)
        try:
            for my_obj in wmi_conn.query(qry):
                cnt -= 1
                if cnt == 0:
                    break
                print("OK ============================================================================")
                print("my_obj=", my_obj)
                #as_str = str(my_obj)
                #print("as_str=", as_str)
                # Le champ properties n'est pas rempli !!!!!!!

                # dir(my_obj)= ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
                # '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__',
                # '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_associated_classes',
                # '_cached_associated_classes', '_cached_methods', '_cached_properties', '_getAttributeNames', '_get_keys',
                # '_instance_of', '_keys', '_methods', '_properties', 'associated_classes', 'associators', 'derivation', 'id',
                # 'keys', 'methods', 'ole_object', 'path', 'properties', 'property_map', 'put', 'qualifiers', 'references', 'set', 'wmi_property']
                #print("dir(my_obj)=", dir(my_obj))
                print("my_obj.properties=", my_obj.properties)
                #my_obj._get_keys()
                #print("my_obj.properties=", my_obj.properties)
                #print("my_obj.property_map=", my_obj.property_map)

                # my_obj.wmi_property('Name')= <wmi_property: Name>
                #print("my_obj.wmi_property('Name')=", my_obj.wmi_property('Name'))
                print("my_obj.Name=", my_obj.Name)

                # my_obj.id= winmgmts:{authenticationlevel=pktprivacy,impersonationlevel=impersonate}!\\laptop-r89kg6v1\root\cimv2:cim_datafile.name="wmi_conn:\\windows\\system32\\onecoreuapcommonproxystub.dll"
                print("my_obj.id=", my_obj.id)

                # my_obj.wmi_property(property_name='Name')= <wmi_property: Name>
                #print("my_obj.wmi_property(property_name='Name')=", my_obj.wmi_property(property_name='Name'))

                # my_obj.path()= \\LAPTOP-R89KG6V1\root\cimv2:CIM_DataFile.Name="C:\\Windows\\System32\\OneCoreUAPCommonProxyStub.dll"
                print("my_obj.path()=", my_obj.path())
                process_handle = my_process.Handle
                file_name = my_obj.Name
                assert my_obj.Name == getattr(my_obj, 'Name')
                print("process_handle=", process_handle, "file_name=", file_name)
        except Exception as exc:
            print("Caught=", exc)
            pass
        if cnt == 0:
            break
        print("")
    print("########################################")


#################################################################################################


def build_where_clauses(where_clauses):
    if not where_clauses:
        return "\""
    where_keys = [where_clause[0] for where_clause in where_clauses]
    where_values = [where_clause[1] for where_clause in where_clauses]

    return " where " \
         + " and ".join(["%s='%%s'" % one_property for one_property in where_keys]) \
         + "\" % (" + ", ".join(where_values) + ")"


def generate_wql_code(output_stream, lst_output_variables, lst_objects):
    print("")
    known_variables = set()

    generated_loop_counter = 0
    objects_loop_counter = 0

    def output_code_line(code_string):
        margin = "    " * generated_loop_counter
        output_stream.write("%s%s\n" % (margin, code_string))

    for one_obj in lst_objects:
        node_variable, class_name, variables_map = one_obj.m_subject, one_obj.m_class, one_obj.m_properties
        #output_code_line("# known_variables=%s" % list(known_variables))
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
                    #assigns_list.append(
                    #    (one_variable, node_variable, one_property, " %s not known" % one_variable))
                        where_clauses.append((one_property, one_variable))
                    else:
                        # Now this variable will be known after the execution.
                        known_variables.add(one_variable)
                        assigns_list.append(
                            (one_variable, node_variable, one_property, " %s is now known" % one_variable))
                elif isinstance(one_variable, LITT):
                    where_clauses.append((one_property, one_variable))

                #else:
                #    known_variables.add(one_variable)
            output_code_line(comment_prefix + "known_variables=%s" % ", ".join([str(one_var) for one_var in known_variables]))
            current_query = "for %s in wmi_conn.query(\"select * from %s%s):" % (
                node_variable, class_name, build_where_clauses(where_clauses))
            output_code_line(current_query)
            generated_loop_counter += 1
            # output_code_line(comment_prefix + "Assign associators here")

            # Now, assign the variables which now are known.
            for one_property, one_variable in variables_map.items():
                pass
                if isinstance(one_variable, VARI):
                    if one_variable in known_variables:
                        continue
                        #assigns_list.append((one_variable, node_variable, one_property,
                        #                     "assign associators : Variable %s is already known" % one_variable))
                        # output_code_line("pass # %s = %s.%s is already known" % (one_variable, node_variable, one_property))
                    else:
                        #assigns_list.append((one_variable, node_variable, one_property, "assign associators"))
                        known_variables.add(one_variable)
            # output_code_line(comment_prefix + "The end")
        objects_loop_counter += 1

        # output_code_line(comment_prefix + "%d in assigns_list" % len(assigns_list))
        for assign_tuple in assigns_list:
            output_code_line("%s = %s.%s # %s" % assign_tuple)
        known_variables.add(node_variable)

    output_code_line(
        "yield {"
        + ", ".join(
            ["'%s': %s" % (output_variable, output_variable) for output_variable in lst_output_variables])
        + "}"
    )

    # print("known_variables=", known_variables)

#################################################################################################

test_data = {}

#################################################################################################
test_data["CIM_ProcessExecutable simple"] = (
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
    ["my_file_name", "my_process_handle"],
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
    ],
    []
)

#################################################################################################
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
    ["my_dir_name"],
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
    ],
    [])

#################################################################################################
test_data["CIM_Process"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle 12345 .
    ?my_process cim:Caption ?my_process_caption .
    }
    """,
    ["my_process_caption"],
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT(12345), 'Caption': VARI('my_process_caption')}),
    ],
    []
)
#################################################################################################

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
    ["same_caption"],
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Caption': VARI('same_caption')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Caption': VARI('same_caption')}),
    ],
    [])
#################################################################################################
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
    ["my_dir_name3"],
    [
    ],
    [])

#################################################################################################


def shuffle_lst_objects(test_details):
    def run_lst_objects(lst_output_variables, shuffled_lst_objects, outputs_array, output_index):
        print("shuffled_lst_objects")
        for one_obj in shuffled_lst_objects:
            assert isinstance(one_obj, _CimObject)
            print("    ", one_obj)

        my_stream = io.StringIO()
        generate_wql_code(my_stream, lst_output_variables, shuffled_lst_objects)
        my_stream.seek(0)
        result_as_str = my_stream.read()
        print("Generated code:")
        print(result_as_str)
        try:
            ast.parse(result_as_str)
        except SyntaxError:
            raise

        if output_index < len(outputs_array):
            print("EXPECTED:", outputs_array[output_index])

    print("")
    print("#########################################################################################")

    sparql_query = test_details[0]
    print("Run query")
    print(sparql_query)
    __run_sparql_query(sparql_query)
    output_variables = _query_header(sparql_query)
    print("output_variables=", output_variables)
    lst_output_variables = test_details[1]
    lst_objects = test_details[2]
    expected_output = test_details[3]

    run_lst_objects(lst_output_variables, lst_objects, expected_output, 0)
    if len(lst_objects) > 1:
        run_lst_objects(lst_output_variables, lst_objects[1:] + lst_objects[0:1], expected_output, 1)
        run_lst_objects(lst_output_variables, lst_objects[0:1] + lst_objects[1:], expected_output, 2)


for test_description, test_details in test_data.items():
    shuffle_lst_objects(test_details)

