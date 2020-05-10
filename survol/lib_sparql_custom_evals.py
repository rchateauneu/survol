from __future__ import print_function

import os
import sys
import psutil
import rdflib
# Probably needed to force rdflib to load its plugins ?
# Apparently, this has to be loaded explicitly.
# Surprisingly it was not needed until this commit.
import rdflib.plugins.memory
import rdflib.plugins.sparql

import lib_util
import lib_common
import lib_ontology_tools
import lib_kbase
import lib_properties

################################################################################

# FIXME: This url is often hardcoded in the tests.
survol_url = "http://www.primhillcomputers.com/survol#"
class_CIM_Process = rdflib.term.URIRef(survol_url + "CIM_Process")
class_CIM_Directory = rdflib.term.URIRef(survol_url + "CIM_Directory")
class_CIM_DataFile = rdflib.term.URIRef(survol_url + "CIM_DataFile")

predicate_Handle = rdflib.term.URIRef(survol_url + "Handle")
predicate_Name = rdflib.term.URIRef(survol_url + "Name")

# This is not part of the ontology but allows to return several processes,
# based on their parent process id.
predicate_ParentProcessId = rdflib.term.URIRef(survol_url + "ParentProcessId")

associator_CIM_DirectoryContainsFile = rdflib.term.URIRef(survol_url + "CIM_DirectoryContainsFile")
associator_CIM_ProcessExecutable = rdflib.term.URIRef(survol_url + "CIM_ProcessExecutable")
################################################################################
def add_ontology(graph):
    graph.add((class_CIM_Process, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_Process, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_Process")))
    graph.add((class_CIM_Directory, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_Directory, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_Directory")))
    graph.add((class_CIM_DataFile, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_DataFile, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_DataFile")))

    graph.add((predicate_Handle, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.domain, class_CIM_Process))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.label, rdflib.Literal("Handle")))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))

    graph.add((predicate_ParentProcessId, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.domain, class_CIM_Process))
    graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.label, rdflib.Literal("ParentProcessId")))

    graph.add((predicate_Name, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_Directory))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_DataFile))
    graph.add((predicate_Name, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((predicate_Name, rdflib.namespace.RDFS.label, rdflib.Literal("Name")))

    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.domain, class_CIM_Directory))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, class_CIM_DataFile))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, class_CIM_Directory))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_DirectoryContainsFile")))

    graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDFS.domain, class_CIM_Process))
    graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDFS.range, class_CIM_DataFile))
    graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_ProcessExecutable")))

################################################################################

is_platform_windows = sys.platform.startswith("win")
is_platform_linux = sys.platform.startswith("linux")

def equal_paths(path_a, path_b):
    # print("process_executable=", process_executable, "executable_path=", executable_path)
    # With pytest as a command line: "c:\python27\python.exe" != "C:\Python27\python.exe"
    if is_platform_linux:
        return path_a == path_b
    elif is_platform_windows:
        return path_a.upper() == path_b.upper()
    else:
        raise Exception("Invalid platform")

# For testing and debugging purpose.
def is_usable_file(file_path):
    if os.path.isfile(file_path):
        return True
    if is_platform_linux:
        if os.path.islink(file_path):
            return True
    return False

# For debugging pujrpose.
def current_function():
    return sys._getframe(1).f_code.co_name

################################################################################

class Sparql_CIM_Object(object):
    def __init__(self, class_name, key_variable, ontology_keys):
        self.m_variable = key_variable
        self.m_class_name = class_name
        self.m_associators = {}
        self.m_associated = {}
        self.m_properties = {}
        # For example ["Name", "Domain"]
        self._m_ontology_keys = ontology_keys
        # print("__init__ ontology_keys=", ontology_keys)

    def __str__(self):
        def kw_to_str(property, value):
            property_str = str(property)[len(survol_url):]
            value_str = str(value)
            return "%s=%s" % (property_str, value_str)

        # print("ka=", self.m_known_attributes.items())
        # This takes only the properties which are part of the ontology keys.
        kw_pairs_subset = [
            kw_to_str(property_key, self.m_properties.get(property_key, "UNKNOWN"))
            for property_key in self._m_ontology_keys]

        kw = ".".join(kw_pairs_subset)
        return "Sparql_CIM_Object:" + self.m_class_name + ":" + self.m_variable + ":" + kw

    # The role of this virtual function is to return a dictionary of pairs made of a variable,
    # or a tuple of variables, and a list of its possible values, or a tuple of list of values.
    # The caller uses these key-value paris to create variables context and recursively instantiate objects,
    # by trying all combinations.
    # If variables are grouped in tuples, it means that they are correlated: For example a file path and its node id,
    # or a process id and its command line.
    def FetchAllVariables(self, graph, variables_context):
        sys.stderr.write("FetchAllVariables not implemented\n")
        raise NotImplementedError(current_function())

    def CalculateVariablesNumber(self):
        self.m_number_variables = 0
        self.m_number_literals = 0
        # FIXME: No need to list the associators which contains only instances. Logic should be different.
        for one_dict in [self.m_associators, self.m_associated, self.m_properties]:
            for key, value in one_dict.items():
                if isinstance(value, rdflib.term.Variable):
                    self.m_number_variables += 1
                elif isinstance(value, rdflib.term.Literal):
                    self.m_number_literals += 1

    def GetNodeValue(self, predicate_node, variables_context):
        try:
            predicate_variable = self.m_properties[predicate_node]
        except KeyError:
            sys.stderr.write("GetNodeValue %s not in %s. variables_context.keys=%s\n"
                             % (predicate_node, str(self.m_properties), str(variables_context.keys())))
            raise
        if isinstance(predicate_variable, rdflib.term.Literal):
            node_value = predicate_variable
        elif isinstance(predicate_variable, rdflib.term.Variable):
            if predicate_variable not in variables_context:
                sys.stderr.write("GetNodeValue QUIT: %s not in%s\n" % (predicate_variable, str(variables_context.keys())))
                return None
            node_value = variables_context[predicate_variable]
            sys.stderr.write("predicate_variable=%s node_value=%s\n" % (predicate_variable, node_value))
            assert isinstance(node_value, rdflib.term.Literal)
        return node_value


class Sparql_CIM_DataFile(Sparql_CIM_Object):
    def __init__(self, class_name, node):
        # Same key "Name" for its base class CIM_Directory.
        super(Sparql_CIM_DataFile, self).__init__(class_name, node, ["Name"])

    # This returns the node of the filename which uniquely identifies the object. It uses the literal properties,
    # or the variable properties if these variables have a value in the context.
    # This returns None if it cannot be done.
    def CreateFileNodeFromProperties(self, variables_context):
        sys.stderr.write("Sparql_CIM_DataFile.CreateFileNodeFromProperties\n")
        if predicate_Name in self.m_properties:
            # The path name is enough to fully define a data file or a directory.
            return self.GetNodeValue(predicate_Name, variables_context)
        else:
            sys.stderr.write("Sparql_CIM_DataFile QUIT: No Name\n")
            return None


    def FetchFromDirectory(self, variables_context, file_path, graph, returned_variables, node_uri_ref):
        check_returned_variables(returned_variables)
        sys.stderr.write("Sparql_CIM_DataFile.FetchFromDirectory file_path=%s\n" % file_path)
        if associator_CIM_DirectoryContainsFile in self.m_associated:
            associator_instance = self.m_associated[associator_CIM_DirectoryContainsFile]
            assert isinstance(associator_instance, Sparql_CIM_Directory)
            assert isinstance(associator_instance.m_variable, rdflib.term.Variable)

            if associator_instance.m_variable in variables_context:
                sys.stderr.write("ALREADY DEFINED ?? %s\n" % associator_instance.m_variable)
                return

            dir_file_path = os.path.dirname(file_path)
            dir_file_path_node = rdflib.term.Literal(dir_file_path)

            dir_node_str = "Machine:CIM_Directory?Name=" + dir_file_path
            associator_instance_url = rdflib.term.URIRef(dir_node_str)
            graph.add((associator_instance_url, rdflib.namespace.RDF.type, class_CIM_Directory))
            graph.add((associator_instance_url, associator_CIM_DirectoryContainsFile, node_uri_ref))

            if predicate_Name in associator_instance.m_properties:
                dir_path_variable = associator_instance.m_properties[predicate_Name]
                assert isinstance(dir_path_variable, rdflib.term.Variable)
            else:
                # This property must be created, to make the directory usable,
                # for example to get its other properties.
                # Generally speaking, this must be done for all properties of the ontology.
                variable_name = str(associator_instance.m_variable) + "_dummy_name"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associator_instance.m_properties[predicate_Name] = dir_path_variable

            if isinstance(dir_path_variable, rdflib.term.Variable):
                returned_variables[(associator_instance.m_variable, dir_path_variable)] = [(associator_instance_url, dir_file_path_node)]
                check_returned_variables(returned_variables)
            else:
                returned_variables[associator_instance.m_variable] = [associator_instance_url]
            check_returned_variables(returned_variables)
            graph.add((associator_instance_url, predicate_Name, dir_file_path_node))

    def FetchAllVariables(self, graph, variables_context):
        node_file_path = self.CreateFileNodeFromProperties(variables_context)
        if not node_file_path:
            return {}
        file_path = str(node_file_path)
        returned_variables = {}

        url_as_str = "Machine:CIM_DataFile?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_DataFile))

        returned_variables[(self.m_variable,)] = [(node_uri_ref,)]
        check_returned_variables(returned_variables)

        # No need to add node_file_path in the results because,
        # if it is a Variable, it is already in the context.
        assert isinstance(self.m_variable, rdflib.term.Variable)
        assert node_file_path
        graph.add((node_uri_ref, predicate_Name, node_file_path))

        assert associator_CIM_DirectoryContainsFile not in self.m_associators

        self.FetchFromDirectory(variables_context, file_path, graph, returned_variables, node_uri_ref)

        # TODO: If there are no properties and no directory, this should return ALL FILES OF THE FILE SYSTEM.

        check_returned_variables(returned_variables)
        return returned_variables

class Sparql_CIM_Directory(Sparql_CIM_DataFile):
    def __init__(self, class_name, node):
        super(Sparql_CIM_Directory, self).__init__(class_name, node)

    def FetchAllVariables(self, graph, variables_context):
        node_file_path = self.CreateFileNodeFromProperties(variables_context)
        if not node_file_path:
            sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables LEAVING DOING NOTHING !!!!!\n")
            return {}
        file_path = str(node_file_path)
        returned_variables = {}

        url_as_str = "Machine:CIM_Directory?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)

        assert isinstance(self.m_variable, rdflib.term.Variable)
        returned_variables[(self.m_variable,)] = [(node_uri_ref,)]
        check_returned_variables(returned_variables)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_Directory))

        # No need to add node_file_path in the results=:
        # This Variable is already in the context.
        assert node_file_path
        graph.add((node_uri_ref, predicate_Name, node_file_path))

        self.FetchFromDirectory(variables_context, file_path, graph, returned_variables, node_uri_ref)
        check_returned_variables(returned_variables)

        if associator_CIM_DirectoryContainsFile in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_DirectoryContainsFile]
            assert isinstance(associated_instance, (Sparql_CIM_DataFile, Sparql_CIM_Directory))
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)

            return_values_list = []

            if predicate_Name in associated_instance.m_properties:
                dir_path_variable = associated_instance.m_properties[predicate_Name]
                sys.stderr.write("dir_path_variable=%s\n" % dir_path_variable)
                sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables dir_path_variable=%s\n" % dir_path_variable)
            else:
                # This creates a temporary variable to store the name because
                # it might be necessary to identify this associated instance.
                # This is needed for all properties of the ontology.
                variable_name = str(associated_instance.m_variable) + "_dummy_subname"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associated_instance.m_properties[predicate_Name] = dir_path_variable
                sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables Created dummy variable:%s\n" % variable_name)

            def add_sub_node(sub_node_str, cim_class, sub_path_name):
                # print("Sparql_CIM_Directory.FetchAllVariables add_sub_node ", sub_node_str, "sub_path_name=", sub_path_name)
                # WARNING("Sparql_CIM_Directory.FetchAllVariables add_sub_node %s / path=%s" % (sub_node_str, sub_path_name))
                assert cim_class in (class_CIM_Directory, class_CIM_DataFile)
                sub_node_uri_ref = rdflib.term.URIRef(sub_node_str)
                graph.add((sub_node_uri_ref, rdflib.namespace.RDF.type, cim_class))
                #sub_uri_ref_list.append(sub_node_uri_ref)
                sub_path_name_url = rdflib.term.Literal(sub_path_name)
                graph.add((sub_node_uri_ref, predicate_Name, sub_path_name_url))
                graph.add((node_uri_ref, associator_CIM_DirectoryContainsFile, sub_node_uri_ref))

                if isinstance(dir_path_variable, rdflib.term.Variable):
                    return_values_list.append((sub_node_uri_ref, sub_path_name_url))
                else:
                    return_values_list.append((sub_node_uri_ref,))
                    assert isinstance(dir_path_variable, rdflib.term.Literal)
                    #print("Associated object Name is literal:", dir_path_variable)

            sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables file_path=%s\n" % file_path)
            for root_dir, dir_lists, files_list in os.walk(file_path):
                if associated_instance.m_class_name == "CIM_Directory":
                    for one_file_name in dir_lists:
                        sub_path_name = os.path.join(root_dir, one_file_name)
                        # This must be a directory, possibly unreadable due to access rights.
                        assert os.path.isdir(sub_path_name)
                        sub_node_str = "Machine:CIM_Directory?Name=" + sub_path_name
                        add_sub_node(sub_node_str, class_CIM_Directory, sub_path_name)
                elif associated_instance.m_class_name == "CIM_DataFile":
                    for one_file_name in files_list:
                        sub_path_name = os.path.join(root_dir, one_file_name)
                        sys.stderr.write("sub_path_name=%s\n" % sub_path_name)
                        # This must be a file, possibly unreadable due to access rights, or a symbolic link.
                        assert is_usable_file(sub_path_name)

                        sub_node_str = "Machine:CIM_DataFile?Name=" + sub_path_name
                        add_sub_node(sub_node_str, class_CIM_DataFile, sub_path_name)
                else:
                    raise Exception("Cannot happen")
                # Loop on first level only.
                break

            #sys.stderr.write("Sparql_CIM_Directory.FetchAll return_values_list=%s\n" % return_values_list)
            if isinstance(dir_path_variable, rdflib.term.Variable):
                #sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables Returning variables pair:%s\n" % associated_instance.m_variable)
                returned_variables[(associated_instance.m_variable, dir_path_variable)] = return_values_list
                check_returned_variables(returned_variables)
            else:
                #sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables Returning variable:%s\n" % associated_instance.m_variable)
                returned_variables[(associated_instance.m_variable,)] = return_values_list
                check_returned_variables(returned_variables)

            #sys.stderr.write("Sparql_CIM_Directory.FetchAllVariables returned_variables=%s\n" % returned_variables)

        # TODO: If there are no properties and no directory and no sub-files or sub-directories,
        # TODO: this should return ALL DIRECTORIES OF THE FILE SYSTEM.

        return returned_variables


class Sparql_CIM_Process(Sparql_CIM_Object):
    def __init__(self, class_name, node):
        super(Sparql_CIM_Process, self).__init__(class_name, node, ["Handle"])

    # Several properties can be used to return one or several objects.
    # TODO: We could use several properties at one: It is difficult to generalise.
    class PropertyDefinition:
        class property_definition_Handle:
            s_property_node = predicate_Handle

            def IfLiteralOrDefinedVariable(self, node_value):
                process_id = int(str(node_value))
                parent_process_pid =  psutil.Process(process_id).ppid()
                #parent_process_pid_node = rdflib.term.Literal(parent_process_pid)

                return (predicate_Handle, predicate_ParentProcessId), [(node_value, rdflib.term.Literal(parent_process_pid))]

        class property_definition_ParentProcessId:
            s_property_node = predicate_ParentProcessId

            def IfLiteralOrDefinedVariable(self, node_value):
                ppid = int(str(node_value))
                list_values = [
                    (rdflib.term.Literal(child_process.pid), node_value)
                    for child_process in psutil.Process(ppid).children(recursive=False)]
                return (predicate_Handle, predicate_ParentProcessId), list_values

        g_properties = [
            property_definition_Handle(),
            property_definition_ParentProcessId()
        ]

    # If no property is usable, this returns all objects.
    # This can work only for some classes, if there are not too many objects.
    def GetAllObjects(self):
        sys.stderr.write("Sparql_CIM_Process.GetAllObjects: Getting all processes\n")
        result_list = []

        list_values = [
            (rdflib.term.Literal(proc.pid), rdflib.term.Literal(proc.ppid()))
            for proc in psutil.process_iter()]
        return (predicate_Handle, predicate_ParentProcessId), list_values

    # This returns key-value pairs defining objects.
	# It returns all properties defined in the instance,
	# not only the properties of the ontology.
    def GetListOfOntologyProperties(self, variables_context):
        sys.stderr.write("GetListOfOntologyProperties\n")
        for one_property in self.PropertyDefinition.g_properties:
            sys.stderr.write("    GetListOfOntologyProperties one_property=%s\n" % one_property.s_property_node)
            if one_property.s_property_node in self.m_properties:
                node_value = self.GetNodeValue(one_property.s_property_node, variables_context)
                if node_value:
                    assert isinstance(node_value, rdflib.term.Literal)
                    url_nodes_list = one_property.IfLiteralOrDefinedVariable(node_value)
                    return url_nodes_list
        sys.stderr.write("GetListOfOntologyProperties leaving: Cannot find anything.\n")
        return None, None

    def CreateURIRef(self, graph, class_name, class_node, dict_predicates_to_values):
        url_as_str = "Machine:" + class_name
        delimiter = "?"
        for node_predicate, node_value in dict_predicates_to_values.items():
            predicate_name = str(node_predicate)[len(survol_url):]
            str_value = str(node_value)
            url_as_str += delimiter + "%s=%s" % (predicate_name, str_value)
            delimiter = "."
        sys.stderr.write("CreateURIRef url_as_str=%s\n" % url_as_str)
        node_uri_ref = rdflib.term.URIRef(url_as_str)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_node))

        for node_predicate, node_value in dict_predicates_to_values.items():
            assert isinstance(node_value, rdflib.term.Literal)
            graph.add((node_uri_ref, node_predicate, node_value))
        return node_uri_ref

    # Given the process id, it creates the file representing the executable being run.
    def DefineExecutableFromProcess(self, variables_context, process_id, graph, returned_variables, node_uri_ref):
        sys.stderr.write("Sparql_CIM_Process.DefineExecutableFromProcess process_id=%d\n" % process_id)
        if associator_CIM_ProcessExecutable in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
            assert isinstance(associated_instance, Sparql_CIM_DataFile)
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)
            assert isinstance(process_id, int)

            # This calculates the variable which defines the executable node.
            assert associated_instance.m_variable not in variables_context

            # TODO: This could also explore DLLs, not only the main executable.
            executable_path = psutil.Process(process_id).exe()
            executable_path_node = rdflib.term.Literal(executable_path)

            associated_instance_url = self.CreateURIRef(graph, "CIM_DataFile", class_CIM_DataFile,
                         {predicate_Name: executable_path_node})

            graph.add((node_uri_ref, associator_CIM_ProcessExecutable, associated_instance_url))

            if predicate_Name in associated_instance.m_properties:
                dir_path_variable = associated_instance.m_properties[predicate_Name]
                assert isinstance(dir_path_variable, rdflib.term.Variable)
            else:
                # This property must be created, to make the directory usable,
                # for example to get its other properties.
                # Generally speaking, this must be done for all properties of the ontology.
                variable_name = str(associated_instance.m_variable) + "_dummy_name"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associated_instance.m_properties[predicate_Name] = dir_path_variable

            if isinstance(dir_path_variable, rdflib.term.Variable):
                assert (associated_instance, dir_path_variable) not in returned_variables
                returned_variables[(associated_instance.m_variable, dir_path_variable)] = [
                    (associated_instance_url, executable_path_node)]
                check_returned_variables(returned_variables)
            else:
                assert associated_instance.m_variable not in returned_variables
                returned_variables[associated_instance.m_variable] = [associated_instance_url]
                check_returned_variables(returned_variables)
            graph.add((associated_instance_url, predicate_Name, executable_path_node))

    # Given a file name, it returns all processes executing it.
    def GetProcessesFromExecutable(self, graph, variables_context):

        sys.stderr.write("Sparql_CIM_Process.GetProcessesFromExecutable executable=%s\n" % sys.executable)
        associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
        assert isinstance(associated_instance, Sparql_CIM_DataFile)
        assert isinstance(associated_instance.m_variable, rdflib.term.Variable)
        assert associated_instance.m_variable in variables_context
        associated_executable_node = variables_context[associated_instance.m_variable]
        assert isinstance(associated_executable_node, rdflib.term.URIRef)

        sys.stderr.write("Sparql_CIM_Process.GetProcessesFromExecutable variables_context=%s\n" % variables_context)
        sys.stderr.write("associated_instance.m_variable=%s\n" % associated_instance.m_variable)
        executable_node = associated_instance.GetNodeValue(predicate_Name, variables_context)
        assert isinstance(executable_node, rdflib.term.Literal)
        executable_path = str(executable_node)

        # Because of backslashes transformed into slashes, which is necessary because of Sparql.
        executable_path = os.path.normpath(executable_path)
        if is_platform_linux:
            executable_path = os.path.realpath(executable_path)
            sys.stderr.write("executable_path=%s\n" % executable_path)

        process_urls_list = []
        for one_process in psutil.process_iter():
            try:
                process_executable = one_process.exe()
            except psutil.AccessDenied as exc:
                sys.stderr.write("GetProcessesFromExecutable Caught:%s\n" % str(exc))
                continue
            # print("process_executable=", process_executable, "executable_path=", executable_path)
            # With pytest as a command line: "c:\python27\python.exe" != "C:\Python27\python.exe"

            # On Linux, it might be a symbolic link: /usr/bin/python3 and /usr/bin/python3.6
            if equal_paths(executable_path, process_executable):
                process_url = self.CreateURIRef(
                    graph, "CIM_Process", class_CIM_Process,
                    {predicate_Handle: rdflib.term.Literal(one_process.pid)})
                sys.stderr.write("Adding process %s\n" % str(process_url))
                graph.add((process_url, associator_CIM_ProcessExecutable, associated_executable_node))
                process_urls_list.append(process_url)
        return process_urls_list
        sys.stderr.write("GetProcessesFromExecutable process_urls_list=%\n" % str(process_urls_list))

    def FetchAllVariables(self, graph, variables_context):
        sys.stderr.write("Sparql_CIM_Process.FetchAllVariables variables_context=%s\n" % str(variables_context))
        properties_tuple, url_nodes_list = self.GetListOfOntologyProperties(variables_context)

        returned_variables = {}

        if isinstance(url_nodes_list, list) and len(url_nodes_list) == 0:
            sys.stderr.write("FetchAllVariables No such process with self.m_properties:%s\n" % str(self.m_properties))
            # No such process.
            return returned_variables

        # If no process was found with the properties, try with the associator.
        if associator_CIM_ProcessExecutable in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
            if associated_instance.m_variable in variables_context:
                if url_nodes_list is not None:
                    raise Exception("BUG: Contradiction with non-empty processes list")
                node_uri_refs_list = self.GetProcessesFromExecutable(graph, variables_context)
                returned_variables[(self.m_variable,)] = [(node_uri_refs,) for node_uri_refs in node_uri_refs_list]
                check_returned_variables(returned_variables)
                return returned_variables

        if not url_nodes_list:
            # Get all objects by default.
            properties_tuple, url_nodes_list = self.GetAllObjects()

        # The object creation has evaluated properties of these objects.
        # Some of these properties might be mapped to variables which are not in used yet.
        # Their values must be returned, so they will be part of the next variables contexts.
        assert isinstance(url_nodes_list, list)
        properties_indices = []
        for index_property, one_property in enumerate(properties_tuple):
            # Maybe this property is defined in the generated objects but not in the instance.
            if one_property in self.m_properties:
                prop_value = self.m_properties[one_property]
                if isinstance(prop_value, rdflib.term.Variable) and prop_value not in variables_context:
                    properties_indices.append(index_property)
        new_properties_tuple = tuple(self.m_properties[properties_tuple[index_property]] for index_property in properties_indices)
        new_values_list = [tuple(value_tuple[index_property] for index_property in properties_indices) for value_tuple in url_nodes_list]
        if properties_indices:
            returned_variables[new_properties_tuple] = new_values_list
            check_returned_variables(returned_variables)


        node_uri_refs_list = []

        for values_tuple in url_nodes_list:
            assert len(values_tuple) == len(properties_tuple)
            properties_dict = dict(zip(properties_tuple, values_tuple))
            node_uri_ref = self.CreateURIRef(graph, "CIM_Process", class_CIM_Process, properties_dict)
            node_uri_refs_list.append((node_uri_ref,))

            process_id = int(properties_dict[predicate_Handle])
            self.DefineExecutableFromProcess(variables_context, process_id, graph, returned_variables, node_uri_ref)

        assert isinstance(self.m_variable, rdflib.term.Variable)
        assert self.m_variable not in returned_variables
        returned_variables[(self.m_variable,)] = node_uri_refs_list
        check_returned_variables(returned_variables)
        return returned_variables

def CreateSparql_CIM_Object(class_name, the_subject):
    class_name_to_class = {
        "CIM_DataFile":Sparql_CIM_DataFile,
        "CIM_Directory": Sparql_CIM_Directory,
        "CIM_Process": Sparql_CIM_Process,
    }

    the_class = class_name_to_class[class_name]
    the_instance = the_class(class_name, the_subject)
    return the_instance

################################################################################


def _wmi_load_ontology():
    # classes_map[class_name] = {"base_class": base_class_name, "class_description": text_descr}
    # map_attributes[prop_obj.name] = { "predicate_type": prop_obj.type,"predicate_domain": class_name}
    global wmiExecutor

    import lib_wmi
    if _wmi_load_ontology.classes_map is None:
        _wmi_load_ontology.classes_map, _wmi_load_ontology.attributes_map = lib_ontology_tools.ManageLocalOntologyCache(
            "wmi", lib_wmi.ExtractWmiOntologyLocal)
        assert _wmi_load_ontology.classes_map
        assert _wmi_load_ontology.attributes_map
        wmiExecutor = lib_wmi.WmiSparqlExecutor()

_wmi_load_ontology.classes_map = None
_wmi_load_ontology.attributes_map = None

wmiExecutor = None

class Sparql_WMI_GenericObject(Sparql_CIM_Object):
    def __init__(self, class_name, node):
        _wmi_load_ontology()

        # This contains the leys of the class, for example["Handle"] if Win32_Process.
        ontology_keys = _wmi_load_ontology.classes_map[class_name]["class_keys_list"]
        super(Sparql_WMI_GenericObject, self).__init__(class_name, node, ontology_keys)

        # We could also use the ontology stored in RDF, but by sticking to the data structure created
        # from WMI, no information is lost, even if the container.
        self.m_class_node = lib_kbase.RdfsPropertyNode(class_name)

    def IteratorToObjects(self, rdflib_graph, iterator_objects):
        sys.stderr.write("IteratorToObjects\n")

        # Set by the first row.
        list_variables = []

        # All the used properties of the object, variables or literals.
        # This is used to add nodes to the rdf graph. All properties must
        # be added, to be processed by Sparql.
        property_names_used = []

        list_current_values = []
        sys.stderr.write("IteratorToObjects %s self.m_properties.keys()=%s\n" % (str(self.m_variable), str(self.m_properties)))

        for object_path, dict_key_values in iterator_objects:

            if not list_variables:
                # The first object is used to create the list of attributes.
                list_variables.append(self.m_variable)
                for wql_key_node, wql_value_dummy in dict_key_values.items():
                    #sys.stderr.write("IteratorToObjects wql_key_node=%s\n" % wql_key_node)
                    assert isinstance(wql_key_node, rdflib.term.URIRef)
                    if wql_key_node not in self.m_properties:
                        continue
                    wql_variable = self.m_properties[wql_key_node]
                    property_names_used.append(wql_key_node)
                    if isinstance(wql_variable, rdflib.term.Variable):
                        list_variables.append(wql_variable)
                    else:
                        dummy_variable_name = "temptemptemp" + "_dummy_subname"
                        dummy_variable_node = rdflib.term.Variable(dummy_variable_name)
                        list_variables.append(dummy_variable_node)
                assert all((isinstance(one_variable, rdflib.term.Variable) for one_variable in list_variables))

            # The Sparql query is:
            # { ?url_proc survol:Handle %d  .
            #  ?url_proc rdf:type survol:CIM_Process . }
            # WMI returns object_path = '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="11568"'
            # Survol object URL must be like: http://rchateau-hp:8000/survol/entity.py?xid=CIM_Process.Handle=6936
            # Therefore, the WMI path cannot be used "as is", but instead use the original self.m_class_name.
            # sys.stderr.write("IteratorToObjects object_path=%s\n" % object_path)
            # sys.stderr.write("IteratorToObjects dict_key_values.keys()=%s\n"
            #                 % [lib_properties.PropToQName(one_uri_ref) for one_uri_ref in dict_key_values])
            uri_key_values = {}
            wmi_class_keys = self.class_keys()
            for one_class_key in wmi_class_keys:
                one_class_key_node = lib_kbase.RdfsPropertyNode(one_class_key)
                uri_key_values[one_class_key] = dict_key_values[one_class_key_node]
            node_uri_ref = lib_common.gUriGen.UriMakeFromDict(self.m_class_name, uri_key_values)

            rdflib_graph.add((node_uri_ref, rdflib.namespace.RDF.type, self.m_class_node))

            # The node of the path is always returned as first element.
            variable_values_list = [node_uri_ref,]
            for wql_key_node in property_names_used:
                assert isinstance(wql_key_node, rdflib.term.URIRef)
                wql_value = dict_key_values[wql_key_node]
                assert isinstance(wql_value, lib_util.scalar_data_types)
                variable_values_list.append(wql_value)
                wql_value_node = rdflib.term.Literal(wql_value)
                rdflib_graph.add((node_uri_ref, wql_key_node, wql_value_node))
            variable_values_tuple = tuple(variable_values_list)
            list_current_values.append(variable_values_tuple)

        sys.stderr.write("IteratorToObjects list_variables=%s\n" % list_variables)
        assert all((isinstance(one_variable, rdflib.term.Variable) for one_variable in list_variables))
        tuple_variables = tuple(list_variables)
        returned_variables = {tuple_variables: list_current_values}
        sys.stderr.write("IteratorToObjects END\n\n")
        check_returned_variables(returned_variables)
        return returned_variables


    def class_keys(self):
        wmi_class_keys = _wmi_load_ontology.classes_map[self.m_class_name]["class_keys_list"]
        assert all([isinstance(one_class_key, lib_util.six_text_type) for one_class_key in wmi_class_keys])
        return wmi_class_keys

    def SelectWmiObjectFromProperties(self, graph, variables_context, filtered_where_key_values):
        sys.stderr.write("SelectWmiObjectFromProperties filtered_where_key_values=%s\n" % str(filtered_where_key_values))
        iterator_objects = wmiExecutor.SelectObjectFromProperties(self.m_class_name, filtered_where_key_values)
        #####iterator_objects = list(iterator_objects)
        returned_variables = self.IteratorToObjects(graph, iterator_objects)
        check_returned_variables(returned_variables)
        sys.stderr.write("SelectWmiObjectFromProperties returned_variables=:\n")
        check_returned_variables(returned_variables)
        return returned_variables

    # This parses the Survol path to build WMI path which is very similar but not completely.
    def BuildWmiPathFromSurvolPath(self, variables_context):
        # survol_path = 'http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_Directory.Name=c:/a/b/c.txt'
        survol_path = variables_context[self.m_variable]
        _, _, shortened_path = survol_path.partition("?xid=")
        class_name, _, kw_pairs_as_str = shortened_path.partition(".")
        assert class_name == self.m_class_name
        # key-value pairs are separated by commas.

        entity_id_dict = lib_util.SplitMoniker(kw_pairs_as_str)

        associator_path = self.m_class_name + "." + ",".join(
            ('%s="%s"' % (prop_key, prop_value) for prop_key, prop_value in entity_id_dict.items())
        )

        sys.stderr.write("BuildWmiPathFromSurvolPath associator_path=%s\n" % associator_path)
        return associator_path

    def CreateAssociatorObjects(self, graph, variables_context):
        if self.m_associated:
            returned_variables = self.CreateAssociatorObjectsBidirectional(graph, variables_context, self.m_associated, 0)
            if returned_variables:
                sys.stderr.write("CreateAssociatorObjects m_associated. returned_variables=%s\n" % returned_variables.keys())
                check_returned_variables(returned_variables)
                return returned_variables
        if self.m_associators:
            returned_variables = self.CreateAssociatorObjectsBidirectional(graph, variables_context, self.m_associators, 1)
            if returned_variables:
                sys.stderr.write("CreateAssociatorObjects m_associators. returned_variables=%s\n" % returned_variables.keys())
                check_returned_variables(returned_variables)
                return returned_variables
        return {}

        # FIXME: What if both return values ???

    def CreateAssociatorObjectsBidirectional(self, graph, variables_context, assoc_list, role_index):

        # We might have several associators for one object.
        associator_urls_set = set()

        # Each associator must give values for all variables of this instance.
        keys_set_first_associator = None

        for associator_predicate, associated_instance in assoc_list.items():
            sys.stderr.write("CreateAssociatorObjectsBidirectional associator_predicate=%s associated_instance=%s\n"
                             % (associator_predicate, associated_instance))
            assert isinstance(associator_predicate, rdflib.term.URIRef)
            assert isinstance(associated_instance, Sparql_CIM_Object)

            associated_variable = associated_instance.m_variable
            assert isinstance(associated_variable, rdflib.term.Variable)
            sys.stderr.write("CreateAssociatorObjectsBidirectional role_index=%d associated_variable=%s\n" % (role_index, associated_variable))
            sys.stderr.write("CreateAssociatorObjectsBidirectional variables_context.keys()=%s\n" % str(variables_context.keys()))

            if associated_variable not in variables_context:
                sys.stderr.write("CreateAssociatorObjectsBidirectional Cannot find in variables_context: associated_variable=%s\n" % associated_variable)
                continue

            associator_name = lib_properties.PropToQName(associator_predicate)
            sys.stderr.write("CreateAssociatorObjectsBidirectional associator_name=%s\n" % associator_name)

            associated_variable_value = variables_context[associated_variable]
            sys.stderr.write("CreateAssociatorObjectsBidirectional associated_variable_value=%s\n" % associated_variable_value)
            assert isinstance(associated_variable_value, rdflib.URIRef)

            associator_path = associated_instance.BuildWmiPathFromSurvolPath(variables_context)

            iterator_objects = wmiExecutor.SelectBidirectionalAssociatorsFromObject(self.m_class_name, associator_name, associator_path, role_index)

            # This returns a map of one element only. The key is a tuple of variables.
            # The value is a list of tuples of the same size.
            returned_variables_one = self.IteratorToObjects(graph, iterator_objects)
            assert len(returned_variables_one) == 1
            first_key = next(iter(returned_variables_one))
            sys.stderr.write("CreateAssociatorObjectsBidirectional first_key=%s\n"
                             % [str(one_key) for one_key in first_key])

            if not first_key:
                sys.stderr.write("CreateAssociatorObjectsBidirectional no selection from %s/%s/%s/%s\n"
                                 % (self.m_class_name, associator_name, associator_path, role_index))
                continue

            if keys_set_first_associator:
                assert keys_set_first_associator == first_key
            else:
                keys_set_first_associator = first_key

            # The variable containing the url must be there.
            sys.stderr.write("first_key=%s\n" % str(first_key))
            sys.stderr.write("self.m_variable=%s\n" % self.m_variable)
            sys.stderr.flush()
            index_url_key = first_key.index(self.m_variable)
            # This is most probably the first key.
            assert index_url_key == 0
            assert first_key[index_url_key] == self.m_variable

            urls_list = returned_variables_one[first_key]
            sys.stderr.write("CreateAssociatorObjectsBidirectional urls_list=%s\n" % urls_list)
            assert isinstance(urls_list, list)

            # Now add the triples specifying the associator relation.
            for one_tuple_url in urls_list:
                assert isinstance(one_tuple_url, tuple)
                assert len(one_tuple_url) >= 1
                object_url = one_tuple_url[index_url_key]
                isinstance(object_url, rdflib.URIRef)
                if role_index == 0:
                    graph.add((associated_variable_value, associator_predicate, object_url))
                else:
                    graph.add((object_url, associator_predicate, associated_variable_value))

            sys.stderr.write("CreateAssociatorObjectsBidirectional returned_variables_one=%s\n" % returned_variables_one)

            if not associator_urls_set:
                associator_urls_set.update(urls_list)
            else:
                associator_urls_set = associator_urls_set.intersection(set(urls_list))
            sys.stderr.write("CreateAssociatorObjectsBidirectional returned_variables_set=%s\n" % associator_urls_set)
            # Because the variable is in the context, it is defined and its path is available.
            # Therefore, it is possible to fetch its associators only from the path.

        sys.stderr.write("associator_urls_set=%s\n" % associator_urls_set)
        associator_urls_list = list(associator_urls_set)
        if keys_set_first_associator:
            returned_variables = {keys_set_first_associator: associator_urls_list}
            check_returned_variables(returned_variables)
        else:
            returned_variables = {}
            sys.stderr.write("Nothing found in associators")
        return returned_variables

    def FetchAllVariables(self, graph, variables_context):
        filtered_where_key_values = dict()

        sys.stderr.write("FetchAllVariables variables_context=%s\n" % " , ".join("%s=%s" % (str(k), str(v)) for k, v in variables_context.items()))
        sys.stderr.write("FetchAllVariables self.m_properties=%s\n" % " , ".join("%s=%s" % (str(k), str(v)) for k, v in self.m_properties.items()))

        for predicate_node in self.m_properties:
            predicate_name = lib_properties.PropToQName(predicate_node)
            value_node = self.GetNodeValue(predicate_node, variables_context)
            sys.stderr.write("FetchAllVariables predicate_node=%s\n" % predicate_node)
            if value_node:
                filtered_where_key_values[predicate_name] = str(value_node)

        if filtered_where_key_values:
            returned_variables = self.SelectWmiObjectFromProperties(graph, variables_context, filtered_where_key_values)
            check_returned_variables(returned_variables)
            return returned_variables

        sys.stderr.write("associated:%d associators:%d\n" % (len(self.m_associated), len(self.m_associators)))

        if not filtered_where_key_values and not self.m_associated and not self.m_associators:
            sys.stderr.write("FetchAllVariables BEWARE FULL SELECT: %s\n" % self.m_class_name)
            returned_variables = self.SelectWmiObjectFromProperties(graph, variables_context, filtered_where_key_values)
            check_returned_variables(returned_variables)
            return returned_variables

        returned_variables = self.CreateAssociatorObjects(graph, variables_context)
        check_returned_variables(returned_variables)
        return returned_variables


def CreateSparql_CIM_Object_Wmi(class_name, the_subject):
    the_instance = Sparql_WMI_GenericObject(class_name, the_subject)
    return the_instance

################################################################################

# This takes the list of triples extracted from the Sparql query,
# and returns a list of instances of CIM classes, each of them
# containing the triples using its instances. The association is
# done based on the variable representing the instance.
# There might be several instances of the same class.
def part_triples_to_instances_dict_function(part, sparql_instance_creator):
    instances_dict = dict()
    sys.stderr.write("len(triples)=%d\n" % len(part.triples))
    for part_subject, part_predicate, part_object in part.triples:
        sys.stderr.write("    spo=%s %s %s\n" % (part_subject, part_predicate, part_object))
        if part_predicate == rdflib.namespace.RDF.type:
            if isinstance(part_subject, rdflib.term.Variable):
                class_as_str = str(part_object)
                sys.stderr.write("class_as_str=%s\n" % class_as_str)
                sys.stderr.write("survol_url=%s\n" % survol_url)
                if class_as_str.startswith(survol_url):
                    class_short = class_as_str[len(survol_url):]
                    sys.stderr.write("Class OK\n")
                    # sparql_instance_creator can also tell the difference between an associator and a property
                    instances_dict[part_subject] = sparql_instance_creator(class_short, part_subject)

    assert instances_dict
    sys.stderr.write("Created instances:%s\n" % instances_dict.keys())

    for part_subject, part_predicate, part_object in part.triples:
        current_instance = instances_dict.get(part_subject, None)
        if not current_instance: continue
        assert isinstance(current_instance, Sparql_CIM_Object)
        if part_predicate == rdflib.namespace.RDF.type: continue

        if part_predicate == rdflib.namespace.RDFS.seeAlso: continue

        associator_instance = instances_dict.get(part_object, None)
        if associator_instance:
            # If the variable of the object is also a subject variable defining an instance,
            # then it can only be an associator. This is why it is necessary to define the class
            # of a subject in a triplet. This is however necessary to instantiate it
            # and do any WMY query on it.
            assert isinstance(associator_instance, Sparql_CIM_Object)
            current_instance.m_associators[part_predicate] = associator_instance
            associator_instance.m_associated[part_predicate] = current_instance
        else:
            assert isinstance(part_object, (rdflib.term.Literal, rdflib.term.Variable))
            current_instance.m_properties[part_predicate] = part_object

    return instances_dict

# Debugging purpose only.
# This checks the content of something similar to:
# {(rdflib.term.Variable(u'url_execfile'),): [(rdflib.term.URIRef(u'http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_DataFile.Name=c:/windows/system32/urlmon.dll'),), (r...,)]}
def check_returned_variables(returned_variables):
    assert isinstance(returned_variables, dict)
    for first_key, values_list in returned_variables.items():
        assert isinstance(values_list, list)
        assert isinstance(first_key, tuple)
        # Maybe, several correlated variables of attributes of the same object.
        for one_value_tuple in values_list:
            assert isinstance(one_value_tuple, tuple)
            assert len(one_value_tuple) == len(first_key)
            for one_value in one_value_tuple:
                assert isinstance(one_value, (rdflib.term.Literal, rdflib.term.URIRef))

# The input is a set of {variable: list-of-values.
# It returns a set of {variable: value}, which is the set of combinations
# of all possible values for each variable.
# A variable can also be a tuple of rdflib variables.
# In this case, the values must also be tuples.
def product_variables_lists(returned_variables, iter_keys = None):
    check_returned_variables(returned_variables)
    try:
        if not iter_keys:
            iter_keys = iter(returned_variables.items())
        first_key, values_list = next(iter_keys)
        assert isinstance(values_list, list)

        max_display_count_values = 100
        #sys.stderr.write("product_variables_lists LOOP BEFORE\n")
        for one_dict in product_variables_lists(returned_variables, iter_keys):
            # sys.stderr.write("product_variables_lists len(values_list)=%d\n" % len(values_list))
            for one_value in values_list:
                new_dict = one_dict.copy()
                # This is one variable, or a tuple of variables of attributes of the same object.

                # Maybe, several correlated variables of attributes of the same object.
                assert isinstance(one_value, tuple)
                #sys.stderr.write("len(first_key)=%d\n" % len(first_key))
                #sys.stderr.write("len(one_value)=%d\n" % len(one_value))

                # This is to avoid the Travis message:
                # "The job exceeded the maximum log length, and has been terminated."
                if max_display_count_values > 0:
                    #sys.stderr.write("product_variables_lists first_key=%s\n" % ",".join(key_element for key_element in first_key))
                    #sys.stderr.write("product_variables_lists one_value=%s\n" % ",".join(value_element for value_element in one_value))
                    max_display_count_values -= 1
                    if max_display_count_values == 0:
                        sys.stderr.write("product_variables_lists STOP DISPLAYING EXCESSIVE NUMBER OF VALUES\n")
                assert len(first_key) == len(one_value)
                # Each key is a tuple of variables matched by each of the tuples of the list of values.
                assert all((isinstance(single_key, rdflib.term.Variable) for single_key in first_key))
                #sys.stderr.write("one_value.types:%s\n" % str([type(single_value) for single_value in one_value]))
                assert all((isinstance(single_value, (rdflib.term.Literal, rdflib.term.URIRef)) for single_value in one_value))

                new_dict.update(zip(first_key, one_value))

                #sys.stderr.write("product_variables_lists first_key=%s\n" % str(first_key))

                yield new_dict
        #sys.stderr.write("product_variables_lists LOOP AFTER\n")
    except StopIteration:
        yield {}

# An instance which is completely known and can be used as a starting point.
def findable_instance_key(instances_dict):
    sys.stderr.write("findable_instance_key\n")
    for instance_key, one_instance in instances_dict.items():
        one_instance.CalculateVariablesNumber()
        sys.stderr.write("    Key=%s Instance=%s\n" % (instance_key, one_instance))
        # Maybe we could return the instance with the greatest number of
        # literals ? Or the one whose implied instances are the fastest to find.
        # if one_instance.m_number_variables == 0 and one_instance.m_number_literals > 0:

        # We want to be able to retrieve at least one object, and as fast as possible.
        # This should check if wthe properties of the ontology are defined,
        # this is very important for WMI otherwise the performance can be awful.
        # On the other hand, in the general case, any property is enough, maybe none of them.
        # Realistically, in this examples, the ontologies properties are required.
        if one_instance.m_number_literals > 0:
            return instance_key

    # Could not find an instance with enough information.
    # The only possibility is to list all object. So, return the first instance.
    for instance_key, one_instance in instances_dict.items():
        return instance_key

# Exploration of the graph, starting by the ones which can be calculated without inference.
def visit_all_nodes(instances_dict):
    # Find a string point to walk the entire graph.
    start_instance_key = findable_instance_key(instances_dict)
    start_instance = instances_dict[start_instance_key]

    for instance_key, one_instance in instances_dict.items():
        one_instance.m_visited = False

    visited_instances = []
    unvisited_instances = set([one_instance for one_instance in instances_dict.values()])

    def instance_recursive_visit(one_instance):
        assert isinstance(one_instance, Sparql_CIM_Object)
        one_instance.m_visited = True
        visited_instances.append(one_instance)
        unvisited_instances.remove(one_instance)
        for sub_instance in one_instance.m_associators.values():
            if not sub_instance.m_visited:
                instance_recursive_visit(sub_instance)
        for sub_instance in one_instance.m_associated.values():
            if not sub_instance.m_visited:
                instance_recursive_visit(sub_instance)

    instance_recursive_visit(start_instance)

    def get_property_variables_list(one_instance):
        return set([property_value
                    for property_value in one_instance.m_properties.values()
                    if isinstance(property_value, rdflib.term.Variable)])

    assert len(visited_instances) + len(unvisited_instances) == len(instances_dict)
    all_properties_set = set.union(*[get_property_variables_list(one_instance) for one_instance in visited_instances])

    while True:
        closest_properties_set = None
        biggest_intersection_num = 0
        best_instance = None
        for sub_instance in unvisited_instances:
            sub_property_variables = get_property_variables_list(sub_instance)
            properties_intersection = all_properties_set.intersection(sub_property_variables)
            num_intersection = len(properties_intersection)
            if num_intersection >= biggest_intersection_num:
                biggest_intersection_num = num_intersection
                best_instance = sub_instance
                closest_properties_set = sub_property_variables
        if not best_instance:
            break
        all_properties_set.update(closest_properties_set)
        instance_recursive_visit(best_instance)

    if len(unvisited_instances) > 0:
        visited_instances += unvisited_instances
        WARNING("visit_all_nodes len(unvisited_instances)=%d", len(unvisited_instances))
    assert len(visited_instances) == len(instances_dict)
    return visited_instances


def custom_eval_function(ctx, part):
    return custom_eval_function_generic(ctx, part, CreateSparql_CIM_Object)

def custom_eval_function_wmi(ctx, part):
    return custom_eval_function_generic(ctx, part, CreateSparql_CIM_Object_Wmi)

def custom_eval_function_wbem(ctx, part):
    return custom_eval_function_generic(ctx, part, None)


# Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
def custom_eval_function_generic(ctx, part, sparql_instance_creator):
    # part.name = "SelectQuery", "Project", "BGP"
    if part.name == 'BGP':
        add_ontology(ctx.graph)

        sys.stderr.write("Instances:\n")
        instances_dict = part_triples_to_instances_dict_function(part, sparql_instance_creator)
        sys.stderr.write("Instances before sort:%d\n" % len(instances_dict))
        for instance_key, one_instance in instances_dict.items():
            sys.stderr.write("    Key=%s Instance=%s\n" % (instance_key, one_instance))

        visited_nodes = visit_all_nodes(instances_dict)
        assert len(instances_dict) == len(visited_nodes)

        # This is a dictionary of variables.
        variables_context = {}

        def display_variables_context(margin):
            for k, v in variables_context.items():
                sys.stderr.write("%s k=%s v=%s\n" % (margin, k, v))

        def recursive_instantiation(instance_index):
            if instance_index == len(visited_nodes):
                return
            margin = " " + str(instance_index) + "    " * (instance_index + 1)
            sys.stderr.write("recursive_instantiation: ix=%d visited nodes=%s\n"
                             % (instance_index, str([nod.m_variable for nod in visited_nodes])))

            # This returns the first instance which is completely kown, i.e. its parameters
            # are iterals, or variables whose values are known in the current context.
            one_instance = visited_nodes[instance_index]
            #sys.stderr.write(margin + "one_instance=%s\n" % one_instance)

            #sys.stderr.write(margin + "variables_context BEFORE\n")
            display_variables_context(margin)
            returned_variables = one_instance.FetchAllVariables(ctx.graph, variables_context)
            #sys.stderr.write(margin + "variables_context AFTER\n")
            display_variables_context(margin)
            check_returned_variables(returned_variables)

            #sys.stderr.write(margin + "returned_variables=%s\n" % str(returned_variables))

            variables_combinations_iter = product_variables_lists(returned_variables)
            variables_context_backup = variables_context.copy()
            for one_subset in variables_combinations_iter:
                variables_context.update(one_subset)
                #sys.stderr.write(margin + "recursive_instantiation instance_index=%d variables_context.keys()=%s\n"
                #                 % (instance_index, ",".join(str(key) for key in variables_context.keys())))
                #sys.stderr.write(margin + "recursive_instantiation instance_index=%d variables_context_backup.keys()=%s\n"
                #                 % (instance_index, ",".join(str(key) for key in variables_context_backup.keys())))
                #sys.stderr.write(margin + "recursive_instantiation one_subset=%s\n" % str(one_subset))
                recursive_instantiation(instance_index+1)
            variables_context.clear()
            variables_context.update(variables_context_backup)

        recursive_instantiation(0)

        INFO("Graph after recursive_instantiation: %d triples", len(ctx.graph))
        #sys.stderr.write("Graph after recursive_instantiation: %d triples\n" % len(ctx.graph))
        for s,p,o in ctx.graph:
            sys.stderr.write("   %s %s %s\n" % (s, p, o))
        sys.stderr.flush()

        # <type 'generator'>
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP

    raise NotImplementedError()

