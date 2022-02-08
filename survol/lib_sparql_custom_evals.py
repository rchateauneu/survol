from __future__ import print_function

import os
import sys
import six
import logging
import psutil
import rdflib
# Probably needed to force rdflib to load its plugins ?
# Apparently, this has to be loaded explicitly.
# Surprisingly it was not needed until this commit.
try:
    # Before rdflib 6.0
    import rdflib.plugins.memory
except ImportError:
    import rdflib.plugins.stores.memory
import rdflib.plugins.sparql

import lib_uris
import lib_util
import lib_common
import lib_ontology_tools
import lib_kbase
import lib_properties

# TODO: This should be conditional.
if lib_util.isPlatformWindows:
    import lib_wmi

################################################################################

# These classes and attributes are defined in WMI, WBEM and Survol ontologies.
class_CIM_Process = lib_kbase.class_node_uriref("CIM_Process")
class_CIM_Directory = lib_kbase.class_node_uriref("CIM_Directory")
class_CIM_DataFile = lib_kbase.class_node_uriref("CIM_DataFile")

predicate_Handle = lib_kbase.property_node_uriref("Handle")
predicate_Name = lib_kbase.property_node_uriref("Name")

################################################################################

# WMI defines this property only to WMI Win32_Process, not to CIM_Process.
# TODO: Survol must add it to be able to run Sparql queries using it.
predicate_ParentProcessId = lib_kbase.property_node_uriref("ParentProcessId")

# This applies only to Windows WMI ontology.

# TODO: This should not be used, or with a default suffix.
associator_CIM_DirectoryContainsFile = \
    lib_kbase.property_node_uriref("CIM_DirectoryContainsFile")
associator_CIM_DirectoryContainsFile_GroupComponent = \
    lib_kbase.property_node_uriref("CIM_DirectoryContainsFile.GroupComponent")
associator_CIM_DirectoryContainsFile_PartComponent = \
    lib_kbase.property_node_uriref("CIM_DirectoryContainsFile.PartComponent")

associator_CIM_ProcessExecutable = lib_kbase.property_node_uriref("CIM_ProcessExecutable")
associator_CIM_ProcessExecutable_Antecedent = \
    lib_kbase.property_node_uriref("CIM_ProcessExecutable.Antecedent")
associator_CIM_ProcessExecutable_Dependent = \
    lib_kbase.property_node_uriref("CIM_ProcessExecutable.Dependent")

################################################################################


def equal_paths(path_a, path_b):
    """This compares two file names irrespective of the platform."""
    # print("process_executable=", process_executable, "executable_path=", executable_path)
    # With pytest as a command line: "c:\python27\python.exe" != "C:\Python27\python.exe"

    # TODO: Now that paths are standardized, this conversation may be replaced by a plain string comparison,
    if lib_util.isPlatformLinux:
        return path_a == path_b
    elif lib_util.isPlatformWindows:
        return path_a.upper() == path_b.upper()
    else:
        raise Exception("Invalid platform")


def _is_readable_file(file_path):
    """For testing and debugging purpose. This is needed because file which are read protected can be listed,
    but cannot be read-opened. """

    if os.path.isfile(file_path):
        return True

    if lib_util.isPlatformWindows:
        try:
            with open(file_path):
                pass
        except IOError as exc:
            # Beware that the temp directory might contain shared memory "cubeb-shm" files, created by firefox.
            # "Permission denied" if the file exists but is read protected.
            return exc.errno == 13
        assert False, "_is_readable_file cannot open:" + file_path
        return False
    else:
        if os.path.islink(file_path):
            return True
    return False


def _current_function():
    """For debugging purpose. Returns the current function name"""
    return sys._getframe(1).f_code.co_name

################################################################################


class Sparql_CIM_Object(object):
    """
    This is the base class of a CIM object in the context of mapping Sparql queries to CIM.

    This mapping assumes objects made of a class, with attributes as a dictionary of key-values.
    For each class, there is a minimal set of keys which must have a value.
    This list of keys is the ontology of a class, that is, the description of its properties.
    The value types are always strings.

    CIM objects are mapped to a Sparql variable and can be searched. They are not only a set of literal values.
    Mapping Sparql to CIM implies for example  that CIM objects in these queries have an URI and a type.

    As a consequence, this mapping transforms a Sparql query into a sequence of the CIM Query Language (CQL),
    in its WMI or WBEM implementations, because they are structurally identical.

    The performance can be poor, but the returned information is always up-to-date, without an intermediary cache.
    This allows Sqarql to directly query information from the operating system.

    Optimisations are possible, for specific classes, by short-cutting WMI/WBEM.
    This is not done here, because the priority is to test the general case.
    Still, it is specialised for Sparql_CIM_DataFile and Sparql_CIM_Process.
    """
    def __init__(self, class_name, key_variable, ontology_keys):
        assert isinstance(key_variable, rdflib.term.Variable)
        self.m_variable = key_variable
        self.m_class_name = class_name
        self.m_associators = {}
        self.m_associated = {}
        self.m_properties = {}
        # For example ["Name", "Domain"]
        self._m_ontology_keys = ontology_keys
        # print("__init__ ontology_keys=", ontology_keys)

    def __str__(self):
        """This is used for debugging: It displays a string with the ontology key-value pairs. """
        def kw_to_str(property, value):
            # This strips the prefix of the string.
            property_str = str(property)[len(lib_kbase.survol_url):]
            value_str = str(value)
            return "%s=%s" % (property_str, value_str)

        # print("ka=", self.m_known_attributes.items())
        # This takes only the properties which are part of the ontology keys.
        kw_pairs_subset = [
            kw_to_str(property_key, self.m_properties.get(property_key, "UNKNOWN"))
            for property_key in self._m_ontology_keys]

        kw = ".".join(kw_pairs_subset)
        return "Sparql_CIM_Object:" + self.m_class_name + ":" + self.m_variable + ":" + kw

    def fetch_all_variables(self, graph, variables_context):
        """
        The role of this virtual function is to return a dictionary of pairs made of a variable,
        or a tuple of variables, and a list of its possible values, or a tuple of list of values.
        The caller uses these key-value pairs to create variables context and recursively instantiate objects,
        by trying all combinations.
        If variables are grouped in tuples, it means that they relate to the same object. For example:
        - a file path and its node id,
        - a process id and its command line,
        - a file size and creation date.
        FIXME: A single variable is not in a one-element tuple: This should be the case. See ONE_VARIABLE_TUPLE

        The long-term plan is to replace it by SelectEnumerationFromAttributes()/
        """
        logging.error("fetch_all_variables cannot be implemented in base class.")
        raise NotImplementedError(_current_function())

    def calculate_literals_number(self):
        """
        This calculates the number of known properties or associators.
        It is used to find which is the best instance to start with, when enumerating instances with the BGP.
        The bigger the number of literals, the easier it is.
        """
        self.m_number_literals = 0
        # FIXME: No need to list the associators which contains only instances. Logic should be different.
        for one_dict in [self.m_associators, self.m_associated, self.m_properties]:
            for key, value in one_dict.items():
                if isinstance(value, rdflib.term.Literal):
                    self.m_number_literals += 1

    def get_node_value(self, predicate_node, variables_context):
        """
        :param predicate_node: The node of a CIM property or similar.
        :param variables_context: Current variables and their values.
        :return: The literal value of this predicate for this object. It is a literal or a variable.
                This value is taken from the object or from the variables context.
        """
        try:
            predicate_variable = self.m_properties[predicate_node]
        except KeyError:
            logging.error("predicate node=%s not in properties=%s. Context keys=%s"
                          % (predicate_node, str(self.m_properties), str(variables_context.keys())))
            raise
        if isinstance(predicate_variable, rdflib.term.Literal):
            node_value = predicate_variable
        elif isinstance(predicate_variable, rdflib.term.Variable):
            if predicate_variable not in variables_context:
                logging.error("QUIT: predicate node=%s. predicate=%s not in context keys=%s"
                              % (predicate_node, predicate_variable, str(variables_context.keys())))
                return None
            node_value = variables_context[predicate_variable]
            logging.debug("predicate_variable=%s node_value=%s" % (predicate_variable, node_value))
            assert isinstance(node_value, rdflib.term.Literal)
        return node_value


class Sparql_CIM_DataFile(Sparql_CIM_Object):
    """
    This is used only for the Survol ontology: It is a specialisation of a CIM class with more capabilities
    than WMI which is not able to do some queries, for example selecting files based on their names.
    """
    def __init__(self, class_name, node):
        """ Same key "Name" for its base class CIM_Directory. """
        super(Sparql_CIM_DataFile, self).__init__(class_name, node, ["Name"])

    def create_file_node_from_properties(self, variables_context):
        """
        This returns the node of the filename which uniquely identifies the object. It uses the literal properties,
        or the variable properties if these variables have a value in the context.
        This returns None if it cannot be done.

        It is not private because it is also used by CIM_Directory for the same purpose.
        """

        if predicate_Name in self.m_properties:
            # The path name is enough to fully define a data file or a directory.
            return self.get_node_value(predicate_Name, variables_context)
        else:
            logging.error("Sparql_CIM_DataFile QUIT: No Name")
            return None

    def _fetch_from_directory(self, variables_context, file_path, graph, returned_variables, node_uri_ref):
        """
        This returns all files contained in the directory containing this file or dir path,
        if the proper associator is used.

        :param variables_context:
        :param file_path:
        :param graph: Where the results are inserted.
        :param returned_variables: A dict whose keys are tuple of variables, and the values are lists of the values
                                   that these variables can take. A scalar product explores all combinations.
        :param node_uri_ref: The node of the input file or dir.
        :return: Nothing.
        """
        check_returned_variables(returned_variables)
        # CIM_DirectoryContainsFile.GroupComponent or CIM_DirectoryContainsFile.PartComponent
        if associator_CIM_DirectoryContainsFile in self.m_associated:
            associator_instance = self.m_associated[associator_CIM_DirectoryContainsFile]
            assert isinstance(associator_instance, Sparql_CIM_Directory)
            assert isinstance(associator_instance.m_variable, rdflib.term.Variable)

            if associator_instance.m_variable in variables_context:
                logging.error("ALREADY DEFINED ?? %s" % associator_instance.m_variable)
                return

            dir_file_path = lib_util.standardized_file_path(os.path.dirname(file_path))
            dir_file_path_node = rdflib.term.Literal(dir_file_path)

            dir_node_str = "Machine:CIM_Directory?Name=" + dir_file_path
            associator_instance_url = rdflib.term.URIRef(dir_node_str)
            graph.add((associator_instance_url, rdflib.namespace.RDF.type, class_CIM_Directory))
            # CIM_DirectoryContainsFile.GroupComponent or CIM_DirectoryContainsFile.PartComponent
            graph.add((associator_instance_url, associator_CIM_DirectoryContainsFile, node_uri_ref))

            if predicate_Name in associator_instance.m_properties:
                dir_path_variable = associator_instance.m_properties[predicate_Name]
                assert isinstance(dir_path_variable, rdflib.term.Variable)
            else:
                # This property must be created, to make the directory usable, for example to get its other properties.
                # Generally speaking, this must be done for all properties of the ontology.
                variable_name = str(associator_instance.m_variable) + "_dummy_name"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associator_instance.m_properties[predicate_Name] = dir_path_variable

            if isinstance(dir_path_variable, rdflib.term.Variable):
                returned_variables[(associator_instance.m_variable, dir_path_variable)] = [(associator_instance_url, dir_file_path_node)]
                # TODO: Why doing this twice ?
                check_returned_variables(returned_variables)
            else:
                # TODO: Add a one-value tuple instead of a single variable: This would be more homogeneous.
                # TODO: See ONE_VARIABLE_TUPLE. The key should be a tuple.
                logging.error("m_variable SHOULD BE A TUPLE")
                returned_variables[associator_instance.m_variable] = [associator_instance_url]
                check_returned_variables(returned_variables)
            graph.add((associator_instance_url, predicate_Name, dir_file_path_node))

    def fetch_all_variables(self, graph, variables_context):
        node_file_path = self.create_file_node_from_properties(variables_context)
        if not node_file_path:
            return {}
        file_path = str(node_file_path)
        returned_variables = {}

        url_as_str = "Machine:CIM_DataFile?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_DataFile))

        # This variable can receive only one value here, so the list contains one element only.
        returned_variables[(self.m_variable,)] = [(node_uri_ref,)]
        check_returned_variables(returned_variables)

        # No need to add node_file_path in the results because,
        # if it is a variable, it is already in the context.
        assert isinstance(self.m_variable, rdflib.term.Variable)
        assert node_file_path
        graph.add((node_uri_ref, predicate_Name, node_file_path))

        assert associator_CIM_DirectoryContainsFile not in self.m_associators

        self._fetch_from_directory(variables_context, file_path, graph, returned_variables, node_uri_ref)

        # TODO: If there are no properties and no directory, this should return ALL FILES OF THE FILE SYSTEM.
        # TODO: Maybe return an iterator.

        check_returned_variables(returned_variables)
        return returned_variables


class Sparql_CIM_Directory(Sparql_CIM_DataFile):
    def __init__(self, class_name, node):
        super(Sparql_CIM_Directory, self).__init__(class_name, node)

    def fetch_all_variables(self, graph, variables_context):
        node_file_path = self.create_file_node_from_properties(variables_context)
        if not node_file_path:
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

        self._fetch_from_directory(variables_context, file_path, graph, returned_variables, node_uri_ref)
        check_returned_variables(returned_variables)

        if associator_CIM_DirectoryContainsFile in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_DirectoryContainsFile]
            assert isinstance(associated_instance, (Sparql_CIM_DataFile, Sparql_CIM_Directory))
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)

            return_values_list = []

            if predicate_Name in associated_instance.m_properties:
                dir_path_variable = associated_instance.m_properties[predicate_Name]
            else:
                # This creates a temporary variable to store the name because
                # it might be necessary to identify this associated instance.
                # This is needed for all properties of the ontology.
                variable_name = str(associated_instance.m_variable) + "_dummy_subname"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associated_instance.m_properties[predicate_Name] = dir_path_variable

            def add_sub_node(sub_node_str, cim_class, sub_path_name):
                # print("Sparql_CIM_Directory.fetch_all_variables add_sub_node ", sub_node_str, "sub_path_name=", sub_path_name)
                # logging.warning("Sparql_CIM_Directory.fetch_all_variables add_sub_node %s / path=%s" % (sub_node_str, sub_path_name))
                assert cim_class in (class_CIM_Directory, class_CIM_DataFile)

                # Frequent errors due to non-utf8 characters in filenames, for example with Python 2:
                # 'Machine:CIM_DataFile?Name=C:/Users/abcdxyz/AppData/Local/Temp/Vive le v\xe9lo.mp4'
                # UnicodeDecodeError: 'utf8' codec can't decode byte 0xe9 in position 72: invalid continuation byte
                try:
                    sub_node_uri_ref = rdflib.term.URIRef(sub_node_str)
                except UnicodeDecodeError:
                    logging.error("file=%s type=%s" % (sub_node_str, type(sub_node_str)))
                    raise
                graph.add((sub_node_uri_ref, rdflib.namespace.RDF.type, cim_class))
                #sub_uri_ref_list.append(sub_node_uri_ref)
                sub_path_name_url = rdflib.term.Literal(sub_path_name)
                graph.add((sub_node_uri_ref, predicate_Name, sub_path_name_url))
                # CIM_DirectoryContainsFile.GroupComponent or CIM_DirectoryContainsFile.PartComponent
                graph.add((node_uri_ref, associator_CIM_DirectoryContainsFile, sub_node_uri_ref))

                if isinstance(dir_path_variable, rdflib.term.Variable):
                    return_values_list.append((sub_node_uri_ref, sub_path_name_url))
                else:
                    return_values_list.append((sub_node_uri_ref,))
                    assert isinstance(dir_path_variable, rdflib.term.Literal)

            for root_dir, dir_lists, files_list in os.walk(file_path):
                if associated_instance.m_class_name == "CIM_Directory":
                    for one_file_name in dir_lists:
                        sub_path_name = lib_util.standardized_file_path(os.path.join(root_dir, one_file_name))
                        # This must be a directory, possibly unreadable due to access rights.
                        assert os.path.isdir(sub_path_name)
                        sub_node_str = "Machine:CIM_Directory?Name=" + sub_path_name
                        add_sub_node(sub_node_str, class_CIM_Directory, sub_path_name)
                elif associated_instance.m_class_name == "CIM_DataFile":
                    for one_file_name in files_list:
                        sub_path_name = lib_util.standardized_file_path(os.path.join(root_dir, one_file_name))
                        # This must be a file, possibly unreadable due to access rights, or a symbolic link.
                        if not _is_readable_file(sub_path_name):
                        # Another possible reason is the wrong encoding of a non-Ascii file name.
                            logging.error("File %s is not readable" % sub_path_name)
                            raise Exception("File %s is not readable" % sub_path_name)

                        sub_node_str = "Machine:CIM_DataFile?Name=" + sub_path_name
                        add_sub_node(sub_node_str, class_CIM_DataFile, sub_path_name)
                else:
                    raise Exception("Cannot happen")
                # Loop on first level only.
                break

            if isinstance(dir_path_variable, rdflib.term.Variable):
                returned_variables[(associated_instance.m_variable, dir_path_variable)] = return_values_list
                check_returned_variables(returned_variables)
            else:
                returned_variables[(associated_instance.m_variable,)] = return_values_list
                check_returned_variables(returned_variables)

        # TODO: If there are no properties and no directory and no sub-files or sub-directories,
        # TODO: this should return ALL DIRECTORIES OF THE FILE SYSTEM.

        return returned_variables


class Sparql_CIM_Process(Sparql_CIM_Object):
    def __init__(self, class_name, node):
        # This is the list of required attributes for this object.
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

    def GetAllObjects(self):
        """If no property is usable, this returns all objects.
        This can work only for some classes, if there are not too many objects."""
        logging.debug("Sparql_CIM_Process.GetAllObjects: Getting all processes")

        list_values = [
            (rdflib.term.Literal(proc.pid), rdflib.term.Literal(proc.ppid()))
            for proc in psutil.process_iter()]
        return (predicate_Handle, predicate_ParentProcessId), list_values

    def _get_list_of_ontology_properties(self, variables_context):
        """
        This returns key-value pairs defining objects.
        It returns all properties defined in the instance,
        not only the properties of the ontology.
        """
        logging.debug("_get_list_of_ontology_properties")
        for one_property in self.PropertyDefinition.g_properties:
            logging.debug("one_property=%s" % one_property.s_property_node)
            if one_property.s_property_node in self.m_properties:
                node_value = self.get_node_value(one_property.s_property_node, variables_context)
                if node_value:
                    assert isinstance(node_value, rdflib.term.Literal)
                    url_nodes_list = one_property.IfLiteralOrDefinedVariable(node_value)
                    return url_nodes_list
        logging.debug("_get_list_of_ontology_properties leaving: Cannot find anything.")
        return None, None

    def _create_uri_ref(self, graph, class_name, class_node, dict_predicates_to_values):
        url_as_str = "Machine:" + class_name
        delimiter = "?"
        for node_predicate, node_value in dict_predicates_to_values.items():
            predicate_name = str(node_predicate)[len(lib_kbase.survol_url):]
            str_value = str(node_value)
            url_as_str += delimiter + "%s=%s" % (predicate_name, str_value)
            delimiter = "."
        logging.debug("url_as_str=%s" % url_as_str)
        node_uri_ref = rdflib.term.URIRef(url_as_str)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_node))

        for node_predicate, node_value in dict_predicates_to_values.items():
            assert isinstance(node_value, rdflib.term.Literal)
            graph.add((node_uri_ref, node_predicate, node_value))
        return node_uri_ref

    def _define_executable_from_process(self, variables_context, process_id, graph, returned_variables, node_uri_ref):
        """Given the process id, it creates the file representing the executable being run."""
        logging.debug("Sparql_CIM_Process._define_executable_from_process process_id=%d" % process_id)
        if associator_CIM_ProcessExecutable in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
            assert isinstance(associated_instance, Sparql_CIM_DataFile)
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)
            assert isinstance(process_id, int)

            # This calculates the variable which defines the executable node.
            assert associated_instance.m_variable not in variables_context

            # TODO: This could also explore DLLs, not only the main executable.
            executable_path = lib_util.standardized_file_path(psutil.Process(process_id).exe())
            executable_path_node = rdflib.term.Literal(executable_path)

            associated_instance_url = self._create_uri_ref(graph, "CIM_DataFile", class_CIM_DataFile,
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
                # TODO: See ONE_VARIABLE_TUPLE
                ### assert isinstance(associated_instance.m_variable, tuple)
                returned_variables[associated_instance.m_variable] = [associated_instance_url]
                check_returned_variables(returned_variables)
            graph.add((associated_instance_url, predicate_Name, executable_path_node))

    def _get_processes_from_executable(self, graph, variables_context):
        """Given a file name, it returns all processes executing it."""

        associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
        assert isinstance(associated_instance, Sparql_CIM_DataFile)
        assert isinstance(associated_instance.m_variable, rdflib.term.Variable)
        assert associated_instance.m_variable in variables_context
        associated_executable_node = variables_context[associated_instance.m_variable]
        assert isinstance(associated_executable_node, rdflib.term.URIRef)

        executable_node = associated_instance.get_node_value(predicate_Name, variables_context)
        assert isinstance(executable_node, rdflib.term.Literal)
        executable_path = str(executable_node)

        # Because of backslashes transformed into slashes, which is necessary because of Sparql.
        executable_path = lib_util.standardized_file_path(executable_path)

        process_urls_list = []
        for one_process in psutil.process_iter():
            try:
                process_executable = lib_util.standardized_file_path(one_process.exe())
            except psutil.AccessDenied as exc:
                logging.error("_get_processes_from_executable Caught:%s" % str(exc))
                continue
            # print("process_executable=", process_executable, "executable_path=", executable_path)
            # With pytest as a command line: "c:\python27\python.exe" != "C:\Python27\python.exe"

            # On Linux, it might be a symbolic link: /usr/bin/python3 and /usr/bin/python3.6
            if equal_paths(executable_path, process_executable):
                process_url = self._create_uri_ref(
                    graph, "CIM_Process", class_CIM_Process,
                    {predicate_Handle: rdflib.term.Literal(one_process.pid)})
                graph.add((process_url, associator_CIM_ProcessExecutable, associated_executable_node))
                process_urls_list.append(process_url)
        return process_urls_list

    def fetch_all_variables(self, graph, variables_context):
        properties_tuple, url_nodes_list = self._get_list_of_ontology_properties(variables_context)

        returned_variables = {}

        if isinstance(url_nodes_list, list) and len(url_nodes_list) == 0:
            # No such process.
            return returned_variables

        # If no process was found with the properties, try with the associator.
        if associator_CIM_ProcessExecutable in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
            if associated_instance.m_variable in variables_context:
                if url_nodes_list is not None:
                    raise Exception("BUG: Contradiction with non-empty processes list")
                node_uri_refs_list = self._get_processes_from_executable(graph, variables_context)
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
        new_properties_tuple = tuple(
            self.m_properties[properties_tuple[index_property]]
            for index_property in properties_indices)
        new_values_list = [
            tuple(value_tuple[index_property]
                  for index_property in properties_indices)
            for value_tuple in url_nodes_list]
        if properties_indices:
            returned_variables[new_properties_tuple] = new_values_list
            check_returned_variables(returned_variables)

        node_uri_refs_list = []

        for values_tuple in url_nodes_list:
            assert len(values_tuple) == len(properties_tuple)
            properties_dict = dict(zip(properties_tuple, values_tuple))
            node_uri_ref = self._create_uri_ref(graph, "CIM_Process", class_CIM_Process, properties_dict)
            node_uri_refs_list.append((node_uri_ref,))

            process_id = int(properties_dict[predicate_Handle])
            self._define_executable_from_process(variables_context, process_id, graph, returned_variables, node_uri_ref)

        assert isinstance(self.m_variable, rdflib.term.Variable)
        assert self.m_variable not in returned_variables
        returned_variables[(self.m_variable,)] = node_uri_refs_list
        check_returned_variables(returned_variables)
        return returned_variables


class _sparql_model_CIM_Object_Survol:
    @staticmethod
    def write_ontology_to_graph(rdf_graph):
        if lib_util.isPlatformWindows:
            lib_ontology_tools.serialize_ontology_to_graph("wmi", lib_wmi.extract_specific_ontology_wmi, rdf_graph)
        # TODO: Should add WBEM if available and Linux.

        # There might be duplicate classes and properties with WMI, but they must not contradict.
        lib_ontology_tools.serialize_ontology_to_graph("survol", lib_util.extract_specific_ontology_survol, rdf_graph)

    @staticmethod
    def object_factory(class_name, the_subject):
        """
        This is a factory for the rdflib custom eval function which handles CIM objects created by Survol only.

        :param class_name: a CIM class name. Strictly speaking, it is redundant
                           because alreasy available in the URL.
        :param the_subject: The RDF url node of the object.
        :return: An instanciation of a derived class of Sparql_CIM_Object,
                modelling the object whose URL is passed as parameter.
        """
        class_name_to_class = {
            "CIM_DataFile": Sparql_CIM_DataFile,
            "CIM_Directory": Sparql_CIM_Directory,
            "CIM_Process": Sparql_CIM_Process,
        }

        the_class = class_name_to_class[class_name]

        # Si c'est une autre classe, renvoyer Sparql_WMI_GenericObject

        the_instance = the_class(class_name, the_subject)
        return the_instance

################################################################################


class Sparql_WMI_GenericObject(Sparql_CIM_Object):
    """
    This models any WMI object of any class.
    The urls are the same with object created by pure Survol classes.
    """

    if lib_util.isPlatformWindows:
        wmi_executor = lib_wmi.WmiSparqlExecutor()

        # The list of attributes of classes is needed.
        classes_map = lib_ontology_tools.get_ontology_classes("wmi", lib_wmi.extract_specific_ontology_wmi)

    def __init__(self, class_name, node):
        assert isinstance(node, rdflib.term.Variable)

        # This contains the leys of the class, for example["Handle"] if Win32_Process.
        ontology_keys = Sparql_WMI_GenericObject.classes_map[class_name]["class_keys_list"]
        super(Sparql_WMI_GenericObject, self).__init__(class_name, node, ontology_keys)

        # We could also use the ontology stored in RDF, but by sticking to the data structure created
        # from WMI, no information is lost, even if the container.
        self.m_class_node = lib_kbase.property_node_uriref(class_name)

    def _iterator_to_objects(self, rdflib_graph, iterator_objects):
        # Set by the first row.
        list_variables = []

        # All the used properties of the object, variables or literals.
        # This is used to add nodes to the rdf graph. All properties must
        # be added, to be processed by Sparql.
        property_names_used = []

        list_current_values = []

        for object_path, dict_key_values in iterator_objects:
            logging.debug("object_path=%s" % object_path)
            if not list_variables:
                # The first object is used to create the list of attributes.
                list_variables.append(self.m_variable)
                for wql_key_node, wql_value_dummy in dict_key_values.items():
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
            # WMI returns object_path = '\\MYMACHINE\root\cimv2:Win32_Process.Handle="11568"'
            # Survol object URL must be like: http://mymachine:8000/survol/entity.py?xid=CIM_Process.Handle=6936
            # Therefore, the WMI path cannot be used "as is", but instead use the original self.m_class_name.
            uri_key_values = {}
            wmi_class_keys = self.class_keys()
            for one_class_key in wmi_class_keys:
                one_class_key_node = lib_kbase.property_node_uriref(one_class_key)
                uri_key_values[one_class_key] = dict_key_values[one_class_key_node]
            node_uri_ref = lib_uris.gUriGen.node_from_dict(self.m_class_name, uri_key_values)

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

        assert all((isinstance(one_variable, rdflib.term.Variable) for one_variable in list_variables))
        tuple_variables = tuple(list_variables)
        returned_variables = {tuple_variables: list_current_values}
        check_returned_variables(returned_variables)
        return returned_variables

    def class_keys(self):
        wmi_class_keys = Sparql_WMI_GenericObject.classes_map[self.m_class_name]["class_keys_list"]
        assert all([isinstance(one_class_key, six.text_type) for one_class_key in wmi_class_keys])
        return wmi_class_keys

    def _select_wmi_object_from_properties(self, graph, variables_context, filtered_where_key_values):
        logging.debug("class=%s filtered_where_key_values=%s" % (self.m_class_name, str(filtered_where_key_values)))
        iterator_objects = Sparql_WMI_GenericObject.wmi_executor.SelectObjectFromProperties(
            self.m_class_name, filtered_where_key_values)
        returned_variables = self._iterator_to_objects(graph, iterator_objects)
        check_returned_variables(returned_variables)
        check_returned_variables(returned_variables)
        return returned_variables

    def _build_wmi_path_from_survol_path(self, variables_context):
        """ This parses the Survol path to build WMI path which is very similar but not completely:
        survol_path = 'http://mymachine:80/LocalExecution/entity.py?xid=CIM_Directory.Name=c:/a/b/c.txt'

        Typical transformation of the path:
        associator_path=CIM_Process.Handle="9332"
        shortened_path=CIM_Process.Handle=9332

        associator_path=CIM_DataFile.Name="C:/Windows/System32/ntdll.dll"
        shortened_path=CIM_DataFile.Name=C:/Windows/System32/ntdll.dll
        """

        survol_path = variables_context[self.m_variable]
        _, _, shortened_path = survol_path.partition("?xid=")

        # key-value pairs are separated by commas.


        associator_path = lib_wmi.reformat_path_for_wmi(shortened_path)
        return associator_path

    def _create_associator_objects(self, graph, variables_context):
        if self.m_associated:
            returned_variables = self._create_associator_objects_bidirectional(
                graph, variables_context, self.m_associated, 0)
            if returned_variables:
                check_returned_variables(returned_variables)
                return returned_variables
        if self.m_associators:
            returned_variables = self._create_associator_objects_bidirectional(
                graph, variables_context, self.m_associators, 1)
            if returned_variables:
                check_returned_variables(returned_variables)
                return returned_variables
        return {}

        # FIXME: What if both return values ???

    def _create_associator_objects_bidirectional(self, graph, variables_context, assoc_list, role_index):

        # We might have several associators for one object.
        associator_urls_set = set()

        # Each associator must give values for all variables of this instance.
        keys_set_first_associator = None

        for associator_predicate, associated_instance in assoc_list.items():
            assert isinstance(associator_predicate, rdflib.term.URIRef)
            assert isinstance(associated_instance, Sparql_CIM_Object)

            associated_variable = associated_instance.m_variable
            assert isinstance(associated_variable, rdflib.term.Variable)

            if associated_variable not in variables_context:
                continue

            associator_name = lib_properties.PropToQName(associator_predicate)

            associated_variable_value = variables_context[associated_variable]
            assert isinstance(associated_variable_value, rdflib.URIRef)

            associator_path = associated_instance._build_wmi_path_from_survol_path(variables_context)

            iterator_objects = Sparql_WMI_GenericObject.wmi_executor.SelectBidirectionalAssociatorsFromObject(
                self.m_class_name, associator_name, associator_path, role_index)

            # This returns a map of one element only. The key is a tuple of variables.
            # The value is a list of tuples of the same size.
            returned_variables_one = self._iterator_to_objects(graph, iterator_objects)
            assert len(returned_variables_one) == 1
            first_key = next(iter(returned_variables_one))

            if not first_key:
                continue

            if keys_set_first_associator:
                assert keys_set_first_associator == first_key
            else:
                keys_set_first_associator = first_key

            # The variable containing the url must be there.
            index_url_key = first_key.index(self.m_variable)
            # This is most probably the first key.
            assert index_url_key == 0
            assert first_key[index_url_key] == self.m_variable

            urls_list = returned_variables_one[first_key]
            assert isinstance(urls_list, list)

            # Now add the triples specifying the associator relation.
            for one_tuple_url in urls_list:
                assert isinstance(one_tuple_url, tuple)
                assert len(one_tuple_url) >= 1
                object_url = one_tuple_url[index_url_key]
                assert isinstance(object_url, rdflib.URIRef)
                if role_index == 0:
                    graph.add((associated_variable_value, associator_predicate, object_url))
                else:
                    graph.add((object_url, associator_predicate, associated_variable_value))

            if not associator_urls_set:
                associator_urls_set.update(urls_list)
            else:
                associator_urls_set = associator_urls_set.intersection(set(urls_list))
            # Because the variable is in the context, it is defined and its path is available.
            # Therefore, it is possible to fetch its associators only from the path.

        associator_urls_list = list(associator_urls_set)
        if keys_set_first_associator:
            returned_variables = {keys_set_first_associator: associator_urls_list}
            check_returned_variables(returned_variables)
        else:
            returned_variables = {}
            logging.debug("Nothing found in associators")
        return returned_variables

    def fetch_all_variables(self, graph, variables_context):
        filtered_where_key_values = dict()

        for predicate_node in self.m_properties:
            predicate_name = lib_properties.PropToQName(predicate_node)
            value_node = self.get_node_value(predicate_node, variables_context)
            if value_node:
                filtered_where_key_values[predicate_name] = str(value_node)

        if filtered_where_key_values:
            returned_variables = self._select_wmi_object_from_properties(
                graph, variables_context, filtered_where_key_values)
            check_returned_variables(returned_variables)
            return returned_variables

        if not filtered_where_key_values and not self.m_associated and not self.m_associators:
            logging.warning("fetch_all_variables BEWARE FULL SELECT: %s" % self.m_class_name)
            returned_variables = self._select_wmi_object_from_properties(
                graph, variables_context, filtered_where_key_values)
            check_returned_variables(returned_variables)
            return returned_variables

        returned_variables = self._create_associator_objects(graph, variables_context)
        check_returned_variables(returned_variables)
        return returned_variables


class _sparql_model_CIM_Object_Wmi:
    @staticmethod
    def write_ontology_to_graph(rdf_graph):
        lib_ontology_tools.serialize_ontology_to_graph("wmi", lib_wmi.extract_specific_ontology_wmi, rdf_graph)

    @staticmethod
    def object_factory(class_name, the_subject):
        """
        Given a class name and the rdflib node of an URL,
        it returns an object which contains the attributes of this CIM object,
        ready to ba handled in Sparql custom evals.
        """
        the_instance = Sparql_WMI_GenericObject(class_name, the_subject)
        return the_instance

################################################################################


def _part_triples_to_instances_dict_function(part, object_factory):
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
    """
    instances_dict = dict()
    logging.debug("len(triples)=%d" % len(part.triples))
    for part_subject, part_predicate, part_object in part.triples:
        logging.debug("    spo=%s %s %s" % (part_subject, part_predicate, part_object))
        if part_predicate == rdflib.namespace.RDF.type:
            if isinstance(part_subject, rdflib.term.Variable):
                class_as_str = str(part_object)
                logging.debug("class_as_str=%s" % class_as_str)
                logging.debug("survol_url=%s" % lib_kbase.survol_url)
                if class_as_str.startswith(lib_kbase.survol_url):
                    # This is the class name without the Survol prefix which is not useful here.
                    class_short = class_as_str[len(lib_kbase.survol_url):]
                    logging.debug("Class OK")
                    # object_factory can also tell the difference between an associator and a property
                    instances_dict[part_subject] = object_factory(class_short, part_subject)

    if not instances_dict:
        # If it does not contain any instance defined by a type which can be mapped to a WMI class,
        # then this query applies to non-instance content, which can only be the WMI ontology.
        # This ontology should be returned anyway: Classes, properties etc...
        logging.warning("No instance found. Possibly a meta-data query.")
        return instances_dict
        # raise Exception("No instance found")
    logging.debug("Created instances:%s" % instances_dict.keys())

    # Second pass on the BGP: The keys of instances_dict are URL variables whose values must be found.
    # TODO: This could be slightly faster because only the keys of instance_dict are of interest,
    # TODO: ... but this is a small list anyway.
    for part_subject, part_predicate, part_object in part.triples:
        current_instance = instances_dict.get(part_subject, None)
        if not current_instance:
            # This is not the pattern of a Survol instance,
            # so we do not care because we cannot do anything with it.
            continue
        assert isinstance(current_instance, Sparql_CIM_Object)
        if part_predicate == rdflib.namespace.RDF.type:
            # OK, this is a sSurvol object, as expected.
            continue

        if part_predicate == rdflib.namespace.RDFS.seeAlso:
            # This is a URL, for example of a script returning more data about this object.
            continue

        associator_instance = instances_dict.get(part_object, None)
        if associator_instance:
            # If the variable of the object is also a subject variable defining an instance,
            # then it can only be an associator. This is why it is necessary to define the class
            # of a subject in a triplet. This is however necessary to instantiate it
            # and do any WMI query on it.
            assert isinstance(associator_instance, Sparql_CIM_Object)
            current_instance.m_associators[part_predicate] = associator_instance
            associator_instance.m_associated[part_predicate] = current_instance
        else:
            assert isinstance(part_object, (rdflib.term.Literal, rdflib.term.Variable))
            current_instance.m_properties[part_predicate] = part_object

    return instances_dict


def check_returned_variables(returned_variables):
    """
    Debugging purpose only.
    This checks the content of something similar to:
    {
        (rdflib.term.Variable(u'url_execfile'),):
        [(rdflib.term.URIRef(u'http://myhost:80/LocalExecution/entity.py?xid=CIM_DataFile.Name=c:/windows/system32/urlmon.dll'),), (r...,)]}
    TODO: See ONE_VARIABLE_TUPLE
    """
    assert isinstance(returned_variables, dict)
    for first_key, values_list in returned_variables.items():
        assert isinstance(values_list, list)
        assert isinstance(first_key, tuple)
        # Maybe, several correlated variables of attributes of the same object.
        len_first_key = len(first_key)
        for one_value_tuple in values_list:
            assert isinstance(one_value_tuple, tuple)
            assert len(one_value_tuple) == len_first_key
            for one_value in one_value_tuple:
                assert isinstance(one_value, (rdflib.term.Literal, rdflib.term.URIRef))


def product_variables_lists(returned_variables, iter_keys=None):
    """
    The input is a set of {variable: list-of-values.
    It returns a set of {variable: value}, which is the set of combinations of all possible values for each variable.
    A variable can also be a tuple of rdflib variables.
    In this case, the values must also be tuples.
    This is used to explore all combinations of values when adding using custom evals in a Sparql query.

    This recursive function returns an iterator so the input can be quite large.
    """
    check_returned_variables(returned_variables)
    try:
        if not iter_keys:
            iter_keys = iter(returned_variables.items())
        first_key, values_list = next(iter_keys)
        assert isinstance(values_list, list)

        for one_dict in product_variables_lists(returned_variables, iter_keys):
            for one_value in values_list:
                new_dict = one_dict.copy()
                # This is one variable, or a tuple of variables of attributes of the same object.

                # Maybe, several correlated variables of attributes of the same object.
                assert isinstance(one_value, tuple)

                assert len(first_key) == len(one_value)
                # Each key is a tuple of variables matched by each of the tuples of the list of values.
                assert all((isinstance(single_key, rdflib.term.Variable) for single_key in first_key))
                assert all(
                    (isinstance(single_value, (rdflib.term.Literal, rdflib.term.URIRef))
                     for single_value
                     in one_value))

                # This receives new values for some variables only. The other variables are not touched.
                # A possible optimisation would be to avoid the copy of untouched key-value paris.
                new_dict.update(zip(first_key, one_value))

                yield new_dict
    except StopIteration:
        # Raised by next() and an iterator __next__() method to signal the end of iteration.
        yield {}


def _findable_instance_key(instances_dict):
    """
    This receives a dictionary whose key represents an object instance,
    and the value is the instance itself.
    Instance are CIM objects, and their attrobutes can be literal or variables.
    This functions returns an instance which is known and can be used as a starting point.
    Complety known, means that all attributes have "enough" literal values and do not need the rest
    of the Sparql query to be found.
    It can then be later used to give a value to variables.
    """
    logging.debug("_findable_instance_key")
    for instance_key, one_instance in instances_dict.items():
        one_instance.calculate_literals_number()
        logging.debug("    Key=%s Instance=%s" % (instance_key, one_instance))

        # We want to be able to retrieve at least one object, and as fast as possible.
        # This should check if the properties of the ontology are defined,
        # this is very important for WMI otherwise the performance can be awful.
        # On the other hand, in the general case, any property is enough, maybe none of them.
        # Realistically, in this examples, the ontologies properties are required.
        # TODO: Maybe, start with the instance with the bigger number of known properties,
        # TODO: i.e. number of literals.
        if one_instance.m_number_literals > 0:
            return instance_key

    # It could not find an instance with enough information.
    # The only possibility is to list all objects. So, this returns the first instance.
    # This could be refined by returning instances with not too many occurrences, or are easy to calculate.
    for instance_key, one_instance in instances_dict.items():
        return instance_key


def _visit_all_nodes(instances_dict):
    """
    Exploration of the graph, starting by the instances which can be calculated without inference.
    It receives the dictionary of all instances detected in the Sparql query.
    It returns the same instances as in the input list, but properly sorted.
    """

    # Find the start instance to walk the entire graph.
    # This should be the most known instance.
    start_instance_key = _findable_instance_key(instances_dict)
    start_instance = instances_dict[start_instance_key]

    for instance_key, one_instance in instances_dict.items():
        one_instance.m_visited = False

    # At the end, this contains the list of instance in the order allowing to enumerate
    # on variables and deduce the following instances.
    visited_instances = []
    # Ideally this should be empty at the end, otherwise some variables are not known,
    # so Cartesian product etc... Not sure we can do that now.
    unvisited_instances = set([one_instance for one_instance in instances_dict.values()])

    def instance_recursive_visit(one_instance):
        """
        This recursively visits the network of instances, starting by best known one,
        using associators as links between instances.
        """
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
        """
        Here, an instance has properties whose value is known, or is a rdflib variable.
        This returns tyhe set of properties whose value is a variable, i.e. not known.
        TODO: Check which list of properties is used.
        """
        return set([property_value
                    for property_value in one_instance.m_properties.values()
                    if isinstance(property_value, rdflib.term.Variable)])

    # The number of instances is the same.
    assert len(visited_instances) + len(unvisited_instances) == len(instances_dict)

    # All variables to enumerate like a Cartesian product, or so.
    all_properties_set = set.union(
        *[get_property_variables_list(one_instance)
          for one_instance in visited_instances])

    # This enumerates the instances which are not linked to the start instance with associators.
    # This hopes that the variables of the properties of the unvisited instances,
    # are in the properties of the visited instances,
    # which implies that the unvisited ones can be deduced with the visited ones.
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
        # This implies a Cartesian product I think.
        logging.warning("_visit_all_nodes len(unvisited_instances)=%d", len(unvisited_instances))
    assert len(visited_instances) == len(instances_dict)
    return visited_instances


def custom_eval_function(ctx, part):
    """
    This function matches the requirement of a rdflib custom evaluation function.
    Used by the Sparql endpoint sparql.py

    It uses an object factory which returns objectgs created by Survol only (Not WMI or WBEM)
    """
    return _custom_eval_function_generic(ctx, part, _sparql_model_CIM_Object_Survol)


def custom_eval_function_wmi(ctx, part):
    """
    This function matches the requirement of a rdflib custom evaluation function.
    Used by tests only.
    """
    return _custom_eval_function_generic(ctx, part, _sparql_model_CIM_Object_Wmi)


def custom_eval_function_wbem(ctx, part):
    """
    This function matches the requirement of a rdflib custom evaluation function.
    Not implemented yet.
    This is very similar to WMI because the underlying CQL query language is structurally the same.
    """
    return _custom_eval_function_generic(ctx, part, None)


def _custom_eval_function_generic_instances(ctx, instances_dict):
    """
    This feeds the graph with triples calculated with nested evaluations of instances.
    """

    # This returns the reordered nodes.
    visited_nodes = _visit_all_nodes(instances_dict)
    assert len(instances_dict) == len(visited_nodes)

    # This is a dictionary of variables.
    variables_context = {}

    def recursive_instantiation(instance_index):
        if instance_index == len(visited_nodes):
            return
        logging.debug(
            "recursive_instantiation: ix=%d visited nodes=%s"
            % (instance_index, str([nod.m_variable for nod in visited_nodes])))

        # This returns the first instance which is completely known, i.e. its parameters
        # are iterals, or variables whose values are known in the current context.
        one_instance = visited_nodes[instance_index]

        returned_variables = one_instance.fetch_all_variables(ctx.graph, variables_context)

        check_returned_variables(returned_variables)

        variables_combinations_iter = product_variables_lists(returned_variables)
        variables_context_backup = variables_context.copy()
        for one_subset in variables_combinations_iter:
            variables_context.update(one_subset)
            recursive_instantiation(instance_index+1)
        variables_context.clear()
        variables_context.update(variables_context_backup)

    recursive_instantiation(0)

    logging.info("Graph after recursive_instantiation: %d triples", len(ctx.graph))


def _custom_eval_function_generic_aux(ctx, part, sparql_model_definition):
    """
    Actual evaluation of the BGP.

    It is practically a callback for rdflib.
    """

    # part.name = "SelectQuery", "Project", "BGP"
    # BGP stands for "Basic Graph Pattern", which is a set of triple patterns.
    # A triple pattern is a triple:
    # RDF-term or value, IRI or value, RDF term or value.

    sparql_model_definition.write_ontology_to_graph(ctx.graph)

    logging.debug("Instances:")
    instances_dict = _part_triples_to_instances_dict_function(part, sparql_model_definition.object_factory)
    logging.debug("Instances before sort:%d" % len(instances_dict))
    for instance_key, one_instance in instances_dict.items():
        logging.debug("    Key=%s Instance=%s" % (instance_key, one_instance))

    if instances_dict:
        _custom_eval_function_generic_instances(ctx, instances_dict)
    else:
        logging.warning("No instances. Maybe a meta-data query.")


def _custom_eval_function_generic(ctx, part, sparql_model_definition):
    """
    Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html

    It takes as parameter a factory of objects. The factory of Survol or WMI objects have different
    implementations but return the same objects for the same input arguments.

    Their implementations are different because the WMI one exclusively uses WMI queries to retrieve objects.
    Also, it can use any class handled by the installed WMI providers.

    On the contrary, the Survol factory uses custom functions, nuch faster but hard-coded by class type.
    """

    # part.name = "SelectQuery", "Project", "BGP"
    # BGP stands for "Basic Graph Pattern", which is a set of triple patterns.
    # A triple pattern is a triple:
    # RDF-term or value, IRI or value, RDF term or value.
    if part.name == 'BGP':
        # This inserts triples in the graph.
        _custom_eval_function_generic_aux(ctx, part, sparql_model_definition)

        # Normal execution of the Sparql engine on the graph with many more triples.
        # <type 'generator'>
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP

    raise NotImplementedError()

