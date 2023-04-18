# This script is a sparql server which receives a Sparql query,
# calculates dynamic data which are inserted in a triplestore through another secondary sparql endpoint,,
# then runs the query on this secondary endpoint.

# 1) Receives the secondary sparql endpoint.
# 2) Receives the Sparql query.
# 3) Extracts the basic graph patterns.
# 4) Uses these patterns to fetch data with another query language, here WQL with WQL and WBEM.
# 5) Inserts the triples in the secondary endpoint.
# 6) Run the original sparql query on the secondary endpoint.
# 7) Receives the triples and output them as if they are generated locally.

# It does not use Survol agent, as opposed to survol/sparql.py which converts
# the input Sparql and executes it locally.

import rdflib
import logging

from .. import lib_sparql_custom_evals


class VerySimpleObject(object):
    """
    This object is created by extracting the basic graph patterns of a sparql query,
    and grouping all triples related to the same object.
    It assumes that the query implictly manipulates objects with a rdf type and several attributes and values.
    Variables and BGP which are not related to an object are not taken into account.
    These objects are then mapped to WQL queries, are retrieved with WMI.
    They are then transformed into fully known triples awhich are injected in the triple-store.
    A loop-hole is if a variable used as an attribute variable of an object, can be known only
    with the content of the triplestore.
    In this case, more and possibly all objects of this type should be retrieved.
    This case is not taken into account now.
    """
    def __init__(self, class_name, key_variable, ontology_keys):
        assert isinstance(key_variable, rdflib.term.Variable)
        # En fait, on s'en fout des keys : Elles seront donnees par les triples.
        self.m_variable = key_variable
        self.m_class_name = class_name
        self.m_associators = {} # Peut etre inutile ?
        self.m_associated = {} # Peut etre inutile ?
        self.m_properties = {}

        # Seulement pour documenter.
        if "comment se fait l insertion" and False:
            # ... dans _part_triples_to_instances_dict_function
            # ... appele par _custom_eval_function_generic_aux
            if "associator mais on le deduit alors qu on pourrait utiliser la syntaxe avec le point":
                current_instance.m_associators[part_predicate] = associator_instance
                associator_instance.m_associated[part_predicate] = current_instance
            else:
                assert isinstance(part_object, (rdflib.term.Literal, rdflib.term.Variable))
                current_instance.m_properties[part_predicate] = part_object



def very_simple_object_factory(class_name, the_subject):
    # On va chercher les clefs dans l'ontologie, ou alors on s'en fout !!!!
    return VerySimpleObject(class_name, the_subject)

def _generate_python_script_wmi(instances_dict):
    #         Pour chaque element du dict:
    #             # Ou alors associators. C est la ou il vaut mieux generer un fichier pour voir le resultat.
    #             # On va ramenr tout le code ici car l autre truc est de la daube indebuggable et trop lent.
    #             qry1 = "select x from the_class where xyz"
    #             for the_varz in qry1.results():
    #                 # On remplace les variables.
    #                 qry2 = "select x from the_class where xyz"
    #                 for the_varz in qry2.results():
    # TODO: Ce serait mieux de ne pas dependre du tout des lib_*. Sans importance pour le moment.

    of = open("thescript.py", "w")

    # Will be incremented of four spaces for each loop on the instances.
    python_margin = ""

    def _create_wmi_query(simple_object):
        boucler sur m_vaiables : Si c est ine constante on la met, sinon on va chercher sa valeur dans dict_variables
        return "select * from %s where " % simple_object.m_class_name

    def _add_wql_loop(subject_node, simple_object):
        wmi_query = _create_wmi_query(simple_object)

        python_statements = [
            "wmi_objects = wmi_connection.query('%s')" % wmi_query,
            "for one_wmi_object in wmi_objects:",
                 # Path='\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"'",
            "    object_path = str(one_wmi_object.path())",
            "    list_key_values = lib_wmi.WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, class_name)",
            "    dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}",

            # Now update the variables with their new values.
            "    dict_variables[simple_object.m_variable_name] = object_path",
            "    for part_predicate, part_object in simple_object.m_properties:",
            "        assert isinstance(part_object, (rdflib.term.Literal, rdflib.term.Variable))",
            "        if part_object is rdflib.term.Variable:",
            "            dict_variables[part_object] = dict_key_values[part_object]",

            "    dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral('WMI')",
                # Add it again, so the original Sparql query will work.",
            "    dict_key_values[lib_kbase.PredicateSeeAlso] = lib_util.NodeLiteral('WMI'')",

                # s=\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            "    dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)",

            # In fact, insert in the secondary endpoint.
            "    print(object_path, dict_key_values)",
        ]

        for one_statement in python_statements:
            of.write(python_margin + one_statement)

    of.write("""
import wmi
import lib_kbase
import lib_wmi
wmi_connection = wmi.WMI()
dict_variables = {}
    """)
    for subject_node, simple_object in instances_dict:
        _add_wql_loop(subject_node, simple_object)
        python_margin += "    "
        
        
    of.close()
    

def ze_callback(ctx, part):
    if part.name == 'BGP':
        # This inserts triples in the graph.
        #sparql_model_definition.write_ontology_to_graph(ctx.graph)

        # On recommence vraiment a zero et ca fabrique a partir de ctx.part une liste de :
        # {rdfnode_of_variable, "class_name", { "member1": rdfnode_of_variable, "member2:" : "literal", "member3": rdfnode_of_variable }
        #
        # Ensuite on reordonne et on genere le WQL dans un fichier .py
        #
        # ... qu'on execute.
        #
        # ... on insere les triplets dans le endpoint secondaire.
        instances_dict = lib_sparql_custom_evals._part_triples_to_instances_dict_function(part, very_simple_object_factory)
        logging.debug("Instances before sort:%d" % len(instances_dict))
        for instance_key, one_instance in instances_dict.items():
            logging.debug("    Key=%s Instance=%s" % (instance_key, one_instance))

        # This returns the reordered nodes.
        # Et encore, peut etre qu on va refaire le tri a notre facon.
        visited_nodes = lib_sparql_custom_evals._visit_all_nodes(instances_dict)
        assert len(instances_dict) == len(visited_nodes)

        _generate_python_script_wmi(visited_nodes)

        # Non, plus maintenant car on ne veut surtout pas inserer.
        #if instances_dict:
        #    _custom_eval_function_generic_instances(ctx, instances_dict)



        # Normal execution of the Sparql engine on the graph with many more triples.
        # NON, Justement, on ne fait rien, on se fiche de l;execution dans rdflib.
        # <type 'generator'>
        # ON n insere rien dans le graphe, car il faut parser eventuellement plusieurs BGP.
        # En priant pour que tous les BGP soient parses avant l'execution.
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP
    raise NotImplementedError()
    # return _custom_eval_function_generic(ctx, part, _sparql_model_CIM_Object_Wmi)

def __run_sparql_query(sparql_query):
    grph = rdflib.Graph()

    # add function directly, normally we would use setuptools and entry_points
    rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function'] = ze_callback
    query_result = grph.query(sparql_query)
    if 'custom_eval_function' in rdflib.plugins.sparql.CUSTOM_EVALS:
        del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function']
    return query_result

##############################################################################
"""
Autre approche plus simple et directe peut-etre en vue d'inclusion en un sous-projet de pywbem.
Les associators sont pris comme tels.

# WMI
# Celle-ci ne devrait-elle pas avoir "Associators of ..." ?
# Select * from CIM_ProcessExecutable Where Antecedent=""\\\\W2012SDC\\root\\cimv2:CIM_DataFile.Name=\""C:\\\\Windows\\\\system32\\\\wininit.exe\""""Dependent=""\\\\W2012SDC\\root\\cimv2:Win32_Process.Handle=\""532\"""""
# SELECT Archive FROM CIM_DataFile WHERE Name = "something"'
# ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"}
# ASSOCIATORS OF {ObjectPath} WHERE
#     AssocClass = AssocClassName
#     ClassDefsOnly
#     RequiredAssocQualifier = QualifierName
#     RequiredQualifier = QualifierName
#     ResultClass = ClassName
#     ResultRole = PropertyName
#     Role = PropertyName
# ?my_process = r'\\.\root\cimv2:Win32_Process.Handle="532"'
# ?my_process = r'\\W2012SDC\root\cimv2:Win32_Process.Handle="532"'
# ?my_file = r'\\.\root\cimv2:CIM_DataFile.Name="C:\\Windows\system32\wininit.exe"'
# ?my_file = r'\\W2012SDC\root\cimv2:CIM_DataFile.Name="C:\\Windows\system32\wininit.exe"'
#
# Get-WmiObject -Query  'Select Name, Handle from CIM_Process where __PATH="\\\\LAPTOP-R89KG6V1\\root\\cimv2:Win32_Process.Handle=\"9660\""'
#
# WBEM
# select * from Solaris_DiskDrive where Storage_Capacity = 1000
# SELECT * FROM Solaris_FileSystem WHERE (Name = `home' OR Name = `files') AND AvailableSpace > 2000000 AND FileSystem = `Solaris'


select ?my_file_name ?my_process_handle
where {
?my_assoc rdf:type cim:CIM_ProcessExecutable .
?my_assoc cim:Dependent ?my_process .
?my_assoc cim:Antecedent ?my_file .
?my_process rdf:type cim:CIM_Process .
?my_process cim:Handle ?my_process_handle .
?my_file rdf:type cim:CIM_DataFile .
?my_file rdf:Name ?my_file_name .
}

# Sous WMI et probablement avec WBEM
for my_process in Query("select * from CIM_Process"):
    for my_file in Query("associators of {%s} where AssocClass = CIM_ProcessExecutable ResultClass=CIM_DataFile ResultRole=Antecedent Role=Precedent" % my_process):
        process_handle = Query('select Handle from CIM_Process where __PATH="%s"' % my_process)
        file_name = Query('select Name from CIM_DataFile where __PATH="%s"' % my_file)

# En tout cas sous WMI ...
for antecedent, precedent from Query("select Antecedent, Precedent from CIM_ProcessExecutable"):
    process_handle = Query('select Handle from CIM_Process where __PATH="%s"' % precedent)
    file_name = Query('select Name from CIM_DataFile where __PATH="%s"' % antecedent)

# Pour faciliter les tests, on tente d'installer wmimapper
# https://support.hpe.com/hpesc/public/swd/detail?swItemId=MTX_9ef95a0fdf044f7aa5f7a09445
#
# TCP    [::]:5988              [::]:0                 LISTENING
#
# This is hanging:
# python -c "import pywbem;c=pywbem.WBEMConnection('http://127.0.0.1:5988');c.ExecQuery('WQL','','root/cimv2')"
#
#
#

# WBEM
        instances_associators = self.m_wbem_connection.Associators(
            ObjectName=subject_path,
            AssocClass=associator_key_name,
            ResultClass=None, # ResultClass=result_class_name,
            Role=None,
            ResultRole=None,
            IncludeQualifiers=None,
            IncludeClassOrigin=None,
            PropertyList=None)
"""