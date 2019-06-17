# This transforms a SPARQL query into a WMI/WBEM query.
# This is extremely restricted.
from __future__ import print_function

import sys
import functools
import rdflib.plugins.sparql.parser

import lib_util
import lib_properties
import lib_kbase
import lib_common


# QUERY_STRING="query=%0A++++PREFIX+rdfs%3A+%3Chttp%3A/www.w3.org/2000/01/rdf-schema%23%3E%0A++++SELECT+%3Flabel%0A++++WHERE+%7B+%3Chttp%3A/dbpedia.org/resource/Asturias%3E+rdfs%3Alabel+%3Flabel+%7D%0A&output=json&results=json&format=json"

#https://docs.aws.amazon.com/neptune/latest/userguide/sparql-api-reference-mime.html
#
# You can choose the MIME type of a SPARQL response by sending an "Accept: type" header with the request.
# For example, curl -H "Accept: application/nquads ...".
# The available content types depend on the SPARQL query type.
#
# SELECT
#    application/sparql-results+json Default
#    application/sparql-results+xml
#    application/x-binary-rdf-results-table
#    text/tab-separated-values
#    text/csv
# ASK
#    application/sparql-results+json Default
#    application/sparql-results+xml
#    text/boolean
# CONSTRUCT
#    application/n-quads Default
#    application/rdf+xml
#    application/ld+json
#    application/n-triples
#    text/turtle
#    text/n3
#    application/trix
#    application/trig
#    application/sparql-results+json
# DESCRIBE
#    application/n-quads Default
#    application/rdf+xml
#    application/ld+json
#    application/n-triples
#    text/turtle
#    text/n3
#    application/trix
#    application/trig
#    application/sparql-results+json

################################################################################

# This is used in a Sparql endpoint. It extracts the SPARQL query
# from the CGI environment.
class SparqlEnvironment:
    # SPARQLWrapper uses CGI variables to specify the expected output type.
    # FieldStorage(
    #   None,
    #   None,
    #   [
    #       MiniFieldStorage(
    #          'query',
    #           '\n    PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>\n    SELECT ?label\n    WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }\n'),
    #       MiniFieldStorage('output', 'json'),
    #       MiniFieldStorage('results', 'json'),
    #       MiniFieldStorage('format', 'json')])
    def __init__(self):
        import cgi
        self.m_arguments = cgi.FieldStorage()
        sys.stderr.write("\n")
        for i in self.m_arguments.keys():
            sys.stderr.write("%s => %s\n"%(i,self.m_arguments[i].value))
        sys.stderr.write("\n")

        self.m_query = self.m_arguments["query"].value
        try:
            output_type = self.m_arguments["output"].value
        except KeyError:
            # This is the only output type which works at the moment.
            output_type = "xml"

        sys.stderr.write("output_type=%s\n"%output_type)

        # Only "xml" works OK.
        if output_type == "json":
            self.m_mime_format = 'application/json'
            self.m_rdflib_format='json'
        elif output_type == "json-ld":
            self.m_mime_format = 'application/json'
            self.m_rdflib_format='json-ld'
        elif output_type == "xml":
            self.m_mime_format = 'application/xml'
            self.m_rdflib_format='xml'
        else:
            sys.stderr.write("Invalid output type:%s\n"%output_type)
            raise Exception("Invalid output type:"+output_type)
        sys.stderr.write("mime_format=%s\n"%self.m_mime_format)
        sys.stderr.write("rdflib_format=%s\n"%self.m_rdflib_format)

    def Query(self):
        return self.m_query

    def WriteTripleStoreAsString(self,grph):
        lib_util.WrtHeader(self.m_mime_format)
        try:
            # pip install rdflib-jsonld
            # No plugin registered for (json-ld, <class 'rdflib.serializer.Serializer'>)
            # rdflib_format = "pretty-xml"
            sys.stderr.write("len grph=%d\n"%len(grph))
            strRdf = grph.serialize(format=self.m_rdflib_format)
        except Exception as exc:
            sys.stderr.write("Caught:%s\n"%exc)
            return
        sys.stderr.write("strRdf=%s\n"%strRdf)
        lib_util.WrtAsUtf(strRdf)

################################################################################

# This works, but we are only interested by triples.
def print_simple(arg_elt,level=1):
    if arg_elt.__class__.__name__ == "list":
        print("    "*level,arg_elt.__class__.__name__)
        for elt2 in arg_elt:
            print("    "*(level+1),"L=",elt2,type(elt2))
    elif arg_elt.__class__.__name__ == "CompValue":
        print("    "*level,arg_elt.__class__.__name__)
        for key2 in arg_elt:
            val2 = arg_elt[key2]
            print("    "*(level+1),"Key=",key2," ==> ",type(val2))
            print_simple(val2,level+2)
    elif arg_elt.__class__.__name__ == "plist":
        print("    "*level,arg_elt.__class__.__name__)
        for elt2 in arg_elt:
            print_simple(elt2,level+1)
    elif arg_elt.__class__.__name__ == "ParseResults":
        print("    "*level,arg_elt.__class__.__name__)
        for elt2 in arg_elt.asList():
            print( ("    "*(level+1) )," ==>",type(elt2))
            print_simple(elt2,level+1)
    elif arg_elt.__class__.__name__ == "Variable":
        print("    "*level,"Variable=",arg_elt)
    elif arg_elt.__class__.__name__ == "URIRef":
        print("    "*level,"URIRef=",arg_elt)
    elif arg_elt.__class__.__name__ == "Literal":
        print("    "*level,"Literal=",arg_elt)
    elif arg_elt.__class__.__name__ == "unicode":
        print("    "*level,"unicode=",arg_elt)
    elif arg_elt.__class__.__name__ == "BNode":
        print("    "*level,"BNode=",arg_elt)
    else:
        print("    "*level,arg_elt.__class__.__name__)
        print("    "*level,"??? ",arg_elt.__class__.__name__,dir(arg_elt))

# This receives a predicate object, which is a directory containing the predicate local name
# and the prefix. It returns a concatenation of the two.
def __pname_to_string(pname):
    # pname_pname_{'localname': u'pid', 'prefix': u'survol'}
    value_localname = pname['localname']
    try:
        value_prefix = pname['prefix']
    except KeyError:
        value_prefix = ""
    value_name = value_prefix + ":" + value_localname
    return value_name


def __decode_parsed_subject(subj):
    # PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'pid', 'prefix': u'survol'}}]}]}
    if isinstance(subj,rdflib.term.Variable):
        return("TRPL_VARIABLE",str(subj))
        return
    if isinstance(subj,rdflib.term.Literal):
        # rdflib.term.Literal(u'123', datatype=rdflib.term.URIRef(u'http://www.w3.org/2001/XMLSchema#integer')
        return("TRPL_LITERAL",str(subj))
    if isinstance(subj,rdflib.term.BNode):
        # rdflib.term.BNode('N9b69940d021342f7b9dd341a53ea947b')
        return("TRPL_NODE",str(subj))
    if isinstance(subj,rdflib.term.URIRef):
        # rdflib.term.URIRef(u'http://nasa.dataincubator.org/spacecraft/1968-089A')
        return("TRPL_URIREF",str(subj))
    if isinstance(subj,rdflib.plugins.sparql.parserutils.CompValue):
        if 'string' in subj:
            # literal_literal_{'string': rdflib.term.Literal(u'CIM_Process')}
            litt_string = subj['string']
            # rdflib.term.Literal(u'CIM_Process')
            return("TRPL_LITERAL",str(litt_string))
        if 'localname' in subj:
            # For a node defined in a specific namespace with a prefix.
            return("TRPL_VALUE_NAME",__pname_to_string(subj))
    raise Exception("Cannot parse ERRSUBJsubj=",str(subj))


def __decode_parsed_predicate(pred):
    # PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'pid', 'prefix': u'survol'}}]}]}
    if isinstance(pred,rdflib.plugins.sparql.parserutils.CompValue):
        try:
            one_part = pred['part']
        except KeyError:
            ERROR("__decode_parsed_predicate pred=%s",pred)
            raise
        if isinstance(one_part,rdflib.plugins.sparql.parserutils.plist):
            assert(len(one_part)==1)
            one_part_first = one_part[0]
            if isinstance(one_part_first,rdflib.plugins.sparql.parserutils.CompValue):
                one_part_part = one_part_first['part']
                if isinstance(one_part_part,rdflib.plugins.sparql.parserutils.plist):
                    assert(len(one_part_part)==1)
                    one_part_part_first = one_part_part[0]
                    if isinstance(one_part_part_first,rdflib.plugins.sparql.parserutils.CompValue):
                        one_part_part_first_part = one_part_part_first['part']
                        if isinstance(one_part_part_first_part,rdflib.plugins.sparql.parserutils.CompValue):
                            resu = __pname_to_string(one_part_part_first_part)
                            return("TRPL_PREDICATE",resu)
                        else:
                            return("TRPL_URIREF",str(one_part_part_first_part))

    elif isinstance(pred,rdflib.term.Variable):
        # rdflib.term.Variable(u'p')
        return("TRPL_VARIABLE",str(pred))
    elif isinstance(pred,rdflib.term.BNode):
        return("TRPL_NODE",pred)
    else:
        ERROR("Error pred:",type(pred))
        raise Exception("Cannot parse")


# This returns a list of lists of tokens.
# These second-level lists of tokens are a SPARQL list of patterns,
# that is, patterns separated by a semi-colon,
# because they share the same subject, or commas if they share the subject and the predicate,
# ended by a dot. When returned, the list of patterns have a length multiple of three,
# because it is made of concatenated RDF triples.
def __get_triples(arg_elt):
    if arg_elt.__class__.__name__ == "CompValue":
        for key2 in arg_elt:
            val2 = arg_elt[key2]
            if key2 == "triples":
                return val2
            res = __get_triples(val2)
            if res:
                return res
    elif arg_elt.__class__.__name__ in ["ParseResults","plist"]:
        for elt2 in arg_elt:
            res = __get_triples(elt2)
            if res:
                return res
    return None


# This groups tokens by sequence of three, to create triples.
# All SPARQL constraints are mixed together
def __aggregate_into_triples(raw_trpl):
    curr_trip = []
    cnt_trip = 0
    for block in raw_trpl:
        for elt in block:
            cnt_trip += 1
            curr_trip.append(elt)
            if cnt_trip == 3:
                yield curr_trip
                cnt_trip = 0
                curr_trip = []
    if cnt_trip == 3:
        yield curr_trip
    else:
        assert cnt_trip == 0


# Examples of input:
# ['s', 'p3', 'N739bb0cc49f94657a365f080994a0e8f']
# [
#   'person',
#   "PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'name', 'prefix': u'foaf'}}]}]}",
#   'name']
# [
#   'x',
#   "PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'name', 'prefix': u'foaf'}}]}]}",
#   "literal_literal_{'string': rdflib.term.Literal(u'Johnny Lee Outlaw')}"]
# [
#   'item',
#   "PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'P2848', 'prefix': u'wdt'}}]}]}",
#   "pname_pname_{'localname': u'Q1543615', 'prefix': u'wd'}"]
def __decode_parsed_triple(one_trpl):
    s0 = __decode_parsed_subject(one_trpl[0])
    s1 = __decode_parsed_predicate(one_trpl[1])
    s2 = __decode_parsed_subject(one_trpl[2])

    clean_trpl = [s0,s1,s2]
    return clean_trpl


# This extracts the triples from the WHERE clause of a Sparql query,
# after it is parsed by rdflib.
def __generate_triples_list(qry):
    parsed = rdflib.plugins.sparql.parser.parseQuery(qry)


    # This returns a long sequence of nodes, length multiple of three.
    raw_trpl = __get_triples(parsed)

    # The logn sequence of nodes is split into triples: subject, predicate, object.
    trpl_lst = __aggregate_into_triples(raw_trpl)
    for one_trpl in trpl_lst:
        clean_trpl = __decode_parsed_triple(one_trpl)
        yield clean_trpl


# Special pass to replace "a" by "rdf:type
def __predicate_substitution(lstTriples):
    for clean_trpl in lstTriples:
        #print("--------------------")
        #print("Subj:",clean_trpl[0])
        #print("Pred:",clean_trpl[1])
        #print("Obj:",clean_trpl[2])

        #print("p=",clean_trpl[1])
        #print("p=",type(clean_trpl[1]))
        if clean_trpl[1][1] == 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type':
            yield clean_trpl[0], ('TRPL_PREDICATE',"rdf:type"), clean_trpl[2]
        else:
            yield clean_trpl

# TODO: When the subject is NOT a variable but an URL.
def __triples_to_input_entities(lst_triples):
    # This is list is visited twice. It is not very big anyway.
    assert isinstance(lst_triples,list)
    dict_key_value_pairs_by_subject = {}

    # First pass to create the output objects.
    # Gathers attributes of objects.
    # Objects for associators must also appear as triple subjects.
    variable_counter = 0
    for one_triple in lst_triples:
        WARNING("one_triple=%s", str(one_triple))
        variable_name = one_triple[0][1]
        if variable_name in dict_key_value_pairs_by_subject:
            continue
        if one_triple[0][0] != "TRPL_VARIABLE":
            continue
        # The predicate type could be "TRPL_VARIABLE"
        if one_triple[1][0] != "TRPL_PREDICATE":
            continue

        dict_key_value_pairs_by_subject[variable_name] = ObjectKeyValues(variable_name, variable_counter)
        variable_counter += 1
    WARNING("dict_key_value_pairs_by_subject=%s", str(dict_key_value_pairs_by_subject.keys()))

    # Gathers attributes of objects.
    for one_triple in lst_triples:
        WARNING("one_triple=%s", str(one_triple))
        variable_name = one_triple[0][1]
        try:
            input_subject = dict_key_value_pairs_by_subject[variable_name]
        except KeyError:
            continue

        object_parsed_type = one_triple[2][0]
        attribute_key = one_triple[1][1]
        attribute_content = one_triple[2][1]
        if object_parsed_type in ["TRPL_LITERAL", "TRPL_VALUE_NAME"]:
            # Literal or node defined in a namespace: type:LandlockedCountries, prop:populationEstimate
            input_subject.add_key_value_pair(attribute_key, attribute_content)
        elif object_parsed_type == "TRPL_VARIABLE":
            try:
                attribute_as_subject = dict_key_value_pairs_by_subject[attribute_content]
                # This is evaluated as an associator which needs all attributes of input_subject
                attribute_as_subject.m_associator_subject = input_subject
                attribute_as_subject.m_associator_key_name = attribute_key
            except KeyError:
                attribute_value = QueryVariable( attribute_content )
                input_subject.add_key_value_pair(attribute_key, attribute_value)
        else:
            WARNING("__triples_to_input_entities object_parsed_type=%s", object_parsed_type)


    list_entities_by_variable = dict_key_value_pairs_by_subject.values()

    for one_entity_by_variable in list_entities_by_variable:
        # This extracts the class name, the seeAlso scripts etc...
        one_entity_by_variable.prepare_for_evaluation()

    WARNING("dict_key_value_pairs_by_subject=%s", str(dict_key_value_pairs_by_subject))

    # TODO: Sort them using m_associator_subject and also the other variables.
    def compare_ObjectKeyValues(okv1,okv2):
        if okv1.m_associator_subject:
            if okv2.m_associator_subject:
                return compare_ObjectKeyValues(okv1.m_associator_subject, okv2.m_associator_subject)
            else:
                return 1
        else:
            if okv2.m_associator_subject:
                return -1
            else:
                # TODO: Should take into account the other variables,
                # the classes and the estimated number of objects,
                # and use the counter only of equality.
                return okv1.m_variable_counter < okv2.m_variable_counter

    # The order of nested loops is very important for performances.
    sort_entities_by_variable = sorted(list_entities_by_variable, key=functools.cmp_to_key(compare_ObjectKeyValues))

    WARNING("After sort=%s", str([one_ent.m_object_variable_name for one_ent in sort_entities_by_variable]))
    return sort_entities_by_variable



#Maintenant, on va extraire a part les proprietes speciales rdf:type etc...
#relatives a l ontologie.
#et aussi quand l object est manifestement un node.
#et quand les proprietes appartiennent a des namespaces differents.


def _parse_query_to_key_value_pairs_list(sparql_query):
    lstTriples = __generate_triples_list(sparql_query)
    lstTriplesReplaced = __predicate_substitution(lstTriples)

    lstTriplesReplaced = list(lstTriplesReplaced)
    listEntitiesByVariable = __triples_to_input_entities(lstTriplesReplaced)
    return listEntitiesByVariable

################################################################################

# This models a variable in a Sparql query.
class QueryVariable:
    def __init__(self,variable_name):
        self.m_query_variable_name = variable_name

    def __repr__(self):
        return "??" + self.m_query_variable_name + "??"

    def __eq__(self, other):
        return self.m_query_variable_name == other.m_query_variable_name


# This models an object as extracted from a Sparql query.
# The class name and the predicates still contain the prefix.
class ObjectKeyValues:
    def __init__(self, variable_name, variable_counter):
        self.m_object_variable_name = variable_name
        self.m_raw_key_value_pairs = []
        DEBUG("self.m_object_variable_name=%s",self.m_object_variable_name)

        # This is used for sorting, to keep by default the user order of triples.
        self.m_variable_counter = variable_counter
        # If None, then it is evaluated with a "select" using the key-value paris.
        # If this points to a subject, the attributes and the handle (moniker)
        # if this subject is used in an "associators" query.
        self.m_associator_subject = None
        # This is the associator class name, if seeAlso is WMI.
        # If not WMI, this could be used as a filter, or a hint to find a script.
        self.m_associator_key_name = None

    def add_key_value_pair(self, key, value):
        DEBUG("key=%s value=%s",key,value)
        self.m_raw_key_value_pairs.append((key, value))

    def prepare_for_evaluation(self):
        self.m_lst_seeAlso = []
        self.m_key_values = {}

        DEBUG("self.m_raw_key_value_pairs=%s",self.m_raw_key_value_pairs)
        class_name = None
        for lst_key, lst_val in self.m_raw_key_value_pairs:
            if lst_key == "rdfs:seeAlso":
                self.m_lst_seeAlso.append(lst_val)
            elif lst_key == "rdf:type":
                # class_name= "survol:CIM_Process" for example.
                class_name = str(lst_val)
            else:
                self.m_key_values[lst_key] = lst_val

        assert class_name
        DEBUG("class_name=%s",class_name)
        if class_name:
            self.m_source_prefix, colon, self.m_class_name =  class_name.rpartition(":")
        else:
            self.m_source_prefix, self.m_class_name = (None, None)

        DEBUG("prefix:%s", self.m_source_prefix)

    def all_sources(self):
        all_sources_set = set(self.m_lst_seeAlso)
        all_sources_set.add(self.m_source_prefix)
        return all_sources_set

    def __repr__(self):
        title = "ObjectKeyValues:"
        if self.m_class_name:
            title += self.m_class_name
        else:
            title += "NoClass"
        title += ":" + ",".join(["%s=%s" % kv for kv in self.m_key_values.items()])
        return title

# This models a result returned from the execution of the join of a Sparql query.
class PathPredicateObject:
    def __init__(self,subject_path, entity_class_name, predicate_object_dict):
        self.m_subject_path = subject_path
        self.m_entity_class_name = entity_class_name
        self.m_predicate_object_dict = predicate_object_dict

    def __repr__(self):
        return "PathPredicateObject:" + self.m_subject_path + ";class="+str(self.m_entity_class_name) + ";dict="+str(self.m_predicate_object_dict)


def chop_namespace(predicate_prefix, attribute_name):
    prefix, colon, short_key = attribute_name.partition(":")
    assert( prefix == predicate_prefix )
    return short_key


def __filter_key_values(predicate_prefix, where_key_values):

    filtered_where_key_values = {}
    for sparql_key, sparql_value in where_key_values.items():
        DEBUG("__filter_key_values sparql_key=%s", sparql_key)
        short_key = chop_namespace(predicate_prefix, sparql_key)
        # The local predicate names have to be unique.
        assert(short_key not in filtered_where_key_values)
        filtered_where_key_values[short_key] = sparql_value

    return filtered_where_key_values



# TODO: Several callbacks. Maybe with a key ??
# TODO: Maybe execute callbacks in a sub-process ?
# TODO: Maybe not recursive run because it is too slow.
# TODO: Rather run them once each.
def _run_callback_on_entities(
        lst_input_object_key_values,
        execute_query_callback_select,
        execute_query_callback_associators):

    def _evaluate_current_entity( index, known_variables, tuple_result_input):
        if index == len(lst_input_object_key_values):
            # Deepest level, last entity is reached, so return a result set.
            yield tuple_result_input
            return
        curr_input_entity = lst_input_object_key_values[index]
        assert curr_input_entity.m_class_name
        predicate_prefix = curr_input_entity.m_source_prefix

        where_key_values_replaced = {}
        dict_variable_to_attribute = {}
        #print("curr_input_entity=", curr_input_entity)
        for key_as_str, value_attribute in curr_input_entity.m_key_values.items():
            WARNING("key_as_str=%s value_attribute=%s", key_as_str,value_attribute)
            if isinstance(value_attribute, QueryVariable):
                variable_name = value_attribute.m_query_variable_name
                if variable_name in known_variables:
                    where_key_values_replaced[key_as_str] = known_variables[variable_name]
                else:
                    # Variable is not known yet. CA NE DEVRAIT PAS ARRIVER ???
                    WARNING("NOT KNOWN YET key_as_str=%s value_attribute=%s", key_as_str, value_attribute)
                    dict_variable_to_attribute[variable_name] = key_as_str
            else:
                where_key_values_replaced[key_as_str] = value_attribute
        # SI PAS DE SUBSTITUTION, STOCKER LE RESULTAT UNE BONNE FOIS POUR TOUTES DANS LE TABLEAU lst_input_object_key_values[index]

        # TODO: Difficulty mapping property names to nodes.
        def _property_name_to_node(attribute_key):
            if attribute_key.startswith(predicate_prefix+":"):
                attribute_key_without_prefix = attribute_key[len(predicate_prefix)+1:]
            else:
                attribute_key_without_prefix = attribute_key
            # This calculates the qname and should use the graph. Is it what we want ?
            return lib_properties.MakeProp(attribute_key_without_prefix)

        DEBUG("dict_variable_to_attribute=%s", str(dict_variable_to_attribute))

        # Ne pas appeler plusieurs fois si ce sont les memes valeurs mais reutiliser le resultat.

        if curr_input_entity.m_associator_subject:
            def _callback_filter_all_sources_associators():
                for one_see_also in curr_input_entity.m_associator_subject.all_sources():
                    WARNING("_callback_filter_all_sources_associators one_see_also=%s", one_see_also)

                    short_associator_class_name = chop_namespace(one_see_also, curr_input_entity.m_associator_key_name)

                    iter_recursive_results = execute_query_callback_associators(
                        curr_input_entity.m_class_name,  # Le resultClass
                        one_see_also,
                        short_associator_class_name,
                        curr_input_entity.m_associator_subject.m_object_path_node
                    )

                    for one_node_dict_pair in iter_recursive_results:
                        yield one_node_dict_pair

            iter_recursive_results = _callback_filter_all_sources_associators()

        else:
            def _callback_filter_all_sources_select():
                for one_see_also in curr_input_entity.all_sources():
                    WARNING("_callback_filter_all_sources_select one_see_also=%s", one_see_also)

                    filtered_where_key_values = __filter_key_values(one_see_also, where_key_values_replaced)
                    iter_recursive_results = execute_query_callback_select(
                        curr_input_entity.m_class_name,
                        one_see_also,
                        filtered_where_key_values)

                    for one_node_dict_pair in iter_recursive_results:
                        yield one_node_dict_pair

            iter_recursive_results = _callback_filter_all_sources_select()

        # TEMP TEMP
        ### iter_recursive_results = list(iter_recursive_results)


        for object_path_node, dict_key_values in iter_recursive_results:
            # The result is made of URL to CIM objects.
            output_entity = PathPredicateObject(object_path_node, curr_input_entity.m_class_name, dict_key_values)
            #print("From callback: output_entity=",output_entity)

            for variable_name, attribute_key in dict_variable_to_attribute.items():
                #WARNING("index=%d variable_name=%s attribute_key=%s", index, variable_name, attribute_key)
                attribute_key_node = _property_name_to_node(attribute_key)
                #WARNING("output_entity.m_predicate_object_dict=%s",str(output_entity.m_predicate_object_dict))
                known_variables[variable_name] = output_entity.m_predicate_object_dict[attribute_key_node]

            tuple_result_extended = tuple(list(tuple_result_input)) + (output_entity,)

            # Rendre object_path_node accessible si Associators.
            # Ca nous donne le moniker. C est dommage de devoir le recalculer.
            # object_path_node = lib_util.NodeUrl(object_path)
            # one_wmi_object.path =\\RCHATEAU - HP\root\cimv2:Win32_Process.Handle = "26720"

            curr_input_entity.m_object_path_node = object_path_node

            # NON: Executer seulement pour chaque combinaison de variables reellement utilisees.
            # Sinon reutiliser le resultat.
            output_results = _evaluate_current_entity(index + 1, known_variables, tuple_result_extended)
            for one_resu in output_results:
                yield one_resu

    itr_tuple_results = _evaluate_current_entity(0, known_variables={}, tuple_result_input=tuple())
    for tuple_results in itr_tuple_results:
        yield tuple_results


def QueryEntities(sparql_query, query_callback_select, query_callback_associator):

    list_entities_by_variable = _parse_query_to_key_value_pairs_list(sparql_query)

    WARNING("list_entities_by_variable=%s", str(list_entities_by_variable))

    input_keys = [ one_entity_by_variable.m_object_variable_name for one_entity_by_variable in list_entities_by_variable ]
    for tuple_results in _run_callback_on_entities(list_entities_by_variable, query_callback_select, query_callback_associator):
        yield dict(zip(input_keys,tuple_results))

    # ON CHANGE LA LOGIQUE D EXECUTION:
    # (1) Essayer de trier les objets
    # (2) A chaque niveau, au lieu d'executer recursivement dans des boucles imbriquees,
    #     peut-etre n executer qu'une seule fois: ON aura des donnees en trop mais on s'en fiche.

    # En fait, on pourrait decider de splitter lq liste d'objects en deux s'il en realite il n'y as pas
    # de partage de variable c'est a dire de produit cartesien. Ou bien, on supprime cette variable,
    # ce qui renvoie davantage de donnees mais au lieu de faire N*M queries on en fait N+M.
    # Toutefois la taille du resultat ne change pas.
    # Cependant si on joue habilement des iterateurs, les besoins en memoire ne grandiront pas.

    # ET EN PLUS C EST IDIOT !!
    # Actuellement si on a deux objets, on va querir l object 2 pour chaque result de l'object 1
    # meme s'il n'y a aucune variable en commun.

    # Peut-etre supprimer des "where" clause pour reutiliser le resultat venant d'un cache.

    # Donc faut reordonner la liste et eventuellement splitter en plusieurs.
    # Puis reassembler les resultats en faisant cette fois-c- un produit cartesien.
    # Mais c'est dommage de traiter deux fois ce produit cartesien bien que de facon differente.


##################################################################################

# This function is similar to QueryEntities, except:
# - The attributes values "rdf:seeAlso" are associated to each object.
#   There might be several of them.
# - These attribute's values are passed as parameter to the callback.
# - The class and attributes prefixes are not used to select the source of information
# Also:
# - Objects might also be nodes, not only literals. If the data source is WMI,
#   then associators/references will be used.
# - Attributes names in the case of objects as nodes, are similar to WMI associators,
#   like in the case of these two queries:
#   "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} where assocclass=CIM_ProcessExecutable"
#   "associators of {CIM_Process.Handle=1780} where assocclass=CIM_ProcessExecutable"



def QuerySeeAlsoEntities(sparql_query, query_callback_select, query_callback_associator):
    return QueryEntities(sparql_query, query_callback_select, query_callback_associator)

##################################################################################

# This runs a Sparql callback and transforms the returned objects into RDF triples.
def QueryToGraph(grph, sparql_query, query_callback_select, query_callback_associator):

    iter_entities_dicts = QueryEntities(sparql_query, query_callback_select, query_callback_associator)

    sys.stderr.write("iter_entities_dicts=%s\n"%dir(iter_entities_dicts))

    for one_dict_entity in iter_entities_dicts:
        sys.stderr.write("one_dict_entity=%s\n"%one_dict_entity)
        for variable_name, sparql_object in one_dict_entity.items():
            # Dictionary of variable names to PathPredicateObject
            for key,val in sparql_object.m_predicate_object_dict.items():
                grph.add((sparql_object.m_subject_path, key,val))

    ### AddOntology(grph)


##################################################################################

# This returns an iterator on objects of the input class.
# These objects must match the input key-value pairs,
# returned by calling the optional class-specific SelectFromWhere() method.
# Each object is modelled by a key-value dictionary.
# No need to return the class name because it is an input parameter.
def SurvolExecuteQueryCallback(class_name, predicate_prefix, filtered_where_key_values):
    DEBUG("SurvolExecuteQueryCallback class_name=%s where_key_values=%s", class_name, str(filtered_where_key_values))

    entity_module = lib_util.GetEntityModule(class_name)
    if not entity_module:
        raise Exception("SurvolExecuteQueryCallback: No module for class:%s"%class_name)

    try:
        enumerate_function = entity_module.SelectFromWhere
    except AttributeError:
        exc = sys.exc_info()[1]
        INFO("No Enumerate for %s", class_name, str(exc) )
        return

    iter_enumeration = enumerate_function( filtered_where_key_values )
    for one_key_value_dict in iter_enumeration:
        one_key_value_dict["rdfs:definedBy"] = class_name + ":" + "SelectFromWhere"
        yield ( lib_util.NodeUrl("survol_object_path"), one_key_value_dict )


# Quand on a un triplet de cette forme, trouver toutes les proprietes
# litterales relatives au sujet.
# Subj: ('VARIABLE=', 't')
# Pred: ('Predicate', u'rdf:type')
# Obj: ('litt_string', 'CIM_Process')# On peut alors en faire des requetes WMI ou WBEM, eventuellement.
#
# En theorie, c'est toujours possible mais probablement tres lent.
#
# Si on a les bons attributs, on peut executer le script principal dans survol.

##################################################################################

# Interface: UpdateTripleStoreSnapshotWithSparqlQuery:
# - On recoit une requete, qu'on parse en une liste de triplets RDF.
# - Ensuite, on enrichit le graphe resultant.

##################################################################################

"""
# Est-ce que ca marche avec les ASSOCIATORS et REFERENCES ?
# Comment ordonner les boucles ?
#
# Si un groupe de triplet a une variable en commun, essayer "associator".
# Dans le cas general, se contenter de boucles.

# La methode est utilisable aussi pour WBEM et peut-etre aussi si enumerate_*.py

# For each predicate, get the list of scripts returning data for this predicate.
# See Test_package_dis.py
# This -possibly- implies classes (But this is not sure).
# Maybe this is only true for the function __init__.AddInfo().
# But this is a hint to identify the class of each variable.

# La relation "predicat" => [scripts] peut etre batie avec Test_package_dis.py
# en analysant le script, mais on peut aussi analyser le contenu des anciens triplestores
# resultat de l'execution des scripts au prealable, construire un historique
# et meme l'exploiter avec du pattern matching en recherchant des triplets similaires.

# For each variable whose class is identified, or suggested.
# For each variable of a given class, see if there are values for each attribute
# of its ontology.

# If yes, it means that the object can be identified.
# Then take the list of scripts for this class, returning these predicates.
# Possibly all scripts: Not many data should be returned.

# If no, we cannot identify the variable, then use the function Search() for this class,
# with the few key-value pairs if the object is a literal.
# There could be a default Search() function based on WMI or WBEM,
# but this is optional, because possibly very slow.
# There must be an upper limit on the number of objects returned by Search().

# The results can be mixed with WMI data by merging the results of both executions.
# Unfortunately, on the other hand, it prevents any join.

# Meme si on separe bien les entites,
# on ne peut pas, dans le cas general, lister les items en focntions des attributs,
# car rien n'indique qu'on aura tous ces attributs.
# Il faut donc avoir pour chaque classe une fonction d'enumeration prenant
# des triplets "key" "operator" "value"
# ou bien des paires "key" "operator/value" qui rendront tous les objects qui matchent.
# Les scripts "enumerate_XXX.py" seront reecrits pour utiliser ces fonctions.
# Evidemment, on va rendre des generateurs pour ne pas faire la meme erreur que WBEM.
# Libre a la fonction de faire ce qu'elle veut.
# Si un seul object ou bien si les attributs sont la clef, on renvoie l'URL de l'objet.
# D'ailleurs on ne renvoie que des URLS d'objet, avec les bonnes clefs.
"""

####################################################
"""
On separe en objets.
On repere les rdfs:seeAlso
On ne garde que les objets ou il y a un rdfs:seeAlso.
Le seeAlso donne le script qui va permettre de charger des objets.
Il peut y avoir plusieurs seeAlso par objet donc c est une liste d paire, pas un dict.
On met le resultat dans definedBy

?subj rdf:type CIM_Process
?subj rdfs:seeAlso "WMI"
=> "select * from CIM_Process"

?subj rdf:type CIM_DataFile
?subj rdfs:seeAlso "Survol"
=> sources_types/CIM_Process.Enumerate()

?subj rdf:type CIM_DataFile
?subj rdfs:seeAlso "sources_types/toto.py"
=> Execute le script et ne garde que les elements de cette classe.

?subj rdf:type CIM_DataFile
?subj rdfs:seeAlso "sources_types/CIM_Process/toto.py"
Si c'est un script d'une classe qu'on n'a pas les parametres, alors echec.
Echec aussi sil nous manque des arguments.

Les scripts sauf WMI vont renvoyer des scripts donc du seeAlso.
=> Implicitement, peut etre que WMI devrait aussi avoir des seeAlso ?
Combien de fois va-t-on iterer ? 

Ou alors:
On execute le premier seeAlso, on filtre avec le RDF et on voit s'il reste des seeAlso,
et si oui on les execute a nouveau ?
=> Il va peuyt-etre forcement en rester ? Ou les triples seeAlso vont eput-etre
forcement etre elimines ?
Quoiqu'il en soit il faudrait un mecanisme plus robuste ?
Peut-on utiliser le resultat des definedBy ?
Il faudrait pouvoir limiter la profondeur, explicitement.

Dans un premier temps, on peut peut-etre se limiter a un cycle.

Si execution d un script normal:
- Que faire si les arguments sont donnes ?
- Que faire si les arguments du script sont des variables ?
- Comment coordonner le produit cartesien entre les scripts ?
- Peut-on filtrer la sortie du script en fonction de la classe ?
=> Peut etre simplement se reposer sur Sparql.
- Est-ce qu on ne devrait pas, au lieu d un script, donner un module ?
Ca revient au meme mais c est plus propre

"""

#



