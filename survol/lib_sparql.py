# This transforms a SPARQL query into a WMI/WBEM query.
# This is extremely restricted.
from __future__ import print_function

import sys
import functools
import rdflib.plugins.sparql.parser

import lib_kbase
import lib_util
import lib_properties

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

        # https://hhs.github.io/meshrdf/sparql-and-uri-requests
        # format=HTML*, XML, CSV, TSV or JSON. Default= HTML*
        #
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

    def Query(self):
        return self.m_query

    def WriteTripleStoreAsString(self,grph):
        lib_util.WrtHeader(self.m_mime_format)
        try:
            # pip install rdflib-jsonld
            # No plugin registered for (json-ld, <class 'rdflib.serializer.Serializer'>)
            # rdflib_format = "pretty-xml"
            # sys.stderr.write("len grph=%d\n"%len(grph))
            strRdf = grph.serialize(format=self.m_rdflib_format)
        except Exception as exc:
            sys.stderr.write("Caught:%s\n"%exc)
            return
        # sys.stderr.write("strRdf=%s\n"%strRdf)
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
def __generate_triples_list(sparql_query):
    parsed = rdflib.plugins.sparql.parser.parseQuery(sparql_query)

    # This returns a long sequence of nodes, length multiple of three.
    raw_trpl = __get_triples(parsed)

    # The long sequence of nodes is split into triples: subject, predicate, object.
    trpl_lst = __aggregate_into_triples(raw_trpl)
    for one_trpl in trpl_lst:
        clean_trpl = __decode_parsed_triple(one_trpl)
        yield clean_trpl


# Special pass to replace "a" by "rdf:type
def __predicate_substitution(lstTriples):
    for clean_trpl in lstTriples:
        if clean_trpl[1][1] == 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type':
            yield clean_trpl[0], ('TRPL_PREDICATE',"rdf:type"), clean_trpl[2]
        else:
            yield clean_trpl

# TODO: When the subject is NOT a variable but an URL,
# TODO: i.e. when the subject is not a variable.
# This receives the list of triples of the WHERE statement of a Spqrql query.
# It returns a list of ObjectKeyValues.
def __triples_to_input_entities(lst_triples):
    # This list is visited twice. It is not very big anyway.
    assert isinstance(lst_triples,list)
    dict_key_value_pairs_by_subject = {}

    # First pass to create the output objects.
    # Gathers attributes of objects.
    # Objects for associators must also appear as triple subjects.
    variable_counter = 0
    for one_triple in lst_triples:
        #WARNING("one_triple=%s", str(one_triple))
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
    #WARNING("dict_key_value_pairs_by_subject=%s", str(dict_key_value_pairs_by_subject.keys()))

    # Gathers attributes of objects.
    for one_triple in lst_triples:
        WARNING("one_triple=%s", one_triple)
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
            # The object is also a subject, a variable: This is similar to the logic of associators.
            try:
                WARNING("attribute_content=%s", attribute_content)
                attribute_as_subject = dict_key_value_pairs_by_subject[attribute_content]
                # This is evaluated as an associator which needs all attributes of input_subject
                attribute_as_subject.m_associator_subject = input_subject
                WARNING("input_subject=%s", input_subject)
                # For example: attribute_key="rdfs:subClassOf"
                attribute_as_subject.m_associator_key_name = attribute_key
                WARNING("attribute_key=%s", attribute_key)
            except KeyError:
                attribute_value = QueryVariable( attribute_content )
                input_subject.add_key_value_pair(attribute_key, attribute_value)
        else:
            WARNING("__triples_to_input_entities object_parsed_type=%s", object_parsed_type)

    # This is a list of ObjectKeyValues. Some of them have their class defined with rdf:type,
    # and can be transformed into a WQL query, or the execution of a Survol script.
    # Some others have no class and will be processed differently.
    # They must be sorted together because variables might be shared between
    # these two kinds of ObjectKeyValues.
    list_entities_by_variable = dict_key_value_pairs_by_subject.values()

    for one_entity_by_variable in list_entities_by_variable:
        # This extracts the class name, the seeAlso scripts etc...
        one_entity_by_variable.prepare_for_evaluation()

    #WARNING("m_associator_subject=%s", attribute_as_subject.m_associator_subject)
    #WARNING("m_associator_key_name=%s", attribute_as_subject.m_associator_key_name)
    #WARNING("dict_key_value_pairs_by_subject=%s", dict_key_value_pairs_by_subject)

    # TODO: Sort them using m_associator_subject and also the other variables.
    def compare_ObjectKeyValues(okv1,okv2):
        if okv1.m_associator_subject:
            if okv1.m_associator_key_name == "rdfs:subClassOf" and okv1.m_associator_subject == okv2:
                WARNING("A SubClass before class")
                return -1

            if okv2.m_associator_subject:
                assert okv2.m_associator_key_name
                return compare_ObjectKeyValues(okv1.m_associator_subject, okv2.m_associator_subject)
            else:
                return 1
        else:
            assert not okv1.m_associator_key_name
            if okv2.m_associator_subject:
                if okv2.m_associator_key_name == "rdfs:subClassOf" and okv2.m_associator_subject == okv1:
                    WARNING("B SubClass before class")
                    return 1

                return -1
            else:
                # TODO: Should take into account the other variables,
                # the classes and the estimated number of objects,
                # and use the counter only of equality.
                return okv1.m_variable_counter < okv2.m_variable_counter

    # The order of nested loops is very important:
    # - It allows to get the value of object variables and assign them to nested queries:
    #   The value of a Sparql variable must be found to set to other key-value paris of other
    #   objects which can at their turn be fetched from WQL or Survol scripts.
    # - Performance impact: This is a secondary criteria.
    sort_entities_by_variable = sorted(list_entities_by_variable, key=functools.cmp_to_key(compare_ObjectKeyValues))

    WARNING("After sort=%s", str([one_ent.m_object_variable_name for one_ent in sort_entities_by_variable]))
    return sort_entities_by_variable

# This receives a Sparql query and returns a list of objects defined
# by their class and a dictionary of key-value pairs.
# The values can be literal or variables.
#
# The class of each object is given by rdf:type.
# The key-value pairs are given by the clause in the Sparql query.
# These objects are used to preload RDF triples from Survol scripts
# or WMI/WBEM queries in WQL language:
# - For WQL, each object is transformed into a "select where" WQL query,
#   with the correct type.
# - For Survol scripts, the key-value pairs are transformed into an URL,
#   and the scripts names are given by "seeAlso".
#
# The list of objects is sorted, so their data can be fetched in nested loops,
# each loop returning values assigned to the variables.
# This returns a list of ObjectKeyValues
def _parse_query_to_key_value_pairs_list(sparql_query):
    lst_triples = __generate_triples_list(sparql_query)
    # This is a list of clauses of the WHERE statement in the Sparql query.
    lst_triples_replaced = __predicate_substitution(lst_triples)

    # It must be a list, and not an iterator, because it is walked twice.
    lst_triples_replaced = list(lst_triples_replaced)
    list_entities_by_variable = __triples_to_input_entities(lst_triples_replaced)
    return list_entities_by_variable

################################################################################
def QueryHeader(sparql_query):
    parsed = rdflib.plugins.sparql.parser.parseQuery(sparql_query)

    # parsed = rdflib.plugins.sparql.parser.parseQuery("select ?a ?b where { ?a a ?b . }")
    # parsed = ([([], {}),
    #     SelectQuery_{'where': GroupGraphPatternSub_{'part': [TriplesBlock_{'triples': [([rdflib.term.Variable(u'a'), PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type')}]}]},
    # rdflib.term.Variable(u'b')], {})]}]}, 'projection': [vars_{'var': rdflib.term.Variable(u'a')}, vars_{'var': rdflib.term.Variable(u'b')}]}], {})

    list_vars = parsed[1]['projection']
    list_names = [str(one_var['var']) for one_var in list_vars]
    return list_names

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
        DEBUG("self.m_object_variable_name=%s", self.m_object_variable_name)

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

        DEBUG("self.m_raw_key_value_pairs=%s", self.m_raw_key_value_pairs)
        class_name = None
        for lst_key, lst_val in self.m_raw_key_value_pairs:
            if lst_key == "rdfs:seeAlso":
                self.m_lst_seeAlso.append(lst_val)
            elif lst_key == "rdf:type":
                # If the object is a class:
                WARNING("lst_val=%s / %s / %s / %d", lst_val, str(type(lst_val)), lib_kbase.PredicateType, lib_kbase.PredicateType == lst_val)
                class_name = str(lst_val)
            else:
                self.m_key_values[lst_key] = lst_val

        DEBUG("class_name=%s",class_name)
        if class_name:
            self.m_source_prefix, colon, self.m_class_name =  class_name.rpartition(":")
        else:
            self.m_source_prefix, self.m_class_name = (None, None)

        DEBUG("prefix:%s", self.m_source_prefix)

    def __repr__(self):
        title = "ObjectKeyValues:" + self.m_object_variable_name + ":"

        if not hasattr(self, 'm_class_name'):
            return title + "NOT_PREPARED_YET"

        if self.m_class_name:
            title += self.m_class_name
        else:
            title += "NoClass"
        title += "*"
        if self.m_associator_key_name:
            title += self.m_associator_key_name
        else:
            title += "NoAssoc"

            title += ".SUBJ=" + str(self.m_associator_subject)
            title += ".KV=" + str(self.m_raw_key_value_pairs)

        title += "@" + ",".join(["%s=%s" % kv for kv in self.m_key_values.items()])
        return title

# This models a result returned from the execution of the join of a Sparql query.
class PathPredicateObject:
    def __init__(self,subject_path, entity_class_name, predicate_object_dict):
        self.m_subject_path = subject_path
        self.m_entity_class_name = entity_class_name
        self.m_predicate_object_dict = predicate_object_dict

    def __repr__(self):
        return "PathPredicateObject:" + self.m_subject_path + ";class="+str(self.m_entity_class_name) + ";dict="+str(self.m_predicate_object_dict)


def chop_namespace(attribute_name):
    prefix, colon, short_key = attribute_name.partition(":")
    return short_key

# This receives a dictionary of key-value pairs for calling the "Select" callback
# of the Sparql Api objet. The namespace of each key is chopped.
def __filter_key_values(where_key_values):
    filtered_where_key_values = {}
    for sparql_key, sparql_value in where_key_values.items():
        short_key = chop_namespace(sparql_key)
        # The local predicate names have to be unique.
        assert(short_key not in filtered_where_key_values)
        filtered_where_key_values[short_key] = sparql_value

    return filtered_where_key_values


"""
En fait, les callbacks ne devraient pas renvoyer des objets !
On a besoin de RDF qu'on va injecter dans le triplestore courant,
sur lequel on va executer la query Sparql.
De plus, il faut que les valeurs de certains attributs des instances puissent aussi etre des objets.
WMI renvoie naturellement des objets, mais les scripts Survol renvoient naturellement du RDF en vrac.
Il faut donc que les callbacks puissent faire les deux:
- Une liste d'objets pour les tests et les jointures, ainsi que le path pour les associators.
- Du RDF "en vrac" injecte dans le triplestore.

REMPLACER LE NODE DU PATH PAR LE PATH D ORIGINE QUI EST NECESSAIRE UNIQUEMENT
POUR LES ASSOCIATORS DE WMI. C EST UNE SIMPLE CHAINE, PAS UNE INSTANCE.
POUR WMI (ET SURVOL "Select" FUNCTION), ON VA SYNTHETISER DU RDF.

MAIS EST-CE QU'IL NE VAUDRAIT PAS MIEUX RECREER DU RDF UNIQUEMENT A LA FIN POUR ALLEGER ?

Lors de la jointure, on accumule le RDF.
"""


# TODO: Several callbacks. Maybe with a key ??
# TODO: Maybe execute callbacks in a sub-process ?
# TODO: Maybe not recursive run because it is too slow.
# TODO: Rather run them once each.
def _run_callback_on_entities(
        grph,
        lst_input_object_key_values,
        query_callback_object):

    def _evaluate_current_entity(index, known_variables, tuple_result_input):
        WARNING("_evaluate_current_entity index=%d known_variables=%s tuple_result_input=%s", index, known_variables, tuple_result_input)
        if index == len(lst_input_object_key_values):
            # Deepest level, last entity is reached, so return a result set.
            yield tuple_result_input
            return
        curr_input_entity = lst_input_object_key_values[index]

        # assert curr_input_entity.m_object_path
        # WARNING("_evaluate_current_entity index=%d curr_input_entity=%s", index, curr_input_entity)

        # This set contains all "seeAlso" values, which are sources of data.
        # This could be the string "WMI", or Survol scripts filenames, or variables,
        # which are evaluated here.
        def evaluate_see_also_sources(object_key_values):
            assert isinstance( object_key_values, ObjectKeyValues )

            set_all_sources = set()

            for one_see_also in object_key_values.m_lst_seeAlso:
                if isinstance(one_see_also, QueryVariable):
                    source_name = one_see_also.m_query_variable_name
                    see_also_name = known_variables[source_name]
                    set_all_sources.add(see_also_name)
                else:
                    set_all_sources.add(one_see_also)

            # The prefix of the attributes is also used as source of data,
            # but not if "rdf" because it is not a proper source.
            if object_key_values.m_source_prefix not in ["rdf","rdfs"]:
                set_all_sources.add(object_key_values.m_source_prefix)

            return set_all_sources

        assert isinstance(curr_input_entity, ObjectKeyValues)
        if not curr_input_entity.m_class_name:
            # Non-typed object.
            # ObjectKeyValues:url_dummy:NoClass*NoAssoc@
            raise Exception("Query without class is not implemented yet:",
                            curr_input_entity.m_raw_key_value_pairs,
                            dir(curr_input_entity),
                            curr_input_entity)

        # (u'rdfs:seeAlso', 'survol:enumerate_python_package')

        predicate_prefix = curr_input_entity.m_source_prefix

        where_key_values_replaced = {}
        dict_variable_to_attribute = {}
        WARNING("curr_input_entity.m_key_values.keys=%s", curr_input_entity.m_key_values.keys())
        for key_as_str, value_attribute in curr_input_entity.m_key_values.items():
            WARNING("key_as_str=%s value_attribute=%s type=%s", key_as_str, value_attribute, str(type(value_attribute)))
            if isinstance(value_attribute, QueryVariable):
                variable_name = value_attribute.m_query_variable_name
                if variable_name in known_variables:
                    where_key_values_replaced[key_as_str] = known_variables[variable_name]
                else:
                    # Variable is not known yet. CA NE DEVRAIT PAS ARRIVER ???
                    WARNING("IS THIS OK ? NOT KNOWN YET key_as_str=%s value_attribute=%s", key_as_str, value_attribute)
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

        # TODO: Reuse result if same input values, instead of calling again.

        # m_associator_subject=ObjectKeyValues:url_subclass:Class*NoAssoc@ m_associator_key_name=rdfs:subClassOf

        # WARNING("curr_input_entity.m_associator_key_name=%s", curr_input_entity.m_associator_key_name)
        # WARNING("curr_input_entity.m_associator_subject=%s", curr_input_entity.m_associator_subject)
        # WARNING("dir(curr_input_entity.m_associator_subject)=%s", dir(curr_input_entity.m_associator_subject))

        # When looking for subclasses, this is not realy an associator, but related to types.
        if curr_input_entity.m_associator_key_name == "rdfs:subClassOf":
            # In this case, m_associator_subject = "ObjectKeyValues:url_subclass:Class*NoAssoc@"
            assert curr_input_entity.m_associator_subject

            # curr_input_entity.m_associator_subject.m_object_path="WmiClass:CIM_Action"
            short_base_class_name = chop_namespace(curr_input_entity.m_associator_subject.m_object_path)

            def _callback_subclasses_of():
                for one_see_also in evaluate_see_also_sources(curr_input_entity.m_associator_subject):
                    # one_see_also=WMI assoc_key=rdfs:subClassOf path=WmiClass:CIM_Action
                    DEBUG("_callback_subclasses_of one_see_also=%s assoc_key=%s path=%s",
                            one_see_also,
                            curr_input_entity.m_associator_key_name,
                            curr_input_entity.m_associator_subject.m_object_path)

                    # 'm_associator_key_name', 'm_associator_subject', 'm_class_name', 'm_key_values', 'm_lst_seeAlso', 'm_object_path', 'm_object_variable_name'
                    DEBUG("_callback_subclasses_of dir(curr_input_entity.m_associator_subject)=%s", dir(curr_input_entity.m_associator_subject))
                    DEBUG("_callback_subclasses_of curr_input_entity.m_associator_key_name=%s", curr_input_entity.m_associator_key_name)
                    DEBUG("_callback_subclasses_of curr_input_entity.m_class_name=%s", curr_input_entity.m_class_name)
                    DEBUG("_callback_subclasses_of curr_input_entity.m_key_values=%s", curr_input_entity.m_key_values)

                    iter_types_results = query_callback_object.CallbackTypeTree(
                        grph,
                        one_see_also,
                        short_base_class_name,
                        curr_input_entity.m_associator_subject)
                    for one_node_dict_pair in iter_types_results:
                        yield one_node_dict_pair
            iter_recursive_results = _callback_subclasses_of()

        elif curr_input_entity.m_associator_subject:
            assert curr_input_entity.m_associator_key_name
            WARNING("evaluate_see_also_sources m_associator_subject=%s m_associator_key_name=%s",
                    curr_input_entity.m_associator_subject, curr_input_entity.m_associator_key_name)

            short_associator_class_name = chop_namespace(curr_input_entity.m_associator_key_name)

            def _callback_filter_all_sources_associators():
                for one_see_also in evaluate_see_also_sources(curr_input_entity.m_associator_subject):
                    WARNING("_callback_filter_all_sources_associators one_see_also=%s assoc_key=%s path=%s",
                            one_see_also,
                            curr_input_entity.m_associator_key_name,
                            curr_input_entity.m_associator_subject.m_object_path)

                    iter_assoc_results = query_callback_object.CallbackAssociator(
                        grph,
                        curr_input_entity.m_class_name,
                        one_see_also,
                        short_associator_class_name,
                        curr_input_entity.m_associator_subject.m_object_path
                    )

                    # The objects should be merged based on what ???
                    for one_node_dict_pair in iter_assoc_results:
                        yield one_node_dict_pair

            iter_recursive_results = _callback_filter_all_sources_associators()

        else:
            assert not curr_input_entity.m_associator_key_name
            WARNING("evaluate_see_also_sources curr_input_entity.m_associator_subject NOT SET")

            def _callback_types_list():
                WARNING("_callback_types_list where_key_values_replaced=%s", where_key_values_replaced)
                for one_see_also in evaluate_see_also_sources(curr_input_entity):
                    iter_types_results = query_callback_object.CallbackTypes(grph, one_see_also, where_key_values_replaced)

                    for one_node_dict_pair in iter_types_results:
                        yield one_node_dict_pair

            def _callback_filter_all_sources_select():
                for one_see_also in evaluate_see_also_sources(curr_input_entity):
                    WARNING("_callback_filter_all_sources_select one_see_also=%s", one_see_also)

                    # one_see_also can be "WMI" or a script like "survol:CIM_DataFile/...".
                    # predicate_prefix, colon, dummy = one_see_also.partition(":")

                    filtered_where_key_values = __filter_key_values(where_key_values_replaced)
                    iter_select_results = query_callback_object.CallbackSelect(
                        grph,
                        curr_input_entity.m_class_name,
                        one_see_also,
                        filtered_where_key_values)

                    for one_node_dict_pair in iter_select_results:
                        yield one_node_dict_pair

            WARNING("_callback_filter_all_sources_select m_source_prefix=%s m_class_name=%s",
                    curr_input_entity.m_source_prefix, curr_input_entity.m_class_name)
            WARNING("_callback_filter_all_sources_select where_key_values_replaced=%s dict_variable_to_attribute=%s",
                    str(where_key_values_replaced), str(dict_variable_to_attribute))
            if curr_input_entity.m_source_prefix == "rdfs" and curr_input_entity.m_class_name == "Class":
                iter_recursive_results = _callback_types_list()
            else:
                iter_recursive_results = _callback_filter_all_sources_select()

        # If there are several associators, they might have returned duplicate objects.
        unique_recursive_results = {}
        WARNING("iter_recursive_results.keys=%s", iter_recursive_results.keys())
        for object_path, dict_key_values in iter_recursive_results:
            try:
                short_base_class_name
                if short_base_class_name == "CIM_LogicalDevice":
                    WARNING("A object_path=%s", object_path)
            except:
                pass

            if object_path in unique_recursive_results:
                unique_recursive_results[object_path].update(dict_key_values)
            else:
                unique_recursive_results[object_path] = dict_key_values

        for object_path, dict_key_values in unique_recursive_results.items():
            # The result is made of URL to CIM objects.
            output_entity = PathPredicateObject(object_path, curr_input_entity.m_class_name, dict_key_values)
            #print("From callback: output_entity=",output_entity)
            # WARNING("B object_path=%s output_entity=%s", object_path, output_entity)

            for variable_name, attribute_key in dict_variable_to_attribute.items():
                #WARNING("index=%d variable_name=%s attribute_key=%s", index, variable_name, attribute_key)
                attribute_key_node = _property_name_to_node(attribute_key)
                WARNING("output_entity.m_predicate_object_dict=%s", str(output_entity.m_predicate_object_dict))
                known_variables[variable_name] = output_entity.m_predicate_object_dict[attribute_key_node]
            tuple_result_extended = tuple_result_input + (output_entity,)

            # object_path = lib_util.NodeUrl(object_path)
            # one_wmi_object.path =\\RCHATEAU - HP\root\cimv2:Win32_Process.Handle = "26720"
            # Loop on the results ?
            curr_input_entity.m_object_path = object_path

            # NON: Executer seulement pour chaque combinaison de variables reellement utilisees.
            # Sinon reutiliser le resultat.
            output_results = _evaluate_current_entity(index + 1, known_variables, tuple_result_extended)
            for one_resu in output_results:
                yield one_resu

        # assert curr_input_entity.m_object_path

    itr_tuple_results = _evaluate_current_entity(0, known_variables={}, tuple_result_input=tuple())
    for tuple_results in itr_tuple_results:
        yield tuple_results

# This returns rows of fetched results, of similar structures.
# Each result is a dictionary: The keys are some selected variables
# of the Sparql query, only subject variables (possibly also used as objects).
# The values are dictionary of key-value pairs which define the variable.
def QueryEntities(grph, sparql_query, query_callback_object):
    # This returns a list of ObjectKeyValues
    object_key_values = _parse_query_to_key_value_pairs_list(sparql_query)

    WARNING("QueryEntities object_key_values=%s", str(object_key_values))

    # This is a list of variables representing URLs of objects with key-values, fetched from WQL or Survol scripts.
    input_keys = [ entity_by_variable.m_object_variable_name for entity_by_variable in object_key_values ]
    for tuple_results in _run_callback_on_entities(grph, object_key_values, query_callback_object):
        yield dict(zip(input_keys,tuple_results))


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


def QuerySeeAlsoEntities(grph, sparql_query, query_callback_object):
    return QueryEntities(grph, sparql_query, query_callback_object)

##################################################################################

# This runs a Sparql callback and transforms the returned objects into RDF triples.
def QueryToGraph(grph, sparql_query, query_callback_object):

    iter_entities_dicts = QueryEntities(grph, sparql_query, query_callback_object)

    # FIXME: Survol scripts are not able to return objects,
    # FIXME: but they natively create triples which can be fed into the graph:
    # FIXME: Survol scripts just return the minimum set of data allowing to join with other clauses.
    #
    # FIXME: On the other hand, WMI returns objects but cannot natively create RDF triples.
    # FIXME: Therefore, it makes sense to create triples from the objects.

    # sys.stderr.write("QueryToGraph len(iter_entities_dicts)=%s\n" % len(iter_entities_dicts))

    for one_dict_entity in iter_entities_dicts:
        #sys.stderr.write("QueryToGraph one_dict_entity=%s\n"%one_dict_entity)
        for variable_name, sparql_object in one_dict_entity.items():
            # Dictionary of variable names to PathPredicateObject
            subject_path_node = lib_util.NodeUrl(sparql_object.m_subject_path)
            for key, val in sparql_object.m_predicate_object_dict.items():
                grph.add((subject_path_node, key, val))

    # TODO: Adds the ontology: Classes and predicates. AddOntology(grph)

##################################################################################

# All methods of the callback api interface must returns results
# of the same structure.

# This meta-callback dispatches the query to the right data source.
class SwitchCallbackApi:
    def __init__(self, prefix_to_callbacks):
        self.m_prefix_to_callbacks = prefix_to_callbacks
        # prefix_to_callbacks = {
        #    "HardCoded": HardcodeSparqlCallbackApi(),
        #    "WMI": objectWmiSparqlCallbackApi,
        #    "survol": lib_sparql_callback_survol.SurvolSparqlCallbackApi(),
        #}

    def CallbackSelect(self, grph, class_name, see_also, where_key_values):
        predicate_prefix, colon, see_also_script = see_also.partition(":")
        callback_object = self.m_prefix_to_callbacks[predicate_prefix]
        return callback_object.CallbackSelect(grph, class_name, see_also, where_key_values)

    def CallbackAssociator(self, grph, result_class_name, see_also, associator_key_name, subject_path):
        predicate_prefix, colon, see_also_script = see_also.partition(":")
        callback_object = self.m_prefix_to_callbacks[predicate_prefix]
        return callback_object.CallbackAssociator(grph, result_class_name, see_also, associator_key_name, subject_path)

    def CallbackTypes(self, grph, see_also, where_key_values):
        WARNING("SwitchCallbackApi.CallbackTypes see_also=%s", see_also)
        predicate_prefix, colon, see_also_script = see_also.partition(":")
        callback_object = self.m_prefix_to_callbacks[predicate_prefix]
        return callback_object.CallbackTypes(grph, see_also, where_key_values)

    def CallbackTypeTree(self, grph, see_also, class_name, associator_subject):
        #WARNING("SwitchCallbackApi.CallbackTypes see_also=%s", see_also)
        predicate_prefix, colon, see_also_script = see_also.partition(":")
        callback_object = self.m_prefix_to_callbacks[predicate_prefix]
        return callback_object.CallbackTypeTree(grph, see_also, class_name, associator_subject)


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
