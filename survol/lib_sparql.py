# This transforms a SPARQL query into a WMI/WBEM query.
# This is extremely restricted.
from __future__ import print_function

import sys
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
            # strJson = grph.serialize( destination = None, format = rdflib_format)
            sys.stderr.write("len grph=%d\n"%len(grph))
            strJson = grph.serialize(format=self.m_rdflib_format)
            # strJson = grph.serialize(format='json-ld', indent=4)
        except Exception as exc:
            sys.stderr.write("Caught:%s\n"%exc)
            return
        sys.stderr.write("strJson=%s\n"%strJson)
        lib_util.WrtAsUtf(strJson)

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

# This returns a list of lists of tokens.
# These second-level lists of tokens are a SPARQL list of patterns,
# that is, patterns separated by a semi-colon,
# because they share the same subject, or commas if they share the subject and the predicate,
# ended by a dot. When returned, the list of patterns have a length multiple of three,
# because it is made of concatenated RDF triples.
def get_triples(arg_elt):
    if arg_elt.__class__.__name__ == "CompValue":
        for key2 in arg_elt:
            val2 = arg_elt[key2]
            if key2 == "triples":
                return val2
            res = get_triples(val2)
            if res:
                return res
    elif arg_elt.__class__.__name__ in ["ParseResults","plist"]:
        for elt2 in arg_elt:
            res = get_triples(elt2)
            if res:
                return res
    return None

# This groups tokens by sequence of three, to create triples.
# All SPARQL constraints are mixed together
def aggregate_into_triples(raw_trpl):
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

# This receives a predicate object, which is a directory containing the predicate local name
# and the prefix. It returns a concatenation of the two.
def pname_to_string(pname):
    # pname_pname_{'localname': u'pid', 'prefix': u'survol'}
    value_localname = pname['localname']
    try:
        value_prefix = pname['prefix']
    except KeyError:
        value_prefix = ""
    value_name = value_prefix + ":" + value_localname
    return value_name

def decode_parsed_subject(subj):
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
            return("TRPL_VALUE_NAME",pname_to_string(subj))
    raise Exception("Cannot parse ERRSUBJsubj=",str(subj))

def decode_parsed_predicate(pred):
    # PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'pid', 'prefix': u'survol'}}]}]}
    if isinstance(pred,rdflib.plugins.sparql.parserutils.CompValue):
        try:
            one_part = pred['part']
        except KeyError:
            print("pred=",pred)
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
                            resu = pname_to_string(one_part_part_first_part)
                            return("TRPL_PREDICATE",resu)
                        else:
                            return("TRPL_URIREF",str(one_part_part_first_part))

    elif isinstance(pred,rdflib.term.Variable):
        # rdflib.term.Variable(u'p')
        return("TRPL_VARIABLE",str(pred))
    elif isinstance(pred,rdflib.term.BNode):
        return("TRPL_NODE",pred)
    else:
        print("ERROR")

        print("***:",type(pred))
        print("***:",dir(pred))
        raise Exception("Cannot parse")

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
def decode_parsed_triple(one_trpl):
    s0 = decode_parsed_subject(one_trpl[0])
    s1 = decode_parsed_predicate(one_trpl[1])
    s2 = decode_parsed_subject(one_trpl[2])

    clean_trpl = [s0,s1,s2]
    return clean_trpl

def GenerateTriplesList(qry):
    parsed = rdflib.plugins.sparql.parser.parseQuery(qry)

    raw_trpl = get_triples(parsed)
    trpl_lst = aggregate_into_triples(raw_trpl)
    for one_trpl in trpl_lst:
        clean_trpl = decode_parsed_triple(one_trpl)
        yield clean_trpl

class EntityQuery:
    def __init__(self,variable_name):
        self.m_variable_name = variable_name
        self.m_input_variables = set()
        self.m_attributes = {}

    def __repr__(self):
        resu = str(self.m_attributes)
        resu += " <= " + str(list(self.m_input_variables))
        return resu

class QueryVariable:
    def __init__(self,variable_name):
        self.m_variable_name = variable_name

    def __repr__(self):
        return "??" + self.m_variable_name + "??"

    def __eq__(self, other):
        return self.m_variable_name == other.m_variable_name


# TODO: When the subject is NOT a variable but an URL.

def ExtractEntitiesWithVariableAttributes(lst_triples):
    dictEntitiesByVariable = {}

    # Gathers attributes of objects.
    for one_triple in lst_triples:
        if one_triple[0][0] != "TRPL_VARIABLE":
            continue
        # The predicate type could be "TRPL_VARIABLE"
        if one_triple[1][0] != "TRPL_PREDICATE":
            continue
        object_parsed_type = one_triple[2][0]
        if object_parsed_type == "TRPL_LITERAL":
            attribute_value = one_triple[2][1]
        elif object_parsed_type  == "TRPL_VARIABLE":
            attribute_value = QueryVariable( one_triple[2][1] )
        elif object_parsed_type  == "TRPL_VALUE_NAME":
            # A node defined in a namespace: type:LandlockedCountries, prop:populationEstimate
            # TODO: Treated like a literal.
            attribute_value = one_triple[2][1]
        else:
            print("AAAAA object_parsed_type=",object_parsed_type)
            continue

        variable_name = one_triple[0][1]
        try:
            class_dict = dictEntitiesByVariable[variable_name]
        except KeyError:
            class_dict = {}
            dictEntitiesByVariable[variable_name] = class_dict
        class_dict[one_triple[1][1]] = attribute_value

    return dictEntitiesByVariable

class SparqlObject:
    def __init__(self,class_name,key_values):
        self.m_class_name = class_name
        self.m_key_values = key_values
    def __repr__(self):
        return "SparqlObject:" + self.m_class_name + ":" + ",".join( [ "%s=%s" % kv for kv in self.m_key_values.items() ] )

# TODO: Several callbacks. Maybe with a key ??
# TODO: Maybe execute callbacks in a sub-process ?
def QueryEntitiesFromList(lst_input_entities, execute_query_callback, predicate_prefix):

    def Evaluate( index, known_variables, tuple_result_input):
        if index == len(lst_input_entities):
            # Deepest level, last entity is reached.
            yield tuple_result_input
            return
        curr_input_entity = lst_input_entities[index]

        key_values = {}
        lst_variables = {}
        for key_attribute in curr_input_entity.m_key_values:
            value_attribute = curr_input_entity.m_key_values[key_attribute]
            if isinstance(value_attribute,QueryVariable):
                variable_name = value_attribute.m_variable_name
                if variable_name in known_variables:
                    key_values[key_attribute] = known_variables[variable_name]
                else:
                    # Variable is not known yet
                    lst_variables[variable_name] = key_attribute
            else:
                key_values[key_attribute] = value_attribute

        print("    "*index + "lst_variables=",lst_variables)
        for oneEntity in CallbackFilter(execute_query_callback, predicate_prefix, curr_input_entity.m_class_name, key_values):
        # for oneEntity in execute_query_callback(curr_input_entity.m_class_name, key_values):
            # The result is made of URL to CIM objects.
            output_entity = SparqlObject(curr_input_entity.m_class_name, oneEntity )

            for variable_name in lst_variables:
                known_variables[variable_name] = oneEntity[lst_variables[variable_name]]
            tuple_result_extended = tuple(list(tuple_result_input)) + (output_entity,)
            output_results = Evaluate( index + 1, known_variables, tuple_result_extended)
            for one_resu in output_results:
                print("    "*index + "yield===",str(one_resu))
                yield one_resu

    itr_tuple_results = Evaluate(0,known_variables={},tuple_result_input=tuple())
    for tuple_results in itr_tuple_results:
        yield tuple_results

def QueryEntities(dictEntitiesByVariable, execute_query_callback, predicate_prefix):
    # This receives the key-value pairs taken from an identity extracted from the triples of a SPARQL query.
    def ExtractClass(key_vals):
        # If the class is not defined, cannot query.
        # TODO: Consider base classes ??
        try:
            class_name = key_vals['rdf:type']
            del key_vals['rdf:type']
        except KeyError:
            return (None,None)

        return SparqlObject( class_name, key_vals )

    # The order of nested loops is very important for performances.
    # Input entites might be reordered here.
    lst_input_entities = []
    for variable_name in dictEntitiesByVariable:
        one_input_entity = ExtractClass( dictEntitiesByVariable[variable_name] )
        lst_input_entities.append( one_input_entity )

    input_keys = dictEntitiesByVariable.keys()
    for tuple_results in QueryEntitiesFromList(lst_input_entities, execute_query_callback, predicate_prefix):
        yield dict(zip(input_keys,tuple_results))

# Special pass to replace "a" by "rdf:type
def PredicateSubstitution(lstTriples):
    for clean_trpl in lstTriples:
        print("--------------------")
        print("Subj:",clean_trpl[0])
        print("Pred:",clean_trpl[1])
        print("Obj:",clean_trpl[2])

        print("p=",clean_trpl[1])
        print("p=",type(clean_trpl[1]))
        if clean_trpl[1][1] == 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type':
            print("OK")
            yield clean_trpl[0], ('TRPL_PREDICATE',"rdf:type"), clean_trpl[2]
        else:
            yield clean_trpl


def ParseQueryToEntities(qry):
    lstTriples = GenerateTriplesList(qry)
    lstTriplesReplaced = PredicateSubstitution(lstTriples)

    dictEntitiesByVariable = ExtractEntitiesWithVariableAttributes(lstTriplesReplaced)
    return dictEntitiesByVariable

def ObjectsToGrph(grph,list_objects):
    for curr_input_entity in list_objects:
        nodeObject = lib_common.gUriGen.UriMakeFromDict(curr_input_entity.m_class_name, curr_input_entity.m_key_values)

        for attrKey, attrVal in curr_input_entity.m_key_values.items():
            grph.add(( nodeObject, lib_properties.MakeProp(attrKey), lib_kbase.MakeNodeLiteral(attrVal) ) )


def CallbackFilter(execute_query_callback, predicate_prefix, class_name, where_key_values):
    # The attributes will contain a RDF namespace
    predicate_prefix_colon = predicate_prefix + ":"

    filtered_where_key_values = {}
    for sparql_key, sparql_value in where_key_values.items():
        assert( sparql_key.startswith(predicate_prefix_colon) )
        short_key = sparql_key[len(predicate_prefix_colon):]
        # The local predicate names have to be unique.
        assert(short_key not in filtered_where_key_values)
        filtered_where_key_values[short_key] = sparql_value

    iter_enumeration = execute_query_callback( class_name, filtered_where_key_values )

    # This re-adds the prefix.
    for one_key_value_dict in iter_enumeration:
        prefixed_key_value_dict = { predicate_prefix_colon + key : value for key,value in one_key_value_dict.items() }
        yield prefixed_key_value_dict


# This returns an iterator of a given class,
# which must match the input key-value pairs.
# Each object is modelled by a key-value dictionary.
# No need to return the class name because it is an input parameter.
def SurvolExecuteQueryCallback(class_name, filtered_where_key_values):
    print("SurvolExecuteQueryCallback class_name=", class_name, " where_key_values=", filtered_where_key_values)

    entity_module = lib_util.GetEntityModule(class_name)
    if entity_module:
        try:
            enumerate_function = entity_module.SelectFromWhere
        except AttributeError:
            exc = sys.exc_info()[1]
            INFO("No Enumerate for %s", class_name, str(exc) )
            return

    iter_enumeration = enumerate_function( filtered_where_key_values )

    # This re-adds the prefix.
    for one_key_value_dict in iter_enumeration:
        yield one_key_value_dict


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

