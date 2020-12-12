import os
import sys
import rdflib
import lib_util
import lib_kbase
import lib_naming
import lib_exports
import lib_properties
from lib_properties import pc

################################################################################


def FlushOrSaveRdfGraph(grph, output_rdf_filename):
    """This dumps the triplestore graph to the current output socket if called in a HTTP server.
    Otherwise it saves the result to a text file, for testing or debugging."""
    INFO("FlushOrSaveRdfGraph l=%s sys.argv=%s",len(sys.argv),str(sys.argv))

    try:
        os.environ["QUERY_STRING"]
        INFO("FlushOrSaveRdfGraph to stream")
        lib_util.WrtHeader('text/html')

        out_dest = lib_util.get_default_output_destination()
        lib_kbase.triplestore_to_stream_xml(grph,out_dest, 'pretty-xml')

    except KeyError:
        INFO("FlushOrSaveRdfGraph onto_filnam=%s",output_rdf_filename)
        outfil = open(output_rdf_filename, "w")
        lib_kbase.triplestore_to_stream_xml(grph,outfil, 'pretty-xml')
        outfil.close()

################################################################################


# FIXME: This does translation also.
# FIXME: So it could be faster is Survol natively uses RDF model,
# FIXME: ... for example RDFS.seeAlso for scripts, RDFS.comment for property_information.
# FIXME: Ideally we should simply add extra data to the input graph, without trabsation..
#
# FIXME: A specific and standard  RDF property should be chosen for sort order, not RDFS.comment.
# FIXME: Or add, for a collapsed/tabulated property, the property which gives its order, by default RDFS.comment.
# FIXME: Instead of a list of collapsed properties, it would be a map whose value would be the key.
# FIXME: Maybe it could be the "key" instead of the "order" ?
# FIXME: Later, it can be interesting to change the ordering key for the children of a specific node only.
#
def _add_ontology(old_grph):
    """This receives a triplestore containing only the information from scripts.
    This adds the classes and the properties information,
    in order to send it to an external database or system. This returns a new graph."""

    map_classes = {}
    map_attributes = {}

    new_grph = rdflib.Graph()

    def _define_class_in_ontology(url_node):
        """This takes the class from an Url and defines it in the RDF ontology.
        This returns the class name as a string."""
        entity_label, class_name, entity_id = lib_naming.ParseEntityUri(url_node)

        # This could be: ("http://the_host", "http://primhillcomputers.com/survol/____Information", "HTTP url")
        if not class_name:
            return None

        # TODO: Define base classes with rdfs:subClassOf / RDFS.subClassOf
        # "base_class" and "class_description' ???

        # A class name with the WMI namespace might be produced with this kind of URL:
        # "http://www.primhillcomputers.com/survol#root\CIMV2:CIM_Process"
        class_name = class_name.replace("\\", "%5C")

        if class_name not in map_classes:
            if class_name == "":
                raise Exception("No class name for url=%s type=%s" % (str(url_node), str(type(url_node))))

            # Maybe this CIM class is not defined as an RDFS class.
            # This function might also filter duplicate and redundant insertions.
            lib_util.AppendClassSurvolOntology(class_name, map_classes, map_attributes)

        # The entity_id is a concatenation of CIM properties and define an unique object.
        # They are different of the triples, but might overlap.
        entity_id_dict = lib_util.SplitMoniker(entity_id)
        for predicate_key in entity_id_dict:
            if predicate_key not in map_attributes:
                # This function might also filter a duplicate and redundant insertion.
                lib_util.AppendPropertySurvolOntology(
                    predicate_key,
                    "CIM key predicate %s" % predicate_key,
                    class_name,
                    None,
                    map_attributes)

            # This value is explicitly added to the node.
            predicate_value = entity_id_dict[predicate_key]
            new_grph.add((url_node, lib_properties.MakeProp(predicate_key), rdflib.Literal(predicate_value)))

        # This adds a triple specifying that this node belongs to this RDFS class.
        lib_kbase.AddNodeToRdfsClass(new_grph, url_node, class_name, entity_label)

        return class_name

    def _url_cleanup(url_node):
        """This is needed for GraphDB which does not accept spaces and backslashes in URL.
        With this, a graph can be uploaded in OntoText."""
        url_as_str = str(url_node)
        url_as_str = url_as_str.replace(" ", "%20")
        url_as_str = url_as_str.replace("\\", "%5C")
        url_as_str = url_as_str.replace("[", "%5B")
        url_as_str = url_as_str.replace("]", "%5D")
        url_as_str = url_as_str.replace("{", "%7B")
        url_as_str = url_as_str.replace("}", "%7D")
        if lib_kbase.IsLiteral(url_node):
            url_node = rdflib.Literal(url_as_str)
        else:
            url_node = rdflib.term.URIRef(url_as_str)
        return url_node

    for node_subject, node_predicate, node_object in old_grph:
        node_subject = _url_cleanup(node_subject)
        node_object = _url_cleanup(node_object)
        if node_predicate == pc.property_script:
            # The subject might be a literal directory containing provider script files.
            if not lib_kbase.IsLiteral(node_subject):
                if lib_kbase.IsLiteral(node_object):
                    new_grph.add((node_subject, lib_kbase.PredicateSeeAlso, node_object))
                else:
                    str_object = str(node_object)
                    str_object_rdf = str_object + "&mode=rdf"
                    node_object_rdf = rdflib.term.URIRef(str_object_rdf)
                    new_grph.add((node_subject, lib_kbase.PredicateSeeAlso, node_object_rdf))
        elif node_predicate == pc.property_information:
            new_grph.add((node_subject, lib_kbase.PredicateComment, node_object))
        else:
            class_subject = _define_class_in_ontology(node_subject)
            if not lib_kbase.IsLiteral(node_object):
                class_object = _define_class_in_ontology(node_object)
            else:
                class_object = None

            name_predicate, dict_predicate = lib_exports.PropToShortPropNamAndDict(node_predicate)
            try:
                description_predicate = dict_predicate["property_description"]
            except:
                description_predicate = ""

            if class_subject and (name_predicate not in map_attributes):
                # This function might also filter a duplicate and redundant insertion.
                lib_util.AppendPropertySurvolOntology(
                    name_predicate, description_predicate, class_subject, class_object, map_attributes)

            # TODO: Add the property type. Experimental because we know the class of the object, or if it is a literal.
            new_grph.add((node_subject, node_predicate, node_object))

    lib_kbase.CreateRdfsOntology(map_classes, map_attributes, new_grph)
    DEBUG("_add_ontology len(grph)=%d map_classes=%d map_attributes=%d len(new_grph)=%d",
          len(new_grph), len(map_classes), len(map_attributes), len(new_grph))

    return new_grph


def Grph2Rdf(grph):
    """Used by all CGI scripts when they have finished adding triples to the current RDF graph.
    The RDF comment is specifically processed to be used by ontology editors such as Protege."""
    DEBUG("Grph2Rdf entering")

    new_grph = _add_ontology(grph)

    # Neither "xml/rdf" nor "text/rdf" are correct MIME-types.
    # It should be "application/xml+rdf" or possibly "application/xml" or "text/xml"
    # 'text/rdf' and 'xml/rdf' are OK with Protege
    # 'application/xml+rdf' creates a file.
    lib_util.WrtHeader('application/xml')

    out_dest = lib_util.get_default_output_destination()

    lib_kbase.triplestore_to_stream_xml(new_grph, out_dest, 'xml')
    DEBUG("Grph2Rdf leaving")


def WriteRdfError(message, broken_url):
    """This is called only by ErrorMessageHtml when an error is detected and the output format is RDF.
    After that, the calling function makes an exit.
    """

    new_grph = rdflib.Graph()
    new_grph.add((
        rdflib.term.URIRef(broken_url),
        lib_properties.pc.property_error,
        rdflib.Literal(message)))

    # Neither "xml/rdf" nor "text/rdf" are correct MIME-types.
    # It should be "application/xml+rdf" or possibly "application/xml" or "text/xml"
    # 'text/rdf' and 'xml/rdf' are OK with Protege
    # 'application/xml+rdf' creates a file.
    lib_util.WrtHeader('application/xml')

    out_dest = lib_util.get_default_output_destination()

    lib_kbase.triplestore_to_stream_xml(new_grph, out_dest, 'xml')

