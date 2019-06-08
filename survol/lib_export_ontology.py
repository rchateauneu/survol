import os
import sys
import lib_util
import lib_kbase
import lib_naming
import lib_exports
import lib_properties
from lib_properties import pc

################################################################################

# This dumps the triplestore graph to the current output socket if called
# in a HTTP server.
# Otherwise it saves the result to a text file, for testing or debugging.
def FlushOrSaveRdfGraph(grph, output_rdf_filename):
    INFO("FlushOrSaveRdfGraph l=%s sys.argv=%s",len(sys.argv),str(sys.argv))

    try:
        os.environ["QUERY_STRING"]
        INFO("FlushOrSaveRdfGraph to stream")
        lib_util.WrtHeader('text/html')

        out_dest = lib_util.DfltOutDest()
        lib_kbase.triplestore_to_stream_xml(grph,out_dest,'pretty-xml')

    except KeyError:
        INFO("FlushOrSaveRdfGraph onto_filnam=%s",output_rdf_filename)
        outfil = open(output_rdf_filename, "w")
        lib_kbase.triplestore_to_stream_xml(grph,outfil,'pretty-xml')
        outfil.close()

################################################################################

# This receives a triplestore containing only the information from scripts.
# This adds the classes and the properties information,
# in order to send it to an external database or system.
# This returns a new graph.
# FIXME: WHY CREATING A NEW GRAPH ?? Maybe because we could not remove some information ?? Which one ??
# FIXME: Maybe to remove the scripts ?
def AddOntology(old_grph):
    DEBUG("AddOntology")
    map_classes = {}
    map_attributes = {}

    new_grph = lib_kbase.MakeGraph()

    # This takes the class from an Url and defines it in the RDF ontology.
    # This returns the class name as a string.
    def DefineClassInOntology(urlNode):
        (entity_label, class_name, entity_id) = lib_naming.ParseEntityUri( urlNode )

        # This could be the triplet: ("http://rchateau-hp", "http://primhillcomputers.com/survol/____Information", "HTTP url")
        if not class_name:
            return None

        # TODO: Define base classes with rdfs:subClassOf / RDFS.subClassOf
        # "base_class" and "class_description' ???

        # Pour les ontologi'ed, a-t-on les memes proprietes pour WMI, Survol et WBEM ?
        # Et sinon, on les fait deriver les unes-des-autres ?
        # "wmi:Handle" et "survol:Handle" sont la meme chose pour RDF ?
        # "wmi:CIM_Process" et "survol:CIM_Process" ?
        # Le fait que RDF puisse exprimer que "Win32_CIM_Process" derive de "CIM_Process" ... L'utiliser.
        # Comment exprimer dans RDF qu'on veut aller chercher des infos dans le namespace (et donc le serveur)
        # wmi ou survol, mais que ca renvoie des objects de la meme ontologie ??



        # A class name with the WMI namespace might be produced with this kind of URL:



        # "http://www.primhillcomputers.com/survol#root\CIMV2:CIM_Process"
        class_name = class_name.replace("\\","%5C")

        if not class_name in map_classes:
            if class_name == "":
                raise Exception("No class name for url=%s type=%s"%(str(urlNode),str(type(urlNode))))

            # Maybe this CIM class is not defined as an RDFS class.
            # This function might also filter duplicate and redundant insertions.
            lib_util.AppendClassSurvolOntology(class_name, map_classes, map_attributes)

        # The entity_id is a concatenation of CIM properties and define an unique object.
        # They are different of the triples, but might overlap.
        entity_id_dict = lib_util.SplitMoniker(entity_id)
        for keyPred in entity_id_dict:
            if not keyPred in map_attributes:
                # This function might also filter a duplicate and redundant insertion.
                lib_util.AppendPropertySurvolOntology(keyPred, "CIM key predicate %s" % keyPred, class_name, None, map_attributes)

            # This value is explicitly added to the node.
            valPred = entity_id_dict[keyPred]
            new_grph.add((urlNode, lib_properties.MakeProp(keyPred), lib_kbase.MakeNodeLiteral(valPred)))

        # This adds a triple specifying that this node belongs to this RDFS class.
        lib_kbase.AddNodeToRdfsClass(new_grph, urlNode, class_name, entity_label)

        return class_name

    # This is needed for GraphDB which does not accept spaces and backslashes in URL.
    def CleanupUrl(nodeUrl):
        strUrl = str(nodeUrl)
        strUrl = strUrl.replace(" ","%20")
        strUrl = strUrl.replace("\\","%5C")
        strUrl = strUrl.replace("[","%5B")
        strUrl = strUrl.replace("]","%5D")
        strUrl = strUrl.replace("{","%7B")
        strUrl = strUrl.replace("}","%7D")
        if lib_kbase.IsLiteral(nodeUrl):
            nodeUrl = lib_kbase.MakeNodeLiteral(strUrl)
        else:
            nodeUrl = lib_kbase.MakeNodeUrl(strUrl)
        return nodeUrl

    for nodeSubject, nodePredicate, nodeObject in old_grph:
        nodeSubject = CleanupUrl(nodeSubject)
        nodeObject = CleanupUrl(nodeObject)
        if nodePredicate == pc.property_script:
            # The subject might be a literal directory containing provider script files.
            if not lib_kbase.IsLiteral(nodeSubject):
                if lib_kbase.IsLiteral(nodeObject):
                    new_grph.add( (nodeSubject, lib_kbase.PredicateSeeAlso, nodeObject))
                else:
                    strObject = str(nodeObject)
                    strObjectRdf = strObject + "&mode=rdf"
                    nodeObjectRdf = lib_kbase.MakeNodeUrl(strObjectRdf)
                    new_grph.add( (nodeSubject, lib_kbase.PredicateSeeAlso, nodeObjectRdf))
        elif nodePredicate == pc.property_information:
            new_grph.add( (nodeSubject, lib_kbase.PredicateComment, nodeObject))
        else:
            classSubject = DefineClassInOntology(nodeSubject)
            if not lib_kbase.IsLiteral(nodeObject):
                classObject = DefineClassInOntology(nodeObject)
            else:
                classObject = None

            namePredicate, dictPredicate = lib_exports.PropToShortPropNamAndDict(nodePredicate)
            try:
                descriptionPredicate = dictPredicate["property_description"]
            except:
                descriptionPredicate = ""

            if classSubject and (namePredicate not in map_attributes):
                # This function might also filter a duplicate and redundant insertion.
                lib_util.AppendPropertySurvolOntology(namePredicate, descriptionPredicate, classSubject, classObject, map_attributes)

                # TODO: Add the property type. Experimental because we know the class of the object, or if this is a literal.
            new_grph.add((nodeSubject, nodePredicate, nodeObject))

    lib_kbase.CreateRdfsOntology(map_classes, map_attributes, new_grph)
    DEBUG("AddOntology len(grph)=%d map_classes=%d map_attributes=%d len(new_grph)=%d",
          len(new_grph), len(map_classes), len(map_attributes), len(new_grph))

    return new_grph

################################################################################
# Used by all CGI scripts when they have finished adding triples to the current RDF graph.
# The RDF comment is specifically processed to be used by ontology editors such as Protege.
def Grph2Rdf(grph):
    DEBUG("Grph2Rdf entering")

    new_grph = AddOntology(grph)

    # Neither "xml/rdf" nor "text/rdf" are correct MIME-types. It should be "application/xml+rdf" or possibly "application/xml" or "text/xml"

    #lib_util.WrtHeader('text/rdf') # OK with Protege
    #lib_util.WrtHeader('xml/rdf') # OK with Protege
    #lib_util.WrtHeader('application/xml+rdf') # Creates a file.
    lib_util.WrtHeader('application/xml')

    out_dest = lib_util.DfltOutDest()

    lib_kbase.triplestore_to_stream_xml(new_grph, out_dest, 'xml')
    DEBUG("Grph2Rdf leaving")

################################################################################

