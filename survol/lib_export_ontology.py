import os
import sys
import lib_util
import lib_kbase
import lib_naming
import lib_exports
import lib_properties
from lib_properties import pc

################################################################################

# This dumps the ontology to a HTTP socket.
# This can also save the results to a file, for later use.
def DumpOntology(grph, onto_filnam):
    INFO("DumpOntology l=%s sys.argv=%s",len(sys.argv),str(sys.argv))

    try:
        os.environ["QUERY_STRING"]
        INFO("DumpOntology to stream")
        # lib_util.WrtAsUtf("Content-type: text/html\n\n")
        lib_util.WrtHeader('text/html')

        out_dest = lib_util.DfltOutDest()
        # out_dest.write(u"Content-type: text/html\n\n")
        lib_kbase.triplestore_to_stream_xml(grph,out_dest,'pretty-xml')

        #SaveToStream(out_dest)
    except KeyError:
        INFO("DumpOntology onto_filnam=%s",onto_filnam)
        outfil = open(onto_filnam,"w")
        #SaveToStream(outfil)
        lib_kbase.triplestore_to_stream_xml(grph,outfil,'pretty-xml')
        outfil.close()

################################################################################

# This receives a triplestore containing only the information from scripts.
# This adds the classes and the properties information,
# in order to send it to an external database or system.
def AddOntology(grph):
    DEBUG("AddOntology")
    map_classes = {}
    map_attributes = {}

    # This takes the class from an Url and defines it in the RDF ontology.
    # This returns the class name as a string.
    def AddObjectToClass(urlNode):
        (entity_label, class_name, entity_id) = lib_naming.ParseEntityUri( urlNode )

        # This could be the triplet: ("http://rchateau-hp", "http://primhillcomputers.com/survol/____Information", "HTTP url")
        if not class_name:
            return None

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
                lib_util.AppendPropertySurvolOntology(keyPred, class_name, None, map_attributes)

            # This value is explicitely added to the node.
            valPred = entity_id_dict[keyPred]
            grph.add((urlNode, lib_properties.MakeProp(keyPred), lib_kbase.MakeNodeLiteral(valPred)))


        # This adds a triple specifying that this node belongs to this RDFS class.
        lib_kbase.AddNodeToRdfsClass(grph, urlNode, class_name, entity_label)

        return class_name

    for nodeSubject, nodePredicate, nodeObject in grph:
        # Quick hack if nodeObject="http://rchateau-hp" or any other URL not from Survol.
        classSubject = AddObjectToClass( nodeSubject )
        if not lib_kbase.IsLiteral( nodeObject ):
            classObject = AddObjectToClass( nodeObject )
        else:
            classObject = None

        #if nodePredicate == pc.property_information:
        # rdfs.comment

        namePredicate = lib_exports.PropToShortPropNam(nodePredicate)
        if classSubject and ( not namePredicate in map_attributes ):
            # This function might also filter a duplicate and redundant insertion.
            lib_util.AppendPropertySurvolOntology(namePredicate, classSubject, classObject, map_attributes)


            # TODO: Add the type of the property. Experimental because we know the class of the object, or if this is a literal.
            # The comments should be defined in lib_properties.

    DEBUG("AddOntology len(grph)=%d map_classes=%d map_attributes=%d",len(grph),len(map_classes),len(map_attributes))
    lib_kbase.CreateRdfsOntology(map_classes, map_attributes, grph)
    DEBUG("AddOntology len(grph)=%d",len(grph))

################################################################################
# Used by all CGI scripts when they have finished adding triples to the current RDF graph.
# The RDF comment is specifically processed to be used by ontology editors such as Protege.
def Grph2Rdf(grph):
    DEBUG("Grph2Rdf")

    # TODO: Should we add the OWL-DL or the RDFS ontology ?
    AddOntology(grph)

    lib_util.WrtHeader('text/rdf')

    # Format support can be extended with plugins,
    # but 'xml', 'n3', 'nt', 'trix', 'rdfa' are built in.
    out_dest = lib_util.DfltOutDest()

    # RDFS uses a special predicate for comments.
    # TODO: We could use the original RDFS predicate instead of replacing.
    #lib_kbase.triplestore_set_comment(grph, pc.property_information)

    lib_kbase.triplestore_to_stream_xml(grph,out_dest,'xml')

################################################################################

