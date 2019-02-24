import os
import sys
import lib_util
import lib_kbase
import lib_naming
import lib_exports

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

    def AddOneClass(urlNode):
        (entity_label, class_name, entity_id) = lib_naming.ParseEntityUri( urlNode )
        if not class_name in map_classes:
            DEBUG("AddOneClass %s",class_name)
            # This function might also filter a duplicate and redundant insertion.
            lib_util.AppendClassSurvolOntology(class_name, map_classes, map_attributes)
        # TODO: DO THAT ONCE ONLY PER NODE
        # TODO: DO THAT ONCE ONLY PER NODE
        # TODO: DO THAT ONCE ONLY PER NODE
        lib_kbase.AddNodeToRdfsClass(grph, urlNode, class_name, entity_label)

    for nodeSubject, nodePredicate, nodeObject in grph:
        AddOneClass( nodeSubject )
        if not lib_kbase.IsLiteral( nodeObject ):
            AddOneClass( nodeObject )

        namePredicate = lib_exports.PropToShortPropNam(nodePredicate)
        if not namePredicate in map_attributes:
            # This function might also filter a duplicate and redundant insertion.
            lib_util.AppendPropertySurvolOntology(namePredicate, map_attributes)

    DEBUG("AddOntology map_classes=%d map_attributes=%d",len(map_classes),len(map_attributes))
    DEBUG("AddOntology len(grph)=%d",len(grph))
    lib_kbase.CreateRdfsOntology(map_classes, map_attributes, grph)
    DEBUG("AddOntology len(grph)=%d",len(grph))

################################################################################
# Used by all CGI scripts when they have finished adding triples to the current RDF graph.
# This just writes a RDF document which can be used as-is by browser,
# or by another scripts which will process this RDF as input, for example when merging RDF data.
def Grph2Rdf(grph):
    DEBUG("Grph2Rdf")

    # TODO: Should we add the OWL-DL or the RDFS ontology ?
    AddOntology(grph)

    lib_util.WrtHeader('text/rdf')

    # Format support can be extended with plugins,
    # but 'xml', 'n3', 'nt', 'trix', 'rdfa' are built in.
    out_dest = lib_util.DfltOutDest()
    # grph.serialize( destination = out_dest, format="xml")
    lib_kbase.triplestore_to_stream_xml(grph,out_dest,'xml')

################################################################################

