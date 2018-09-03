# Encapsulate rdflib features.
# This is just in case another triplestore implementation would be more convenient.

import rdflib
import sys

def IsLiteral(objRdf):
	return isinstance(objRdf, (rdflib.term.Literal))

def IsLink(obj):
	return isinstance( obj , (rdflib.URIRef, rdflib.BNode))

def MakeNodeLiteral(value):
	return rdflib.Literal(value)

# This returns an object which, whose string conversion is identical to the input string.
# Beware that it is sometimes called recursively.
def MakeNodeUrl(url):
	uriRef = rdflib.term.URIRef(url)
	# sys.stderr.write("MakeNodeUrl url=%s uriRef=%s\n"%(url,uriRef))
	return uriRef

def MakeNamespace(primns):
	pc = rdflib.Namespace(primns)
	return pc

def MakeGraph():
	return rdflib.Graph()

# The returns the set of unique subjects or objects.
def enumerate_instances(grph):
	instancesSet = set()
	# Beware that the order might change each time.
	for kSub,kPred,kObj in grph:
		if kSub not in instancesSet:
			instancesSet.add(kSub)

		if not IsLiteral(kObj):
			if kObj not in instancesSet:
				instancesSet.add(kObj)
	return instancesSet


# This writes a triplestore to a stream which can be a socket or a file.
def triplestore_to_stream_xml(grph,out_dest):
	# With Py2 and StringIO or BytesIO, it raises "TypeError: unicode argument expected, got 'str'"
	# grph.serialize( destination = out_dest, format="xml")
	# There might be a way to serialize directory to the socket.
	strXml = grph.serialize( destination = None, format="xml")
	out_dest.write(strXml.decode('latin1'))


# This reasonably assumes that the triplestore library is able to convert from RDF.
# This transforms a serialize XML document into RDF.
# See: https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html
def triplestore_from_rdf_xml(docXmlRdf):
	# This is the inverse operation of: grph.serialize( destination = out_dest, format="xml")
	grph = rdflib.Graph()
	grph.parse(data=docXmlRdf, format="application/rdf+xml")
	return grph

# See https://rdflib.readthedocs.io/en/stable/merging.html for how it uses rdflib.
def triplestore_add(tripleStoreA,tripleStoreB):
	grphResult = tripleStoreA + tripleStoreB
	return grphResult

# See https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html which does qll the work.
def triplestore_sub(tripleStoreA,tripleStoreB):
	grphResult = tripleStoreA - tripleStoreB
	return grphResult

