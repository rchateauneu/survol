# Encapsulate rdflib features.
# This is just in case another triplestore implementation would be more convenient.

import rdflib
import sys
import re

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

# The returns the set of unique subjects or objects,
# instances and scripts, but no literals.
def enumerate_urls(grph):
	urlsSet = set()

	# Beware that the order might change each time.
	for kSub,kPred,kObj in grph:
		urlsSet.add(kSub)

		if not IsLiteral(kObj):
			urlsSet.add(kObj)
	return urlsSet

# It has to build an intermediary map because we have no simple way to find all edges
# starting from a node. Otherwise, we could use a classical algorithm (Dijkstra ?)
def get_urls_adjacency_list(grph,startInstance,filterPredicates):
	DEBUG("startInstance=%s type=%s",str(startInstance),str(type(startInstance)))
	# Each node maps to the list of the nodes it is directly connected to.
	adjacency_list = dict()

	# This takes an edge and updates the map.
	def InsertEdge(urlStart,urlEnd):
		#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
		# This keeps only Survol instances urls.
		strStart = str(urlStart)
		strEnd = str(urlEnd)
		# TODO: Make this test better.

		#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)

		if (strStart != "http://localhost") and (strEnd != "http://localhost"):
			#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
			assert strStart.find("/localhost") < 0, "start local host"
			assert strEnd.find("/localhost") < 0, "end local host"
			#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
			try:
				#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
				adjacency_list[urlStart].add(urlEnd)
				#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
			except KeyError:
				#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
				adjacency_list[urlStart] = set([urlEnd])
				#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
		#INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)

	DEBUG("len(grph)=%d",len(grph))

	# Connected in both directions.
	for kSub,kPred,kObj in grph:
		# TODO: Like in Grph2Json(), we could filter when kPred = pc.property_script = MakeProp("script")
		# TODO: because this can only be a script.
		if kPred in filterPredicates:
			continue

		if (not IsLiteral(kSub)) and (not IsLiteral(kObj)):

			#if str(kSub).find("entity.py") < 0:
			#	raise Exception("Broken1 %s %s %s"%(kSub,kPred,kObj))
			#if str(kObj).find("entity.py") < 0:
			#	raise Exception("Broken2 %s %s %s"%(kSub,kPred,kObj))

			InsertEdge(kSub,kObj)
			InsertEdge(kObj,kSub)
	#DEBUG("str(adjacency_list)=%s",str(adjacency_list))

	return adjacency_list


# This returns a subset of a triplestore whose object matches a given string.
# TODO: Consider using SparQL.
def triplestore_matching_strings(grph,searchString):
	DEBUG("triplestore_matching_strings: searchString=%s"%searchString)
	# Beware that the order might change each time.
	compiledRgx = re.compile(searchString)
	for kSub,kPred,kObj in grph:
		if IsLiteral(kObj):
			# Conversion to string in case it would be a number.
			strObj = str(kObj.value)
			if compiledRgx.match(strObj):
				#DEBUG("strObj=%s YES"%strObj)
				# yield strObj
				yield (kSub,kPred,kObj)
			#else:
			#	DEBUG("strObj=%s NO"%strObj)

def triplestore_all_strings(grph):
	DEBUG("triplestore_all_strings")
	# Beware that the order might change each time.
	for kSub,kPred,kObj in grph:
		if IsLiteral(kObj):
			# Conversion to string in case it would be a number.
			strObj = str(kObj.value)
			yield (kSub,kPred,kObj)

# This writes a triplestore to a stream which can be a socket or a file.
def triplestore_to_stream_xml(grph,out_dest):
	# With Py2 and StringIO or BytesIO, it raises "TypeError: unicode argument expected, got 'str'"
	# grph.serialize( destination = out_dest, format="xml")
	# There might be a way to serialize directory to the socket.
	strXml = grph.serialize( destination = None, format="xml")
	if sys.version_info >= (3,):
		# Really horrible piece of code, because out_dest might expect a str or a bytes,
		# depending on its type.
		try:
			#out_dest.write(strXml.decode('latin1'))
			# TypeError: string argument expected, got 'bytes'
			out_dest.write(strXml)
		except TypeError as exc:
			DEBUG("triple_store_to_stream_xml. tp=%s exc=%s.",str(type(strXml)),str(exc))
			try:
				# TypeError: a bytes-like object is required, not 'str'
				out_dest.write(strXml.decode('latin1'))
			except TypeError as exc:
				ERROR("triple_store_to_stream_xml. tp=%s exc=%s. Cannot write:%s", str(type(strXml)), str(exc), strXml)
				raise
	else:
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

