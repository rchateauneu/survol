# This allows to easily handle Survol URLs in Jupyter or any other client.
import cgitb
cgitb.enable(format="txt")

import os
import sys
import json
import heapq
import urllib
import traceback

import lib_util
import lib_kbase
import lib_common
import lib_naming
import lib_properties
from lib_properties import pc
import entity_dirmenu_only

################################################################################

try:
    # Python 2
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs

################################################################################

# A SourceBase is a Survol URL or a script which returns a graph of urls
# of CIM objects, linked by properties. This graph can be formatted in XML-RDF,
# in JSON, in SVG, D3 etc...
# This URL or this script has no arguments, or, it comes with a CIM class name
# and the key-value pairs describing an unique CIM object.
class SourceBase (object):
    def __init__(self):
        self.m_current_triplestore = None

    # This returns the merge of the two urls.
    # Easy of two urls. What of one script and one url ?
    # TODO: Modify merge_scripts.py so it can handle urls and scripts.
    #
    def __add__(self, otherSource):
        return SourceMergePlus(self,otherSource)

    def __sub__(self, otherSource):
        return SourceMergeMinus(self,otherSource)

    # So it can be used with rdflib and its Sparql component.
    def content_rdf(self):
        return self.get_content_moded("rdf")

    # This returns a Json object.
    def content_json(self):
        strJson = self.get_content_moded("json")
        url_content = json.loads(strJson)
        return url_content

    # In the general case, it gets the content in RDF format and converts it
    # again to a triplestore. This always works if this is a remote host.
    def get_triplestore(self):
        docXmlRdf = self.get_content_moded("rdf")

        grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
        return TripleStore(grphKBase)

    # This is a hack when mapping Sparql to Survol.
    # This helps avoiding scripts which are very slow and not usable in a loop.
    def is_very_slow(self):
        return False

    # If it does not have the necessary CGI args,
    # then loop on the existing objects of this class.
    # It is always True for merged sources,
    # because they do not have CGI arguments.
    def is_cgi_complete(self):
        return True

################################################################################
# If it has a class, then it has CGI arguments.
class SourceCgi(SourceBase):
    def __init__(self,className = None,**kwargs):
        self.m_className = className
        self.m_kwargs = kwargs
        super(SourceCgi, self).__init__()

    def create_url_query(self, mode=None):
        # suffix = ",".join( [ "%s=%s" % (k,v) for k,v in self.m_kwargs.items() ])
        # v might be an integer, a double, a string.
        suffix = ",".join( [ "%s=%s" % (k,lib_util.urllib_quote(str(v))) for k,v in self.m_kwargs.items() ])
        if self.m_className:
            restQry = self.m_className + "." + suffix
        else:
            restQry = suffix
        quotedRest = restQry

        # TODO: See lib_util.xidCgiDelimiter = "?xid="
        qryArgs = "xid=" + quotedRest
        if mode:
            qryArgs += "&mode=" + mode

        return qryArgs

    def create_url_query_with_question_mark(self,mode=None):
        urlQry = self.create_url_query(mode)
        if urlQry:
            return "?" + urlQry
        else:
            return ""

    # TODO: For the moment, this assumes that all CGI arguments are there.
    def is_cgi_complete(self):
        return True

    def get_script_bag_of_words(self):
        raise Exception("GetScriptBag Not implemented yet")


def load_moded_urls(urlModed):
    DEBUG("load_moded_urls urlModed=%s",urlModed)
    try:
        # Very long timeout to read WBEM ontology.
        response = lib_util.survol_urlopen(urlModed, timeout=120)
    except Exception as exc:
        ERROR("load_moded_urls urlModed=%s. Caught:%s", urlModed, str(exc))
        raise
    data = response.read()
    assert isinstance(data, lib_util.six_binary_type)
    return data


# Server("127.0.0.1:8000").CIM_Process(Handle=1234) and Server("192.168.0.1:8000").CIM_Datafile(Name='/tmp/toto.txt')
#
class SourceRemote (SourceCgi):
    def __init__(self,anUrl,className = None,**kwargsOntology):
        self.m_url = anUrl
        super(SourceRemote, self).__init__(className,**kwargsOntology)

    def __str__(self):
        return "URL=" + self.Url()

    def Url(self):
        return self.m_url + self.create_url_query_with_question_mark()

    def __url_with_mode(self,mode):
        return self.m_url + self.create_url_query_with_question_mark(mode)

    def get_content_moded(self,mode):
        the_url = self.__url_with_mode(mode)
        data = load_moded_urls(the_url)
        assert isinstance(data, lib_util.six_binary_type)
        return data

def create_string_stream():
    from io import BytesIO
    return BytesIO()

class SourceLocal (SourceCgi):
    def __init__(self,aScript,className = None,**kwargsOntology):
        self.m_script = aScript
        super(SourceLocal, self).__init__(className,**kwargsOntology)

    def __str__(self):
        return self.m_script + self.create_url_query_with_question_mark()

    def __get_local_module(self):
        # Sets an environment variable then imports the script and execute it.
        # TODO: "?" or "&"

        urlDirNam = os.path.dirname(self.m_script)

        # The directory of the script is used to build a Python module name.
        moduNam = urlDirNam.replace("/",".")

        urlFilNam = os.path.basename(self.m_script)

        return lib_util.GetScriptModule(moduNam, urlFilNam)


    # This executes the script and return the data in the right format.
    def __execute_script_with_mode(self,mode):
        # Sets an envirorment variable then imports the script and execute it.
        # TODO: "?" or "&"
        modu = self.__get_local_module()

        # SCRIPT_NAME=/survol/print_environment_variables.py
        os.environ["SCRIPT_NAME"] = lib_util.prefixLocalScript + "/" + self.m_script
        # QUERY_STRING=xid=class.k=v
        os.environ["QUERY_STRING"] = self.create_url_query(mode)

        # This technique of replacing the output object is also used by WSGI
        class OutputMachineString:
            def __init__(self):
                self.m_output = create_string_stream()

            # Do not write the header: This just wants the content.
            def HeaderWriter(self,mimeType,extraArgs= None):
                pass

            # The output will be available in a string.
            def OutStream(self):
                return self.m_output

            def GetStringContent(self):
                strResult = self.m_output.getvalue()
                self.m_output.close()
                return strResult

        DEBUG("__execute_script_with_mode before calling module=%s",modu.__name__)
        outmachString = OutputMachineString()
        originalOutMach = lib_util.globalOutMach

        lib_util.SetGlobalOutMach(outmachString)

        # If there is an error, it will not exit but send a nice exception/
        lib_common.ErrorMessageEnable(False)
        try:
            # TODO: If some arguments are missing, it might display an HTML form.
            modu.Main()
        except Exception as ex:
            # https://www.stefaanlippens.net/python-traceback-in-catch/
            ERROR("__execute_script_with_mode with module=%s: Caught:%s",modu.__name__,ex, exc_info=True)
            lib_common.ErrorMessageEnable(True)

            # Restores the original stream.
            lib_util.globalOutMach = originalOutMach
            raise

        lib_common.ErrorMessageEnable(True)

        # Restores the original stream.
        lib_util.globalOutMach = originalOutMach

        strResult = outmachString.GetStringContent()
        return strResult

    # This returns a string.
    # It runs locally: When using only the local node, no web server is needed.
    # TODO: Replace __execute_script_with_mode
    def get_content_moded(self,mode):
        data_content = self.__execute_script_with_mode(mode)
        assert isinstance(data_content, lib_util.six_binary_type)
        return data_content

    # This returns a bag of words which describe what this script does.
    # This is much faster than executing this module. Also, it is probably already
    # imported so the cost is minimal.
    # TODO: Add the classes and predicates returns by this script when executed.
    # TODO: Estimate the cost of calling this script.
    # TODO: Store it in the object.
    def get_script_bag_of_words(self):
        modu = self.__get_local_module()
        if modu.__doc__:
            return set( [ wrd.strip() for wrd in modu.__doc__.split() ])
        else:
            # There is not much information we can return: Just the module name.
            return set(modu.__name__)


    # TODO: At the moment, this serializes an rdflib triplestore into a XML-RDF buffer,
    # TODO: which is parsed again by rdflib into a triplestore,
    # TODO: and then this triplestore is looped on, to extract the instances.
    # TODO: It would be much faster to avoid this useless serialization/deserialization.
    def get_triplestore(self):
        docXmlRdf = self.get_content_moded("rdf")
        if not docXmlRdf:
            return None
        # If the string is empty, it throws "<unknown>:1:0:"
        grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
        return TripleStore(grphKBase)


    @staticmethod
    def get_object_instances_from_script(script_name,class_name = None,**kwargs_ontology):
        my_source = SourceLocal(script_name, class_name, **kwargs_ontology)
        my_triplestore = my_source.get_triplestore()
        list_instances = my_triplestore.GetInstances()
        return list_instances

    def is_very_slow(self):
        modu = self.__get_local_module()
        try:
            return modu.SlowScript
        except AttributeError:
            return False


class SourceMerge (SourceBase):
    def __init__(self,srcA,srcB,operatorTripleStore):
        if not srcA.is_cgi_complete():
            raise Exception("Left-hand-side URL must be complete")
        self.m_srcA = srcA
        self.m_srcB = srcB
        # Plus or minus
        self.m_operatorTripleStore = operatorTripleStore
        super(SourceMerge, self).__init__()

    def get_triplestore(self):
        triplestoreA = self.m_srcA.get_triplestore()
        if self.is_cgi_complete():
            triplestoreB = self.m_srcB.get_triplestore()

            return self.m_operatorTripleStore(triplestoreA,triplestoreB)

        else:
            # TODO: Was it ever used ?
            # The class cannot be None because the url is not complete

            objsList = triplestoreA.enumerate_urls()

            # TODO: Not optimal because it processes not only instances urls but also scripts urls.
            for instanceUrl in objsList:
                ( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
                if entity_label == self.m_srcB.m_class:
                    urlDerived = url_to_instance(instanceUrl)
                    # urlDerived = self.m_srcB.DeriveUrl(instanceUrl)
                    triplestoreB = urlDerived.get_triplestore()
                    triplestoreA = self.m_operatorTripleStore(triplestoreA,triplestoreB)
            return TripleStore(triplestoreA)

    def get_content_moded(self,mode):
        tripstore = self.get_triplestore()
        if mode == "rdf":
            strStrm = create_string_stream()
            tripstore.to_stream_xml(strStrm)
            strResult = strStrm.getvalue()
            strStrm.close()
            assert isinstance(strResult, lib_util.six_binary_type)
            return strResult

        raise Exception("get_content_moded: Cannot yet convert to %s"%mode)

class SourceMergePlus (SourceMerge):
    def __init__(self,srcA,srcB):
        super(SourceMergePlus, self).__init__(srcA,srcB,TripleStore.__add__)

class SourceMergeMinus (SourceMerge):
    def __init__(self,srcA,srcB):
        super(SourceMergeMinus, self).__init__(srcA,srcB,TripleStore.__sub__)

################################################################################

# A bit simpler because it is not needed to explicitely handle the url.
#def CreateSource(script,className = None,urlRoot = None,**kwargsOntology):
#    if urlRoot:
#        return SourceRemote(urlRoot,className,**kwargsOntology)
#    else:
#        return SourceLocal(script,className,**kwargsOntology)
################################################################################

# http://LOCALHOST:80
# http://rchateau-hp:8000
def AgentToHost(agentUrl):
    parsed_url = lib_util.survol_urlparse(agentUrl)
    DEBUG("AgentToHost %s => %s",agentUrl,parsed_url.hostname)
    return parsed_url.hostname

# https://stackoverflow.com/questions/15247075/how-can-i-dynamically-create-derived-classes-from-a-base-class

class BaseCIMClass(object):
    def __init__(self,agentUrl, entity_id, kwargsOntology):
        DEBUG("BaseCIMClass.__init__ agentUrl=%s %s",agentUrl,entity_id)
        self.m_agent_url = agentUrl # If None, this is a local instance.
        self.m_entity_id = entity_id
        # The values are stored in three ways:
        # - In the URL.
        # - As attributes of the class instance.
        # - As a dictionary of key-value pairs as a reference.
        # This is costly but avoids extra conversions.
        self.m_key_value_pairs = kwargsOntology

    # Maybe this object is already in the cache ?
    def __new__(cls, agentUrl, className, **kwargsOntology):

        entity_id = lib_util.KWArgsToEntityId(className, **kwargsOntology)
        if agentUrl:
            hostAgent = AgentToHost(agentUrl)
            instanceKey = hostAgent + "+++" + entity_id
        else:
            instanceKey = "NO_AGENT" + "+++" + entity_id

        # TODO: The key to this class instance must include the host associated to the agent.
        try:
            cacheInstance = cls.m_instances_cache[instanceKey]
            DEBUG("BaseCIMClass.__new__ %s is IN the cache instanceKey=",instanceKey)
            return cacheInstance
        except KeyError:
            DEBUG("BaseCIMClass.__new__ %s is NOT in the cache instanceKey=",instanceKey)
            # newInstance = super(ClassA, cls).__new__(cls, agentUrl, **kwargsOntology)
            #DEBUG("cls=%s kwargs=%s",cls.__name__,str(kwargs))

            newInstance = super(BaseCIMClass, cls).__new__(cls)
            cls.m_instances_cache[instanceKey] = newInstance
            return newInstance


    # TODO: This could be __repr__ also.
    def __str__(self):
        return self.__class__.__name__ + "." + self.m_entity_id

    # This returns the list of Sources (URL or local sources) usable for this entity.
    # This can be a tree ? Or a flat list ?
    # Each source can return a triplestore.
    # This allows the discovery of a machine and its neighbours,
    # discovery with A* algorithm or any exploration heuristic etc....
    def get_scripts(self):
        if self.m_agent_url:
            return self.__get_scripts_remote()
        else:
            return self.__get_scripts_local()

    def __get_scripts_remote(self):
        # We expect a contextual menu in JSON format, not a graph.
        urlScripts = self.m_agent_url + "/survol/entity_dirmenu_only.py" + "?xid=" + self.__class__.__name__ + "." + self.m_entity_id + "&mode=menu"

        # Typical content:
        # {
        #     "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/dir_stat.py?xid=CIM_Directory.Name%3DD%3A": {
        #         "name": "Directory stat information",
        #         "url": "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/dir_stat.py?xid=CIM_Directory.Name%3DD%3A"
        #     },
        #     "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name%3DD%3A": {
        #         "name": "Files in directory",
        #         "url": "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name%3DD%3A"
        #     }
        # }
        dataJsonStr = load_moded_urls(urlScripts)
        dataJson = json.loads(dataJsonStr)

        # The scripts urls are the keys of the Json object.
        listSources = [ script_url_to_source(oneScr) for oneScr in dataJson]
        return listSources

    # This is much faster than using the URL of a local server.
    # Also: Such a server is not necessary.
    def __get_scripts_local(self):
        listScripts = []

        # This function is called for each script which applies to the given entity.
        # It receives a triplet: (subject,property,object) and the depth in the tree.
        # Here, this simply stores the scripts in a list. The depth is not used yet.
        def CallbackGrphAdd( trpl, depthCall ):
            #sys.stdout.write("CallbackGrphAdd:%s %d\n"%(str(trpl),depthCall))
            aSubject,aPredicate,anObject = trpl
            if aPredicate == pc.property_script:
                # Directories of scripts are also labelled with the same predicate
                # although they are literates and not urls.
                if not lib_kbase.IsLiteral(anObject):
                    listScripts.append( anObject )
                    #sys.stdout.write("CallbackGrphAdd: anObject=%s %s\n"%(str(type(anObject)),str(anObject)))

        flagShowAll = False

        # Beware if there are subclasses.
        entity_type = self.__class__.__name__
        entity_host = None # To start with
        rootNode = None # The top-level is script is not necessary.

        #sys.stdout.write("lib_util.gblTopScripts=%s\n"%lib_util.gblTopScripts)

        entity_dirmenu_only.DirToMenu(CallbackGrphAdd,rootNode,entity_type,self.m_entity_id,entity_host,flagShowAll)

        listSources = [ script_url_to_source(oneScr) for oneScr in listScripts]
        return listSources

    # This returns the set of words which describes an instance and allows to compare it to other instances.
    def get_instance_bag_of_words(self):
        # TODO: And the host ?
        bagOfWords = set(self.__class__.__name__)

        # This is the minimal set of words.
        dictIds = lib_util.SplitMoniker( self.m_entity_id )
        for keyId in dictIds:
            bagOfWords.add(keyId)
            valId = dictIds[keyId]
            bagOfWords.add(valId)

        # TODO: Call AddInfo()

        return bagOfWords

    # This returns an iterator.
    # TODO: This will be able to return elements being calculated by sub-processes.
    # TODO: Filter with something similar to SparQL ??
    # Test cases:
    # - Look for a specific string to understand where it comes from,
    #   its path. For example, where does an error message comes from ?
    #   or a malformed string ?
    #   Long-term goal: Actively wait after several processes, files, queues,
    #   looking for the same string, and see it appear from several sources,
    #    in the order it is processed.
    # - Does an object X depends on and object Y: If an executable binary depends
    #   on a configuration file ?
    #
    # Searching for an instance is very similar as long as it has a bag of words.
    #
    def find_string_from_neighbour(self,searchString,maxDepth,filterInstances,filterPredicates):
        # Heuristics and specialization per class.

        # TODO: This is very raw...
        targetBagOfWords = set(searchString)

        # TODO: Ponderation of words ? With < global dictionary of number of occurrences of each word.
        # TODO: Maybe minimal bag of words ?
        def BagOfWordsToEstimatedDistance(wordsBagA, wordsBagB):
            setDifference = wordsBagA.symmetric_difference(wordsBagB)
            setUnion = wordsBagA.union(wordsBagB)
            setDist = len(setDifference)/len(setUnion)
            return setDist

        priorityQueue = []
        visitedInstances = set()

        class AStarEdge:
            def __init__(self, nodeInstance, urlScript, currDist, currDepth, wordsBag):
                self.m_node_instance = nodeInstance
                self.m_url_script = urlScript
                self.m_current_distance = currDist
                self.m_current_depth = currDepth
                self.m_words_bag = wordsBag
                self.m_estimation_to_target = BagOfWordsToEstimatedDistance(wordsBag,targetBagOfWords)

            def __lt__(selfInstance, otherInstance):
                """This is for the heap priority queue when walking on the triplestores graph.

                Each node is associated to a bag of words containing keywords related
                to the instance (AddInfo) and to the script.

                The target also has a bag of words, built the same way.

                We add a node to the priority list of the A* algorithm,
                the distance between its bag of words and the target's is calculated:
                This distance is used to sort the priority queue,
                possibly using Levenshtein distance for similar strings.
                The next explored node is the closest of the target.
                """
                return selfInstance.m_estimation_to_target < otherInstance.m_estimation_to_target

            def __str__(self):
                return str(self.m_url_script) + " (Est=%d, depth=%d)" % (self.m_estimation_to_target,self.m_current_depth)

        if filterInstances and self in filterInstances:
            INFO("Avoiding instance:%s",self)
            return

        # It does this by maintaining a tree of paths originating at the start node and extending
        # those paths one edge at a time until its termination criterion is satisfied.
        # At each iteration of its main loop, A* needs to determine which of its paths to extend.
        # It does so based on the cost of the path and an estimate of the cost required
        # to extend the path all the way to the goal. Specifically, A* selects the path that minimizes
        #  f(n)=g(n)+h(n)
        # where n is the next node on the path, g(n) is the cost of the path from the start node to n,
        # and h(n) is a heuristic function that estimates the cost of the cheapest path from n to the goal.
        def fill_heap_with_instance_scripts(nodeInstance,currDistance, currDepth):
            global heapq
            lstScripts = nodeInstance.get_scripts()
            instanceBagOfWords = nodeInstance.get_instance_bag_of_words()

            #DEBUG("nodeInstance=%s type(nodeInstance)=%s",nodeInstance,str(type(nodeInstance)))
            for oneScript in lstScripts:
                scriptBagOfWords = oneScript.get_script_bag_of_words()
                commonBagOfWords = set.union(instanceBagOfWords, scriptBagOfWords)
                anEdge = AStarEdge(nodeInstance, oneScript, currDistance, currDepth, commonBagOfWords)
                heapq.heappush( priorityQueue, anEdge)


        fill_heap_with_instance_scripts( self, 0, 0 )

        # Search in the instance based on a specific function.
        # If found, add to the list of results.

        while True:
            try:
                bestEdge = heapq.heappop(priorityQueue)
            except IndexError:
                # Empty priority queue.
                break

            visitedInstances.add(bestEdge)

            # The depth is just here for informational purpose.
            currDepth = bestEdge.m_current_depth + 1
            # TODO: For the moment, this is equivalent to the depth,
            # TODO: but it could take into account the number of edges, or, better,
            # TODO: the cost of scripts.
            currDistance = bestEdge.m_current_distance + 1

            INFO("Selecting edge:%s",bestEdge)

            if currDepth <= maxDepth:
                INFO("bestEdge.m_url_script=%s bestEdge.m_node_instance=%s",bestEdge.m_url_script,bestEdge.m_node_instance)
                lib_common.ErrorMessageEnable(False)

                # TODO: Use filterPredicates
                try:
                    tripleStore = bestEdge.m_url_script.get_triplestore()
                except Exception as exc:
                    WARNING("find_string_from_neighbour:%s",str(exc))
                    continue

                if tripleStore is None:
                    continue

                tripleStoreMatch = tripleStore.get_matching_strings_triples(searchString)
                for oneTriple in tripleStoreMatch:
                    yield oneTriple

                try:
                    # TODO: We can refine the calculation of the distance if this returns
                    # TODO: the number of edges up to each connected node. But it does not really
                    # TODO: matter because the true cost is in calculating a script,
                    # TODO: or maybe in the CPU time taken by the script.
                    # TODO: However a very raw evaluation is enough: Its role is to avoid
                    # TODO: searching in depth first, possibly in an endless suite,
                    # TODO: whereas the solution could be quite close.
                    #
                    # TODO: Give a high cost when a node is on a remote machine.
                    lstInstances = tripleStore.get_connected_instances(bestEdge.m_node_instance,filterPredicates)
                except Exception as ex:
                    ERROR("find_string_from_neighbour: %s",ex)
                    raise
                    continue
                lib_common.ErrorMessageEnable(True)
                for oneInstance in lstInstances:
                    if filterInstances and oneInstance in filterInstances:
                        INFO("Avoiding instance:%s",oneInstance)
                        continue

                    if oneInstance in visitedInstances:
                        INFO("Already visited instance:%s",oneInstance)
                        continue

                    #DEBUG("Adding oneInstance=%s currDepth=%d",oneInstance,currDepth)
                    try:
                        # If the node is already seen, and closer as expected.
                        # We might have rejected it before ?
                        if oneInstance.m_current_distance > currDistance:
                            oneInstance.m_current_distance = currDistance
                        if oneInstance.m_current_depth > currDepth:
                            oneInstance.m_current_depth = currDepth
                    except AttributeError:
                        fill_heap_with_instance_scripts( oneInstance, currDistance, currDepth )



def CIMClassFactoryNoCache(className):
    def Derived__init__(self, agentUrl, className, **kwargsOntology):
        """This function will be used as a constructor for the new class."""
        for key, value in kwargsOntology.items():
            setattr(self, key, value)
        entity_id = lib_util.KWArgsToEntityId(className, **kwargsOntology)
        BaseCIMClass.__init__(self,agentUrl, entity_id, kwargsOntology)

    if sys.version_info < (3,0):
        # Python 2 does not want Unicode class name.
        className = className.encode()

    # sys.stderr.write("className: %s/%s\n"%(str(type(className)),className))
    newclass = type(className, (BaseCIMClass,),{"__init__": Derived__init__})
    newclass.m_instances_cache = {}
    return newclass

# Classes are keyed with their name.
# Each class contain a dictionary of its instances, with a key
# mostly made of the URL parameters plus the agent.
# Classes are the same for all agents, therefore the agent is not needed in the key.
cacheCIMClasses = {}

def CreateCIMClass(agentUrl,className,**kwargsOntology):
    global cacheCIMClasses
    entity_id = lib_util.KWArgsToEntityId(className,**kwargsOntology)

    # No need to use the class in the key, because the cache is class-specific.
    DEBUG("CreateCIMClass agentUrl=%s className=%s entity_id=%s",agentUrl,className,entity_id)

    try:
        newCIMClass = cacheCIMClasses[className]
        #DEBUG("Found existing className=%s",className)
    except KeyError:
        # This class is not yet created.
        # TODO: If entity_label contains slashes, submodules must be imported.
        newCIMClass = CIMClassFactoryNoCache(className)

        cacheCIMClasses[className] = newCIMClass

    # Now, it creates a new instance and stores it in the cache of the CIM class.
    newInstance = newCIMClass(agentUrl, className, **kwargsOntology)
    return newInstance

################################################################################

# Example: xid="CIM_Process.Handle=2092"
def entity_id_to_instance(agentUrl, class_name, entity_id):
    xidDict = { sp[0]:sp[2] for sp in [ ss.partition("=") for ss in entity_id.split(",") ] }

    newInstance = CreateCIMClass(agentUrl, class_name, **xidDict)
    return newInstance

# This creates an object from an URI.
# Example input: instanceUrl="http://LOCALHOST:80/LocalExecution/entity.py?xid=CIM_Process.Handle=2092"
def url_to_instance(instanceUrl):
    if instanceUrl.find("entity.py") < 0:
        # So maybe this is not an instance after all.
        return None

    # This parsing that all urls are not scripts but just define an instance
    # and therefore have the form "http://.../entity.py?xid=...",
    agentUrl = instance_url_to_agent_url(instanceUrl)

    ( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
    # Tries to extract the host from the string "Key=Val,Name=xxxxxx,Key=Val"
    # BEWARE: Some arguments should be decoded.
    #DEBUG("GetInstances instanceUrl=%s entity_graphic_class=%s entity_id=%s",instanceUrl,entity_graphic_class,entity_id)

    return entity_id_to_instance(agentUrl, entity_graphic_class, entity_id)


# instanceUrl="http://LOCAL_MODE:80/LocalExecution/entity.py?xid=Win32_Group.Domain=local_mode,Name=Replicator"
# instanceUrl=http://LOCALHOST:80/LocalExecution/entity.py?xid=addr.Id=127.0.0.1:427
# instanceUrl="http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui"
def instance_url_to_agent_url(instanceUrl):
    parse_url = lib_util.survol_urlparse(instanceUrl)
    if parse_url.path.startswith(lib_util.prefixLocalScript):
        agentUrl = None
    else:
        idxSurvol = instanceUrl.find("/survol")
        agentUrl = instanceUrl[:idxSurvol]

    DEBUG("instance_url_to_agent_url instanceUrl=%s agentUrl=%s",instanceUrl,agentUrl)
    return agentUrl

# This wraps rdflib triplestore.
# rdflib objects and subjects can be handled as WMI or WBEM objects.
class TripleStore:
    # In this context, this is a rdflib graph.
    def __init__(self, grphKBase = None):
        self.m_triplestore = grphKBase
        if grphKBase:
            DEBUG("TripleStore.__init__ len(grphKBase)=%d",len(grphKBase))
        else:
            DEBUG("TripleStore.__init__ empty")

    def to_stream_xml(self,strStrm):
        DEBUG("TripleStore.to_stream_xml")
        lib_kbase.triplestore_to_stream_xml(self.m_triplestore,strStrm,'xml')

    # This merges two triplestores. The package rdflib does exactly that,
    # but it is better to isolate from it, just in case another triplestores
    # implementation would be preferable.
    def __add__(self, otherTriple):
        return TripleStore(lib_kbase.triplestore_add(self.m_triplestore,otherTriple.m_triplestore))

    def __sub__(self, otherTriple):
        return TripleStore(lib_kbase.triplestore_sub(self.m_triplestore,otherTriple.m_triplestore))

    def __len__(self):
        return len(self.m_triplestore)

    # This keeps only Survol instances and scripts urls.
    # For example, 'http://localhost:12345/#/vhosts/' is a RabbitMQ HTTP url.
    # TODO: Make this test better.
    def is_survol_url(self,anUrl):
        strUrl = str(anUrl)
        # anUrl=http://LOCALHOST:80/entity.py?xid=python/package.Id%3Drdflib
        # anUrl=http://LOCALHOST:80/LocalExecution/entity.py?xid=python/package.Id=sparqlwrapper
        if strUrl.startswith("http://LOCALHOST:80/"):
            # "http://LOCALHOST:80/LocalExecution"
            # lib_util.prefixLocalScript = "/LocalExecution"
            assert(strUrl.startswith("http://LOCALHOST:80"+lib_util.prefixLocalScript))

        # These local scripts are always from Survol.
        if strUrl.find(lib_util.prefixLocalScript) >= 0:
            return True
        return strUrl.find("/survol") >= 0

    def enumerate_urls(self):
        objsSet = lib_kbase.enumerate_urls(self.m_triplestore)
        for instanceUrl in objsSet:
            if self.is_survol_url(instanceUrl    ):
                yield instanceUrl

    # This creates a CIM object for each unique URL, subject or object found in a triplestore.
    # If needed, the CIM class is created on-the-fly.
    # TODO: Is is really useful to build objects, given that the edges are lost ??
    # TODO: And what about connected objects ? Can a value be an object ?
    def GetInstances(self):
        DEBUG("GetInstances")
        objsSet = self.enumerate_urls()
        lstInstances = []
        for instanceUrl in objsSet:
            if instanceUrl.find("entity.py") < 0:
                continue

            ( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
            # Tries to extract the host from the string "Key=Val,Name=xxxxxx,Key=Val"
            # BEWARE: Some arguments should be decoded.
            #DEBUG("GetInstances instanceUrl=%s entity_graphic_class=%s entity_id=%s",instanceUrl,entity_graphic_class,entity_id)

            xidDict = { sp[0]:sp[2] for sp in [ ss.partition("=") for ss in entity_id.split(",") ] }

            # This parsing that all urls are not scripts but just define an instance
            # and therefore have the form "http://.../entity.py?xid=...",
            agentUrl = instance_url_to_agent_url(instanceUrl)

            newInstance = CreateCIMClass(agentUrl,entity_graphic_class, **xidDict)
            lstInstances.append(newInstance)
        return lstInstances

    # This returns the set of all nodes connected directly or indirectly to the input.
    def get_connected_instances(self,startInstance,filterPredicates):
        setFilterPredicates = {pc.property_script,pc.property_rdf_data_nolist2}
        if filterPredicates:
            setFilterPredicates.update(filterPredicates)

        urls_adjacency_list = lib_kbase.get_urls_adjacency_list(self.m_triplestore,startInstance,setFilterPredicates)

        # Now the adjacency list between scripts must be transformed into an adjacency list between instances only.
        instances_adjacency_list = dict()
        for oneUrl in urls_adjacency_list:
            oneInstance = url_to_instance(oneUrl)
            if oneInstance:
                adj_urls_list = urls_adjacency_list[oneUrl]
                adj_insts = []
                for oneAdjUrl in adj_urls_list:
                    oneAdjInstance = url_to_instance(oneAdjUrl)
                    if oneAdjInstance:
                        adj_insts.append(oneAdjInstance)
                if adj_insts:
                    instances_adjacency_list[oneInstance] = adj_insts

        setConnectedInstances = set()

        # This recursively merges all nodes connected to this one.
        def __merge_connected_instances_to(oneInst):

            if not oneInst in instances_adjacency_list:
                #DEBUG("Already deleted oneInst=%s",oneInst)
                return

            assert oneInst in instances_adjacency_list,"oneInst not there:%s"%oneInst
            instsConnected = instances_adjacency_list[oneInst]

            setConnectedInstances.update(instsConnected)

            del instances_adjacency_list[oneInst]
            for endInst in instsConnected:
                __merge_connected_instances_to(endInst)

        __merge_connected_instances_to(startInstance)

        # All the nodes connected to the input one.
        INFO("startInstance=%s len(setConnectedInstances)=%d",startInstance,len(setConnectedInstances))
        return setConnectedInstances

    def get_matching_strings_triples(self, searchString):
        return lib_kbase.triplestore_matching_strings(self.m_triplestore,searchString)

    def get_all_strings_triples(self):
        for trpSubj,trpPred,trpObj in lib_kbase.triplestore_all_strings(self.m_triplestore):
            yield lib_util.urllib_unquote(trpObj.value )

    # This returns only the objects of a given class and for a given predicate.
    def filter_objects_with_predicate_class(self, associator_key_name, result_class_name):
        WARNING("TripleStore.ObjectFromPredicate associator_key_name=%s, result_class_name=%s",
                associator_key_name, result_class_name)

        dict_objects = {}

        # First pass to filter the objects nodes of a given class labelled with the predicate..
        for source_subject, source_predicate, source_object in self.m_triplestore:
            #WARNING("TripleStore.ObjectFromPredicate s=%s, p=%s, o=%s",
            #        source_subject, source_predicate, source_object)

            # This transforms for example "http://primhillcomputers.com/survol#Domain" into "Domain"
            predicate_name = lib_properties.PropToQName(source_predicate)

            # WARNING("filter_objects_with_predicate_class predicate_name=%s",predicate_name)
            # s=http://LOCALHOST:80/LocalExecution/entity.py?xid=CIM_Process.Handle=2544
            # p=http://primhillcomputers.com/survol#ppid
            # o=http://LOCALHOST:80/LocalExecution/entity.py?xid=CIM_Process.Handle=2092

            if predicate_name == associator_key_name:
                # class_object = source_object
                object_instance = url_to_instance(source_object)
                #if predicate_name.find("ppid") >= 0:
                #    WARNING("filter_objects_with_predicate_class OKOKOKOK s=%s p=%s o=%s", str(source_subject), str(source_predicate), str(source_object))
                #    WARNING("filter_objects_with_predicate_class object_instance=%s", dir(object_instance) )
                #    WARNING("filter_objects_with_predicate_class object_instance.__class__.__name__=%s", object_instance.__class__.__name__)
                if object_instance.__class__.__name__ == result_class_name:
                    dict_objects[source_object] = object_instance

        # Now, it gathers extra properties for the selected objects.
        # This does not fit exactly in the object model,
        # because the extra properties are added in the internal dictonal,
        # but are not members of the object.
        for source_subject, source_predicate, source_object in self.m_triplestore:
            if source_subject in dict_objects:
                predicate_name = lib_properties.PropToQName(source_predicate)
                object_value = str(source_object)
                #WARNING("TripleStore.ObjectFromPredicate predicate_name=%s object_value=%s", predicate_name, object_value)
                dict_objects[source_subject].m_key_value_pairs[predicate_name] = object_value

        for dict_objects, object_instance in dict_objects.items():
            node_path = str(dict_objects)
            #WARNING("TripleStore.ObjectFromPredicate node_path=%s", node_path)
            # The keys of the key-value dictionary must be nodes, not string,
            # for example: rdflib.term.URIRef(u'http://primhillcomputers.com/survol#runs')
            dict_nodes_keys_values = {
                lib_properties.MakeProp(dict_key): dict_value for dict_key, dict_value in object_instance.m_key_value_pairs.items() }
            yield (node_path, dict_nodes_keys_values)

    def copy_to_graph(self, grph):
        """This adds the triples to another triplestore."""
        # TODO: This could be faster.

        # Maybe this is a test mode.
        if not grph:
            WARNING("copy_to_graph Graph is None. Leaving")
            return

        WARNING("copy_to_graph Adding %d triples", len(self.m_triplestore))
        for subject, predicate, object in self.m_triplestore:
            grph.add((subject, predicate, object))


################################################################################

# This receives an URL, parses it and creates a Source object.
# It is able to detect if the URL is local or not.
# Input examples:
# "http://LOCAL_MODE:80/LocalExecution/sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py?xid=Win32_UserAccount.Domain%3Drchateau-hp%2CName%3Drchateau"
# "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/doxygen_dir.py?xid=CIM_Directory.Name%3DD%3A"
def script_url_to_source(callingUrl):

    parse_url = lib_util.survol_urlparse(callingUrl)
    query = parse_url.query

    params = parse_qs(query)

    xidParam = params['xid'][0]
    # sys.stdout.write("script_url_to_source xidParam=%s\n"%xidParam)
    (entity_type,entity_id,entity_host) = lib_util.ParseXid(xidParam)
    # sys.stdout.write("script_url_to_source entity_id=%s\n"%entity_id)
    entity_id_dict = lib_util.SplitMoniker(entity_id)
    # sys.stdout.write("entity_id_dict=%s\n"%str(entity_id_dict))

    # parse_url.path=/LocalExecution/sources_types/Win32_UserAccount/Win32_NetUserGetInfo.py
    # This is a very simple method to differentiate local from remote scripts
    if parse_url.path.startswith(lib_util.prefixLocalScript):
        # This also chops the leading slash.
        pathScript = parse_url.path[len(lib_util.prefixLocalScript)+1:]
        objSource = SourceLocal(pathScript,entity_type,**entity_id_dict)

        # Note: This should be True: parse_url.netloc.startswith("LOCAL_MODE")
    else:
        objSource = SourceRemote(callingUrl,entity_type,**entity_id_dict)

    return objSource

################################################################################

# This models a Survol agent, or the local execution of survol scripts.
class Agent:
    def __init__(self,agent_url = None):
        self.m_agent_url = agent_url

    def __str__(self):
        if self.m_agent_url:
            return "Agent=%s" % self.m_agent_url
        else:
            return "Agent=<NO AGENT>"

    # This allows the creation of CIM instances.
    def __getattr__(self, attribute_name):

        class CallDispatcher(object):
            def __init__(self, caller, agent_url, name):
                #sys.stdout.write("CallDispatcher.__init__ agent=%s name=%s\n"%(str(type(agent_url)),name))
                #sys.stdout.flush()
                self.m_name = name
                self.m_caller = caller
                self.m_agent_url = agent_url

            def __call__(self, *argsCall, **kwargsCall):
                #sys.stdout.write("CallDispatcher.__call__ class=%s url=%s\n"%(self.m_name,str(type(self.m_agent_url))))
                #sys.stdout.flush()
                newInstance = CreateCIMClass(self.m_agent_url, self.m_name, **kwargsCall)
                return newInstance

            def __getattr__(self, attribute_name):
                #sys.stdout.write("CallDispatcher.__getattr__ attr=%s\n"%(str(attribute_name)))
                #sys.stdout.flush()
                return CallDispatcher(self, self.m_agent_url, self.m_name + "/" + attribute_name)

        #sys.stdout.write("Agent.__getattr__ attr=%s\n"%(str(attribute_name)))
        return CallDispatcher(self, self.m_agent_url, attribute_name)

    def exec_http_script(self,aScript):
        if self.m_agent_url:
            anUrl = self.m_agent_url + aScript
            DEBUG("get_internal_data anUrl=%s"%anUrl)
            urlContent = load_moded_urls(anUrl)
            return urlContent
        else:
            raise Exception("exec_http_script: Feature not implemenetd yet")

    def get_internal_data(self):
        # This adds "?xid=" at the end, otherwise it is parsed differently,
        # depending on the path.
        urlContent = self.exec_http_script("/survol/print_internal_data_as_json.py" + lib_util.xidCgiDelimiter)
        return json.loads(urlContent)


################################################################################

# This checks that a full ontology contains a minimal subset of classes and attributes.
# This is for testing purpose only.
def check_ontology_graph(ontology_key, survol_agent = None):
    import rdflib

    url_script = {
            "survol": "ontologies/Survol_RDFS.py",
            "wmi": "ontologies/WMI_RDFS.py",
            "wbem": "ontologies/WBEM_RDFS.py"}[ontology_key]

    if survol_agent:
        # TODO: The url syntax differences between SourceLocal and SourceRemote are not convenient.
        # TODO: Remove this leading "/" slash.
        mySource = SourceRemote(survol_agent + "/survol/" + url_script)
    else:
        mySource = SourceLocal(url_script)
    ontologySurvol = mySource.get_content_moded(None)
    assert isinstance(ontologySurvol, lib_util.six_binary_type)
    INFO("Ontology=", type(ontologySurvol), ontologySurvol[:20])
    ontology_graph = rdflib.Graph()
    ontoTrunc = b"".join(ontologySurvol.split(b"\n"))
    result = ontology_graph.parse(data=ontoTrunc, format="application/rdf+xml")
    INFO("check_ontology_graph Load OK:l=%d"%len(ontology_graph))

    return lib_kbase.CheckMinimalRdsfOntology(ontology_graph)

################################################################################

# TODO: Connect to a Jupyter Python kernel which will execute the Python scripts.
# Jupyter kernel is now a new type of agent, after Survol, WMI, WBEM and local execution in lib_client.
# Find a way to detect a Jupyter Kernel socket address. Or start it on request.

# TODO: Create the merge URL. What about a local script ?
# Or: A merged URL needs an agent anyway.

################################################################################

