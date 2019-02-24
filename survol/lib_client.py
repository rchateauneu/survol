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
from lib_properties import pc
import entity_dirmenu_only

################################################################################

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

try:
    # Python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

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
    def GetTriplestore(self):
        docXmlRdf = self.get_content_moded("rdf")

        grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
        return TripleStore(grphKBase)

    # If it does not have the necessary CGI args,
    # then loop on the existing objects of this class.
    # It is always True for merged sources,
    # because they do not have CGI arguments.
    def IsCgiComplete(self):
        #print("SourceCgi.IsCgiComplete")
        return True

################################################################################
# If it has a class, then it has CGI arguments.
class SourceCgi (SourceBase):
    def __init__(self,className = None,**kwargs):
        self.m_className = className
        self.m_kwargs = kwargs
        super(SourceCgi, self).__init__()

    def UrlQuery(self,mode=None):
        suffix = ",".join( [ "%s=%s" % (k,v) for k,v in self.m_kwargs.items() ])
        if self.m_className:
            restQry = self.m_className + "." + suffix
        else:
            restQry = suffix
        quotedRest = lib_util.urllib_quote(restQry)

        # TODO: See lib_util.xidCgiDelimiter = "?xid="
        qryArgs = "xid=" + quotedRest
        if mode:
            qryArgs += "&mode=" + mode

        return qryArgs

    def UrlQueryWithQuestionMark(self,mode=None):
        urlQry = self.UrlQuery(mode)
        if urlQry:
            return "?" + urlQry
        else:
            return ""

    # TODO: For the moment, this assumes that all CGI arguments are there.
    def IsCgiComplete(self):
        #print("SourceCgi.IsCgiComplete")
        return True

    def GetScriptBagOfWords(self):
        raise Exception("GetScriptBag Not implemented yet")


def LoadModedUrl(urlModed):
    DEBUG("LoadModedUrl.get_content_moded urlModed=%s",urlModed)
    try:
        response = urlopen(urlModed,timeout=20)
    except:
        ERROR("LoadModedUrl urlModed=%s",urlModed)
        raise
    data = response.read().decode("utf-8")
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
        return self.m_url + self.UrlQueryWithQuestionMark()

    def __url_with_mode(self,mode):
        return self.m_url + self.UrlQueryWithQuestionMark(mode)

    def get_content_moded(self,mode):
        the_url = self.__url_with_mode(mode)
        data = LoadModedUrl(the_url)
        return data

def CreateStringStream():
    try:
        # Python 3
        from io import StringIO
    except ImportError:
        try:
            from cStringIO import StringIO
        except ImportError:
            from StringIO import StringIO
    return StringIO()
    #from io import BytesIO
    #return BytesIO

class SourceLocal (SourceCgi):
    def __init__(self,aScript,className = None,**kwargsOntology):
        self.m_script = aScript
        super(SourceLocal, self).__init__(className,**kwargsOntology)

    def __str__(self):
        return self.m_script + self.UrlQueryWithQuestionMark()

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
        os.environ["QUERY_STRING"] = self.UrlQuery(mode)

        # This technique of replacing the output object is also used by WSGI
        class OutputMachineString:
            def __init__(self):
                self.m_output = CreateStringStream()
                #sys.stderr.write("OutputMachineString init type=%s\n"%type(self.m_output).__name__)

            # Do not write the header.
            def HeaderWriter(self,mimeType,extraArgs= None):
                #sys.stderr.write("OutputMachineString HeaderWriter:%s\n"%mimeType)
                pass

            # The output will be available in a string.
            def OutStream(self):
                #sys.stderr.write("OutputMachineString OutStream type=%s\n"%type(self.m_output).__name__)
                return self.m_output

            def GetStringContent(self):
                strResult = self.m_output.getvalue()
                self.m_output.close()
                return strResult

        DEBUG("__execute_script_with_mode before calling module=%s",modu.__name__)
        outmachString = OutputMachineString()
        originalOutMach = lib_util.globalOutMach
        lib_util.globalOutMach = outmachString

        # If there is an error, it will not exit but send a nice exception/
        lib_common.ErrorMessageEnable(False)
        try:
            modu.Main()
        except Exception as ex:
            # https://www.stefaanlippens.net/python-traceback-in-catch/
            ERROR("__execute_script_with_mode with module=%s: Caught:%s",modu.__name__,ex, exc_info=True)
            lib_common.ErrorMessageEnable(True)
            raise

        lib_common.ErrorMessageEnable(True)
            #traceback.print_exc()

            # Get traceback as a string and do something with it
            #error = traceback.format_exc()
            #print( error.upper())

            # Log it through logging channel
            #ERROR('Ooops', exc_info=True)

        # Restores the original stream.
        lib_util.globalOutMach = originalOutMach

        strResult = outmachString.GetStringContent()
        # sys.stderr.write("__execute_script_with_mode strResult=%s\n"%strResult[:30])
        return strResult

    # This returns a string.
    # It runs locally: When using only the local node, no web server is needed.
    def get_content_moded(self,mode):
        data_content = self.__execute_script_with_mode(mode)
        return data_content

    # This returns a bag of words which describe what this script does.
    # This is much faster than executing this module. Also, it is probably already
    # imported so the cost is minimal.
    # TODO: Add the classes and predicates returns by this script when executed.
    # TODO: Estimate the cost of calling this script.
    # TODO: Store it in the object.
    def GetScriptBagOfWords(self):
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
    def GetTriplestore(self):
        docXmlRdf = self.get_content_moded("rdf")
        if not docXmlRdf:
            return None
        # If the string is empty, it throws "<unknown>:1:0:"
        grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
        return TripleStore(grphKBase)


class SourceMerge (SourceBase):
    def __init__(self,srcA,srcB,operatorTripleStore):
        if not srcA.IsCgiComplete():
            raise Exception("Left-hand-side URL must be complete")
        self.m_srcA = srcA
        self.m_srcB = srcB
        # Plus or minus
        self.m_operatorTripleStore = operatorTripleStore
        super(SourceMerge, self).__init__()

    def GetTriplestore(self):
        triplestoreA = self.m_srcA.GetTriplestore()
        if self.IsCgiComplete():
            triplestoreB = self.m_srcB.GetTriplestore()

            return self.m_operatorTripleStore(triplestoreA,triplestoreB)

        else:
            # The class cannot be None because the url is not complete

            objsList = triplestoreA.EnumerateUrls()

            # TODO: Not optimal because it processes not only instances urls but also scripts urls.
            for instanceUrl in objsList:
                ( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
                if entity_label == self.m_srcB.m_class:
                    urlDerived = UrlToInstance(instanceUrl)
                    # urlDerived = self.m_srcB.DeriveUrl(instanceUrl)
                    triplestoreB = urlDerived.GetTriplestore()
                    triplestoreA = self.m_operatorTripleStore(triplestoreA,triplestoreB)
            return TripleStore(triplestoreA)

    def get_content_moded(self,mode):
        tripstore = self.GetTriplestore()
        if mode == "rdf":
            strStrm = CreateStringStream()
            tripstore.ToStreamXml(strStrm)
            strResult = strStrm.getvalue()
            strStrm.close()
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
    parsed_url = urlparse(agentUrl)
    DEBUG("AgentToHost %s => %s",agentUrl,parsed_url.hostname)
    return parsed_url.hostname

# https://stackoverflow.com/questions/15247075/how-can-i-dynamically-create-derived-classes-from-a-base-class

class BaseCIMClass(object):
    def __init__(self,agentUrl, entity_id):
        DEBUG("BaseCIMClass.__init__ agentUrl=%s %s",agentUrl,entity_id)
        self.m_agentUrl = agentUrl # If None, this is a local instance.
        self.m_entity_id = entity_id


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
            cacheInstance = cls.m_instancesCache[instanceKey]
            DEBUG("BaseCIMClass.__new__ %s is IN the cache instanceKey=",instanceKey)
            return cacheInstance
        except KeyError:
            DEBUG("BaseCIMClass.__new__ %s is NOT in the cache instanceKey=",instanceKey)
            # newInstance = super(ClassA, cls).__new__(cls, agentUrl, **kwargsOntology)
            #DEBUG("cls=%s kwargs=%s",cls.__name__,str(kwargs))
            if sys.version_info >= (3,):
                newInstance = super(BaseCIMClass, cls).__new__(cls)
            else:
                # TODO: Consider reusing eneity_id.
                newInstance = super(BaseCIMClass, cls).__new__(cls,  agentUrl, className, **kwargsOntology)

            cls.m_instancesCache[instanceKey] = newInstance
            return newInstance


    # TODO: This could be __repr__ also.
    def __str__(self):
        return self.__class__.__name__ + "." + self.m_entity_id

    # This returns the list of Sources (URL or local sources) usable for this entity.
    # This can be a tree ? Or a flat list ?
    # Each source can return a triplestore.
    # This allows the discovery of a machine and its neighbours,
    # discovery with A* algorithm or any exploration heuristic etc....
    def GetScripts(self):
        if self.m_agentUrl:
            return self.GetScriptsRemote()
        else:
            return self.GetScriptsLocal()

    def GetScriptsRemote(self):
        # We expect a contextual menu in JSON format, not a graph.
        urlScripts = self.m_agentUrl + "/survol/entity_dirmenu_only.py" + "?xid=" + self.__class__.__name__ + "." + self.m_entity_id + "&mode=menu"
        #DEBUG("GetScriptsRemote self.m_agentUrl=%s urlScripts=%s",self.m_agentUrl,urlScripts)

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
        dataJsonStr = LoadModedUrl(urlScripts)
        dataJson = json.loads(dataJsonStr)

        # The scripts urls are the keys of the Json object.
        listSources = [ ScriptUrlToSource(oneScr) for oneScr in dataJson]
        return listSources

    # This is much faster than using the URL of a local server.
    # Also: Such a server is not necessary.
    def GetScriptsLocal(self):
        #sys.stdout.write("GetScriptsLocal: class=%s entity_id=%s\n"%(self.__class__.__name__,self.m_entity_id))

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

        listSources = [ ScriptUrlToSource(oneScr) for oneScr in listScripts]
        return listSources

    # This returns the set of words which describes an instance and allows to compare it to other instances.
    def GetInstanceBagOfWords(self):
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
    def FindStringFromNeighbour(self,searchString,maxDepth,filterInstances,filterPredicates):
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
        def FillHeapWithInstanceScripts(nodeInstance,currDistance, currDepth):
            global heapq
            lstScripts = nodeInstance.GetScripts()
            instanceBagOfWords = nodeInstance.GetInstanceBagOfWords()

            #DEBUG("nodeInstance=%s type(nodeInstance)=%s",nodeInstance,str(type(nodeInstance)))
            for oneScript in lstScripts:
                scriptBagOfWords = oneScript.GetScriptBagOfWords()
                commonBagOfWords = set.union(instanceBagOfWords, scriptBagOfWords)
                anEdge = AStarEdge(nodeInstance, oneScript, currDistance, currDepth, commonBagOfWords)
                heapq.heappush( priorityQueue, anEdge)


        FillHeapWithInstanceScripts( self, 0, 0 )

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
                    tripleStore = bestEdge.m_url_script.GetTriplestore()
                except Exception as exc:
                    WARNING("FindStringFromNeighbour:%s",str(exc))
                    continue

                if tripleStore is None:
                    continue

                tripleStoreMatch = tripleStore.GetMatchingStringsTriples(searchString)
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
                    lstInstances = tripleStore.GetConnectedInstances(bestEdge.m_node_instance,filterPredicates)
                except Exception as ex:
                    ERROR("FindStringFromNeighbour: %s",ex)
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
                        FillHeapWithInstanceScripts( oneInstance, currDistance, currDepth )



def CIMClassFactoryNoCache(className):
    def Derived__init__(self, agentUrl, className, **kwargsOntology):
        """This function will be used as a constructor for the new class."""
        for key, value in kwargsOntology.items():
            setattr(self, key, value)
        entity_id = lib_util.KWArgsToEntityId(className,**kwargsOntology)
        BaseCIMClass.__init__(self,agentUrl, entity_id)

    if sys.version_info < (3,0):
        # Python 2 does not want Unicode class name.
        className = className.encode()

    # sys.stderr.write("className: %s/%s\n"%(str(type(className)),className))
    newclass = type(className, (BaseCIMClass,),{"__init__": Derived__init__})
    newclass.m_instancesCache = {}
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
def UrlToInstance(instanceUrl):
    if instanceUrl.find("entity.py") < 0:
        # So maybe this is not an instance after all.
        return None

    ( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
    # Tries to extract the host from the string "Key=Val,Name=xxxxxx,Key=Val"
    # BEWARE: Some arguments should be decoded.
    #DEBUG("GetInstances instanceUrl=%s entity_graphic_class=%s entity_id=%s",instanceUrl,entity_graphic_class,entity_id)

    xidDict = { sp[0]:sp[2] for sp in [ ss.partition("=") for ss in entity_id.split(",") ] }

    # This parsing that all urls are not scripts but just define an instance
    # and therefore have the form "http://.../entity.py?xid=...",
    agentUrl = InstanceUrlToAgentUrl(instanceUrl)

    newInstance = CreateCIMClass(agentUrl,entity_graphic_class, **xidDict)
    return newInstance


# instanceUrl="http://LOCAL_MODE:80/NotRunningAsCgi/entity.py?xid=Win32_Group.Domain=local_mode,Name=Replicator"
# instanceUrl=http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=addr.Id=127.0.0.1:427
# instanceUrl="http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui"
def InstanceUrlToAgentUrl(instanceUrl):
    parse_url = urlparse(instanceUrl)
    if parse_url.path.startswith(lib_util.prefixLocalScript):
        agentUrl = None
    else:
        idxSurvol = instanceUrl.find("/survol")
        agentUrl = instanceUrl[:idxSurvol]

    DEBUG("InstanceUrlToAgentUrl instanceUrl=%s agentUrl=%s",instanceUrl,agentUrl)
    return agentUrl

# This wraps rdflib triplestore.
# rdflib objects and subjects can be handled as WMI or WBEM objects.
class TripleStore:
    # In this context, this is most likely a rdflib object.
    def __init__(self,grphKBase = None):
        self.m_triplestore = grphKBase
        if grphKBase:
            DEBUG("TripleStore.__init__ len(grphKBase)=%d",len(grphKBase))
        else:
            DEBUG("TripleStore.__init__ empty")

    # Debugging purpose.
    def DisplayTripleStore(self):
        DEBUG("TripleStore.DisplayTripleStore")
        for a,b,c in self.m_triplestore:
            print("   ",a,b,c)

    def ToStreamXml(self,strStrm):
        DEBUG("TripleStore.ToStreamXml")
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
    def IsSurvolUrl(self,anUrl):
        strUrl = str(anUrl)
        # anUrl=http://LOCALHOST:80/entity.py?xid=python/package.Id%3Drdflib
        # anUrl=http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=python/package.Id=sparqlwrapper
        if strUrl.startswith("http://LOCALHOST:80/"):
            # "http://LOCALHOST:80/NotRunningAsCgi"
            # lib_util.prefixLocalScript = "/NotRunningAsCgi"
            assert(strUrl.startswith("http://LOCALHOST:80"+lib_util.prefixLocalScript))

        # These local scripts are always from Survol.
        if strUrl.find(lib_util.prefixLocalScript) >= 0:
            return True
        return strUrl.find("/survol") >= 0

    def EnumerateUrls(self):
        objsSet = lib_kbase.enumerate_urls(self.m_triplestore)
        for instanceUrl in objsSet:
            if self.IsSurvolUrl(instanceUrl    ):
                yield instanceUrl

    # This creates a CIM object for each unique URL, subject or object found in a triplestore.
    # If needed, the CIM class is created on-the-fly.
    def GetInstances(self):
        DEBUG("GetInstances")
        objsSet = self.EnumerateUrls()
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
            agentUrl = InstanceUrlToAgentUrl(instanceUrl)

            newInstance = CreateCIMClass(agentUrl,entity_graphic_class, **xidDict)
            lstInstances.append(newInstance)
        return lstInstances

    # This returns the set of all nodes connected directly or indirectly to the input.
    def GetConnectedInstances(self,startInstance,filterPredicates):
        setFilterPredicates = {pc.property_script,pc.property_rdf_data_nolist2}
        if filterPredicates:
            setFilterPredicates.update(filterPredicates)

        urls_adjacency_list = lib_kbase.get_urls_adjacency_list(self.m_triplestore,startInstance,setFilterPredicates)


        # Now the adjacency list between scripts must be transformed into an adjacency list between instances only.
        instances_adjacency_list = dict()
        for oneUrl in urls_adjacency_list:
            oneInstance = UrlToInstance(oneUrl)
            if oneInstance:
                adj_urls_list = urls_adjacency_list[oneUrl]
                adj_insts = []
                for oneAdjUrl in adj_urls_list:
                    oneAdjInstance = UrlToInstance(oneAdjUrl)
                    if oneAdjInstance:
                        adj_insts.append(oneAdjInstance)
                if adj_insts:
                    instances_adjacency_list[oneInstance] = adj_insts

        setConnectedInstances = set()

        # This recursively merges all nodes connected to this one.
        def MergeConnectedInstancesTo(oneInst):

            if not oneInst in instances_adjacency_list:
                #DEBUG("Already deleted oneInst=%s",oneInst)
                return

            assert oneInst in instances_adjacency_list,"oneInst not there:%s"%oneInst
            instsConnected = instances_adjacency_list[oneInst]

            setConnectedInstances.update(instsConnected)

            del instances_adjacency_list[oneInst]
            for endInst in instsConnected:
                MergeConnectedInstancesTo(endInst)

        MergeConnectedInstancesTo(startInstance)

        # All the nodes connected to the input one.
        INFO("startInstance=%s len(setConnectedInstances)=%d",startInstance,len(setConnectedInstances))
        return setConnectedInstances

    def GetMatchingStringsTriples(self,searchString):
        return lib_kbase.triplestore_matching_strings(self.m_triplestore,searchString)

    def GetAllStringsTriples(self):
        return lib_kbase.triplestore_all_strings(self.m_triplestore)

################################################################################

# This receives an URL, parses it and creates a Source object.
# It is able to detect if the URL is local or not.
# Input examples:
# "http://LOCAL_MODE:80/NotRunningAsCgi/sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py?xid=Win32_UserAccount.Domain%3Drchateau-hp%2CName%3Drchateau"
# "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/doxygen_dir.py?xid=CIM_Directory.Name%3DD%3A"
def ScriptUrlToSource(callingUrl):

    parse_url = urlparse(callingUrl)
    query = parse_url.query

    params = parse_qs(query)

    xidParam = params['xid'][0]
    # sys.stdout.write("ScriptUrlToSource xidParam=%s\n"%xidParam)
    (entity_type,entity_id,entity_host) = lib_util.ParseXid( xidParam )
    # sys.stdout.write("ScriptUrlToSource entity_id=%s\n"%entity_id)
    entity_id_dict = lib_util.SplitMoniker(entity_id)
    # sys.stdout.write("entity_id_dict=%s\n"%str(entity_id_dict))

    # parse_url.path=/NotRunningAsCgi/sources_types/Win32_UserAccount/Win32_NetUserGetInfo.py
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

    def ExecHttpScript(self,aScript):
        if self.m_agent_url:
            anUrl = self.m_agent_url + aScript
            DEBUG("GetInternalData anUrl=%s"%anUrl)
            urlContent = LoadModedUrl(anUrl)
            return urlContent
        else:
            tralala

    def GetInternalData(self):
        urlContent = self.ExecHttpScript("/survol/print_internal_data_as_json.py")
        return json.loads(urlContent)

################################################################################
def SetDebugMode():
    lib_util.SetLoggingConfig(True)

################################################################################

# TODO: Connect to a Jupyter Python kernel which will execute the Python scripts.
# Jupyter kernel is now a new type of agent, after Survol, WMI, WBEM and local execution in lib_client.
# Find a way to detect a Jupyter Kernel socket address. Or start it on request.

# TODO: Create the merge URL. What about a local script ?
# Or: A merged URL needs an agent anyway.


################################################################################

"""
Recherche en parallele:
=======================
Si le script a une fonction Daemon(), alors on lance un sous-process qui va l'appeler
et rester constamment en attente des resultats.
Il n y a pas de multiprocessing.heapq mais uniquement multiprocessing.queue
Le sous-process qui lance le script ajoute les resultats dans la queue des resultats,
un par un, et quand ce sera un script, on l'insere dans la heapq des scripts
mais doit la locker: multiprocessing.Lock.
Si pas de fonction Daemon(), ou bien si script remote,alors on appelle juste le script.
On pourrait lancer un sous-process si HTTP permettait de recevoir des infos via la socket,
sans fin.

OU ALORS:
La gestion des scripts d evenements est transparente: On relance simplement les scripts
si leur nom contient "auto", et le bidule est capable de stocker les triples
crees par une sous-process: A chaque appel, on va lire le contenu de la queue.
Bien sur, si local, ce serait plus rapide d eviter l encodage/decoage en lisant directement
la queue ou meme en lancant "Daemon" qui ecrirait directement ses triples dans notre queue.
"Premature omptimisation etc..."
"""
