# This allows to easily handle Survol URLs in Jupyter or any other client.
import cgitb
cgitb.enable(format="txt")

import os
import six
import sys
import json
import heapq
import rdflib
import logging

import lib_util
import lib_kbase
import lib_common
import lib_naming
import lib_properties
from lib_properties import pc
import entity_dirmenu_only

################################################################################


class SourceBase (object):
    """
    A SourceBase is a Survol URL or a script which returns a graph of urls
    of CIM objects, linked by properties. This graph can be formatted in XML-RDF,
    in JSON, in SVG, D3 etc...
    This URL or this script has no arguments, or, it comes with a CIM class name
    and the key-value pairs describing an unique CIM object.
    """
    def __init__(self):
        self.m_current_triplestore = None

    def __add__(self, other_source):
        """This returns the merge of the two urls.
        Easy of two urls. What of one script and one url ?"""
        #
        # TODO: Modify merge_scripts.py so it can handle urls and scripts.
        return SourceMergePlus(self, other_source)

    def __sub__(self, other_source):
        return SourceMergeMinus(self, other_source)

    def content_rdf(self):
        """So it can be used with rdflib and its Sparql component."""
        return self.get_content_moded("rdf")

    def content_json(self):
        """This returns a Json object."""
        str_json = self.get_content_moded("json")
        url_content = json.loads(str_json)
        return url_content

    def get_triplestore(self):
        """In the general case, it gets the content in RDF format and converts it
        again to a triplestore. This always works if this is a remote host."""
        doc_xml_rdf = self.get_content_moded("rdf")

        grph_k_base = lib_kbase.triplestore_from_rdf_xml(doc_xml_rdf)
        return TripleStore(grph_k_base)

    def is_very_slow(self):
        """This is a hack when mapping Sparql to Survol.
        This helps avoiding scripts which are very slow and not usable in a loop."""
        return False

    def is_cgi_complete(self):
        """If it does not have the necessary CGI args, then loop on the existing objects of this class.
        It is always True for merged sources, because they do not have CGI arguments."""
        return True


class SourceCgi(SourceBase):
    """If it has a class, then it has CGI arguments."""
    def __init__(self, class_name=None, **kwargs):
        self.m_className = class_name
        self.m_kwargs = kwargs
        super(SourceCgi, self).__init__()

    def create_url_query(self, mode=None):
        # v might be an integer, a double, a string.
        suffix = ",".join(["%s=%s" % (k, lib_util.urllib_quote(str(v))) for k,v in self.m_kwargs.items()])
        if self.m_className:
            rest_qry = self.m_className + "." + suffix
        else:
            rest_qry = suffix
        quoted_rest = rest_qry

        # TODO: See lib_util.xidCgiDelimiter = "?xid="
        qry_args = "xid=" + quoted_rest
        if mode:
            qry_args += "&mode=" + mode

        return qry_args

    def create_url_query_with_question_mark(self, mode=None):
        url_qry = self.create_url_query(mode)
        if url_qry:
            return "?" + url_qry
        else:
            return ""

    # TODO: For the moment, this assumes that all CGI arguments are there.
    def is_cgi_complete(self):
        return True

    def get_script_bag_of_words(self):
        raise Exception("GetScriptBag Not implemented yet")


def _load_moded_urls(url_moded):
    logging.debug("_load_moded_urls urlModed=%s", url_moded)
    try:
        # Very long timeout to read WBEM ontology.
        response = lib_util.survol_urlopen(url_moded, timeout=120)
    except Exception as exc:
        ERROR("_load_moded_urls urlModed=%s. Caught:%s", url_moded, str(exc))
        raise
    data = response.read()
    assert isinstance(data, six.binary_type)
    return data


# Server("127.0.0.1:8000").CIM_Process(Handle=1234) and Server("192.168.0.1:8000").CIM_Datafile(Name='/tmp/toto.txt')
#
class SourceRemote (SourceCgi):
    def __init__(self, an_url, class_name=None, **kwargs_ontology):
        self.m_url = an_url
        super(SourceRemote, self).__init__(class_name, **kwargs_ontology)

    def __str__(self):
        return "URL=" + self.Url()

    def Url(self):
        return self.m_url + self.create_url_query_with_question_mark()

    def __url_with_mode(self, mode):
        return self.m_url + self.create_url_query_with_question_mark(mode)

    def get_content_moded(self, mode):
        the_url = self.__url_with_mode(mode)
        data = _load_moded_urls(the_url)
        assert isinstance(data, six.binary_type)
        return data


def create_string_stream():
    from io import BytesIO
    return BytesIO()


class SourceLocal (SourceCgi):
    def __init__(self, a_script, class_name=None, **kwargs_ontology):
        self.m_script = a_script
        super(SourceLocal, self).__init__(class_name, **kwargs_ontology)

    def __str__(self):
        return self.m_script + self.create_url_query_with_question_mark()

    def __get_local_module(self):
        """Sets an environment variable then imports the script and execute it."""

        url_dir_nam = os.path.dirname(self.m_script)

        # The directory of the script is used to build a Python module name.
        modu_nam = url_dir_nam.replace("/", ".")

        url_fil_nam = os.path.basename(self.m_script)

        return lib_util.GetScriptModule(modu_nam, url_fil_nam)

    def __execute_script_with_mode(self, mode):
        """This executes the script and return the data in the right format."""

        # Sets an environment variable then imports the script and execute it.
        modu = self.__get_local_module()

        # SCRIPT_NAME=/survol/print_environment_variables.py
        os.environ["SCRIPT_NAME"] = lib_util.prefixLocalExecution + "/" + self.m_script
        # QUERY_STRING=xid=class.k=v
        os.environ["QUERY_STRING"] = self.create_url_query(mode)

        # This technique of replacing the output object is also used by WSGI
        class OutputMachineString:
            def __init__(self):
                self.m_output = create_string_stream()

            # Do not write the header: This just wants the content.
            def HeaderWriter(self, mime_type, extra_args= None):
                pass

            # The output will be available in a string.
            def OutStream(self):
                return self.m_output

            def GetStringContent(self):
                str_result = self.m_output.getvalue()
                self.m_output.close()
                return str_result

        logging.debug("__execute_script_with_mode before calling module=%s",modu.__name__)
        outmach_string = OutputMachineString()
        original_out_mach = lib_util.globalOutMach

        lib_util.SetGlobalOutMach(outmach_string)

        # If there is an error, it will not exit but send a nice exception/
        lib_common.enable_error_message(False)
        try:
            # TODO: If some arguments are missing, it might display an HTML form.
            modu.Main()
        except Exception as ex:
            # https://www.stefaanlippens.net/python-traceback-in-catch/
            ERROR("__execute_script_with_mode with module=%s: Caught:%s", modu.__name__, ex, exc_info=True)
            lib_common.enable_error_message(True)

            # Restores the original stream.
            lib_util.globalOutMach = original_out_mach
            raise

        lib_common.enable_error_message(True)

        # Restores the original stream.
        lib_util.globalOutMach = original_out_mach

        str_result = outmach_string.GetStringContent()
        return str_result

    def get_content_moded(self, mode):
        """This returns a string. It runs locally: When using only the local node, no web server is needed."""

        # TODO: Replace __execute_script_with_mode
        data_content = self.__execute_script_with_mode(mode)
        assert isinstance(data_content, six.binary_type)
        return data_content

    def get_script_bag_of_words(self):
        """This returns a bag of words which describe what this script does.
        This is faster than executing this module. Also, it is probably already imported so the cost is minimal."""

        # TODO: Add the classes and predicates returns by this script when executed.
        # TODO: Estimate the cost of calling this script.
        # TODO: Store it in the object.
        modu = self.__get_local_module()
        if modu.__doc__:
            return set([wrd.strip() for wrd in modu.__doc__.split()])
        else:
            # There is not much information we can return: Just the module name.
            return set(modu.__name__)

    # TODO: At the moment, this serializes an rdflib triplestore into a XML-RDF buffer,
    # TODO: which is parsed again by rdflib into a triplestore,
    # TODO: and then this triplestore is looped on, to extract the instances.
    # TODO: It would be much faster to avoid this useless serialization/deserialization.
    def get_triplestore(self):
        doc_xml_rdf = self.get_content_moded("rdf")
        if not doc_xml_rdf:
            return None
        # If the string is empty, it throws "<unknown>:1:0:"
        grph_kbase = lib_kbase.triplestore_from_rdf_xml(doc_xml_rdf)
        return TripleStore(grph_kbase)

    @staticmethod
    def get_object_instances_from_script(script_name, class_name=None, **kwargs_ontology):
        my_source = SourceLocal(script_name, class_name, **kwargs_ontology)
        my_triplestore = my_source.get_triplestore()
        list_instances = my_triplestore.get_instances()
        return list_instances

    def is_very_slow(self):
        modu = self.__get_local_module()
        try:
            return modu.SlowScript
        except AttributeError:
            return False


class SourceMerge (SourceBase):
    def __init__(self, src_a, src_b, operator_triple_store):
        if not src_a.is_cgi_complete():
            raise Exception("Left-hand-side URL must be complete")
        self.m_srcA = src_a
        self.m_srcB = src_b
        # Plus or minus
        self.m_operatorTripleStore = operator_triple_store
        super(SourceMerge, self).__init__()

    def get_triplestore(self):
        triplestore_a = self.m_srcA.get_triplestore()
        if self.is_cgi_complete():
            triplestore_b = self.m_srcB.get_triplestore()

            return self.m_operatorTripleStore(triplestore_a, triplestore_b)

        else:
            # TODO: Was it ever used ?
            # The class cannot be None because the url is not complete

            objs_list = triplestore_a.enumerate_urls()

            # TODO: Not optimal because it processes not only instances urls but also scripts urls.
            for instance_url in objs_list:
                entity_label, entity_graphic_class, entity_id = lib_naming.ParseEntityUri(instance_url)
                if entity_label == self.m_srcB.m_class:
                    url_derived = url_to_instance(instance_url)
                    triplestore_b = url_derived.get_triplestore()
                    triplestore_a = self.m_operatorTripleStore(triplestore_a,triplestore_b)
            return TripleStore(triplestore_a)

    def get_content_moded(self, mode):
        tripstore = self.get_triplestore()
        if mode == "rdf":
            str_strm = create_string_stream()
            tripstore.to_stream_xml(str_strm)
            str_result = str_strm.getvalue()
            str_strm.close()
            assert isinstance(str_result, six.binary_type)
            return str_result

        raise Exception("get_content_moded: Cannot yet convert to %s" % mode)


class SourceMergePlus (SourceMerge):
    def __init__(self, src_a, src_b):
        super(SourceMergePlus, self).__init__(src_a, src_b, TripleStore.__add__)


class SourceMergeMinus (SourceMerge):
    def __init__(self, src_a, src_b):
        super(SourceMergeMinus, self).__init__(src_a, src_b, TripleStore.__sub__)


# http://LOCALHOST:80
# http://rchateau-hp:8000
def agent_to_host(agent_url):
    parsed_url = lib_util.survol_urlparse(agent_url)
    logging.debug("agent_to_host %s => %s", agent_url, parsed_url.hostname)
    return parsed_url.hostname

# https://stackoverflow.com/questions/15247075/how-can-i-dynamically-create-derived-classes-from-a-base-class


class BaseCIMClass(object):
    def __init__(self, agent_url, entity_id, kwargs_ontology):
        self.m_agent_url = agent_url # If None, this is a local instance.
        self.m_entity_id = entity_id
        # The values are stored in three ways:
        # - In the URL.
        # - As attributes of the class instance.
        # - As a dictionary of key-value pairs as a reference.
        # This is costly but avoids extra conversions.
        self.m_key_value_pairs = kwargs_ontology

    # Maybe this object is already in the cache ?
    def __new__(cls, agent_url, class_name, **kwargs_ontology):

        entity_id = lib_util.KWArgsToEntityId(class_name, **kwargs_ontology)
        if agent_url:
            host_agent = agent_to_host(agent_url)
            instance_key = host_agent + "+++" + entity_id
        else:
            instance_key = "NO_AGENT" + "+++" + entity_id

        # TODO: The key to this class instance must include the host associated to the agent.
        try:
            cache_instance = cls.m_instances_cache[instance_key]
            return cache_instance
        except KeyError:

            new_instance = super(BaseCIMClass, cls).__new__(cls)
            cls.m_instances_cache[instance_key] = new_instance
            return new_instance

    # TODO: This could be __repr__ also.
    def __str__(self):
        return self.__class__.__name__ + "." + self.m_entity_id

    def get_scripts(self):
        """This returns the list of Sources (URL or local sources) usable for this entity.
        Each source can return a triplestore.
        This allows the discovery of a machine and its neighbours,
        discovery with A* algorithm or any exploration heuristic etc...."""
        if self.m_agent_url:
            return self.__get_scripts_remote()
        else:
            return self.__get_scripts_local()

    def __get_scripts_remote(self):
        # We expect a contextual menu in JSON format, not a graph.
        url_scripts = self.m_agent_url + "/survol/entity_dirmenu_only.py" \
                    + "?xid=" + self.__class__.__name__ \
                    + "." + self.m_entity_id + "&mode=menu"

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
        data_json_str = _load_moded_urls(url_scripts)
        data_json = json.loads(data_json_str)

        # The scripts urls are the keys of the Json object.
        list_sources = [script_url_to_source(one_scr) for one_scr in data_json]
        return list_sources

    def __get_scripts_local(self):
        """This is much faster than using the URL of a local server. Also: Such a server is not necessary."""
        list_scripts = []

        # This function is called for each script which applies to the given entity.
        # It receives a triplet: (subject,property,object) and the depth in the tree.
        # Here, this simply stores the scripts in a list. The depth is not used yet.
        def callback_grph_add(trpl, depth_call):
            a_subject, a_predicate, an_object = trpl
            if a_predicate == pc.property_script:
                # Directories of scripts are also labelled with the same predicate
                # although they are literates and not urls.
                if not lib_kbase.IsLiteral(an_object):
                    list_scripts.append(an_object)

        flag_show_all = False

        # Beware if there are subclasses.
        entity_type = self.__class__.__name__
        entity_host = None # To start with
        root_node = None # The top-level is script is not necessary.

        entity_dirmenu_only.DirToMenu(
            callback_grph_add,
            root_node,
            entity_type,
            self.m_entity_id,
            entity_host,
            flag_show_all)

        list_sources = [script_url_to_source(one_scr) for one_scr in list_scripts]
        return list_sources

    def get_instance_bag_of_words(self):
        """This returns the set of words which describes an instance and allows to compare it to other instances."""
        # TODO: And the host ?
        bag_of_words = set(self.__class__.__name__)

        # This is the minimal set of words.
        dict_ids = self.m_key_value_pairs
        for key_id in dict_ids:
            bag_of_words.add(key_id)
            val_id = dict_ids[key_id]
            bag_of_words.add(val_id)

        # TODO: Call AddInfo()

        return bag_of_words

    def find_string_from_neighbour(self, search_string, max_depth, filter_instances, filter_predicates):
        """
        This returns an iterator.
        Test cases:
        - Look for a specific string to understand where it comes from,
          its path. For example, where does an error message comes from ?
          or a malformed string ?
          Long-term goal: Actively wait after several processes, files, queues,
          looking for the same string, and see it appear from several sources,
           in the order it is processed.
        - Does an object X depends on and object Y: If an executable binary depends
          on a configuration file ?
        Searching for an instance is very similar as long as it has a bag of words.
        """

        # Heuristics and specialization per class.

        # TODO: This will be able to return elements being calculated by sub-processes.
        # TODO: Filter with something similar to SparQL ??

        # TODO: This is very raw...
        target_bag_of_words = set(search_string)

        # TODO: Ponderation of words ? With < global dictionary of number of occurrences of each word.
        # TODO: Maybe minimal bag of words ?
        def bag_of_words_to_estimated_distance(words_bag_a, words_bag_b):
            set_difference = words_bag_a.symmetric_difference(words_bag_b)
            set_union = words_bag_a.union(words_bag_b)
            set_dist = len(set_difference) / len(set_union)
            return set_dist

        priority_queue = []
        visited_instances = set()

        class AStarEdge:
            def __init__(self, node_instance, url_script, curr_dist, curr_depth, words_bag):
                self.m_node_instance = node_instance
                self.m_url_script = url_script
                self.m_current_distance = curr_dist
                self.m_current_depth = curr_depth
                self.m_words_bag = words_bag
                self.m_estimation_to_target = bag_of_words_to_estimated_distance(words_bag, target_bag_of_words)

            def __lt__(self, other_instance):
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
                return self.m_estimation_to_target < other_instance.m_estimation_to_target

            def __str__(self):
                return "%s (Est=%d, depth=%d)" % (
                    str(self.m_url_script), self.m_estimation_to_target, self.m_current_depth)

        if filter_instances and self in filter_instances:
            INFO("Avoiding instance:%s", self)
            return

        # It does this by maintaining a tree of paths originating at the start node and extending
        # those paths one edge at a time until its termination criterion is satisfied.
        # At each iteration of its main loop, A* needs to determine which of its paths to extend.
        # It does so based on the cost of the path and an estimate of the cost required
        # to extend the path all the way to the goal. Specifically, A* selects the path that minimizes
        #  f(n)=g(n)+h(n)
        # where n is the next node on the path, g(n) is the cost of the path from the start node to n,
        # and h(n) is a heuristic function that estimates the cost of the cheapest path from n to the goal.
        def fill_heap_with_instance_scripts(node_instance, curr_distance, curr_depth):
            lst_scripts = node_instance.get_scripts()
            instance_bag_of_words = node_instance.get_instance_bag_of_words()

            #logging.debug("nodeInstance=%s type(nodeInstance)=%s",nodeInstance,str(type(nodeInstance)))
            for one_script in lst_scripts:
                script_bag_of_words = one_script.get_script_bag_of_words()
                common_bag_of_words = set.union(instance_bag_of_words, script_bag_of_words)
                an_edge = AStarEdge(node_instance, one_script, curr_distance, curr_depth, common_bag_of_words)
                heapq.heappush(priority_queue, an_edge)

        fill_heap_with_instance_scripts(self, 0, 0)

        # Search in the instance based on a specific function.
        # If found, add to the list of results.

        while True:
            try:
                best_edge = heapq.heappop(priority_queue)
            except IndexError:
                # Empty priority queue.
                break

            visited_instances.add(best_edge)

            # The depth is just here for informational purpose.
            curr_depth = best_edge.m_current_depth + 1
            # TODO: For the moment, this is equivalent to the depth,
            # TODO: but it could take into account the number of edges, or, better,
            # TODO: the cost of scripts.
            curr_distance = best_edge.m_current_distance + 1

            INFO("Selecting edge:%s", best_edge)

            if curr_depth <= max_depth:
                lib_common.enable_error_message(False)

                # TODO: Use filter_predicates
                try:
                    triple_store = best_edge.m_url_script.get_triplestore()
                except Exception as exc:
                    logging.warning("find_string_from_neighbour:%s", str(exc))
                    continue

                if triple_store is None:
                    continue

                triple_store_match = triple_store.get_matching_strings_triples(search_string)
                for one_triple in triple_store_match:
                    yield one_triple

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
                    lst_instances = triple_store.get_connected_instances(best_edge.m_node_instance, filter_predicates)
                except Exception as ex:
                    ERROR("find_string_from_neighbour: %s", ex)
                    raise

                lib_common.enable_error_message(True)
                for one_instance in lst_instances:
                    if filter_instances and one_instance in filter_instances:
                        INFO("Avoiding instance:%s",one_instance)
                        continue

                    if one_instance in visited_instances:
                        INFO("Already visited instance:%s", one_instance)
                        continue

                    #logging.debug("Adding one_instance=%s curr_depth=%d",one_instance,curr_depth)
                    try:
                        # If the node is already seen, and closer as expected.
                        # We might have rejected it before ?
                        if one_instance.m_current_distance > curr_distance:
                            one_instance.m_current_distance = curr_distance
                        if one_instance.m_current_depth > curr_depth:
                            one_instance.m_current_depth = curr_depth
                    except AttributeError:
                        fill_heap_with_instance_scripts(one_instance, curr_distance, curr_depth)


def CIM_class_factory_no_cache(class_name):
    def Derived__init__(self, agent_url, class_name, **kwargs_ontology):
        """This function will be used as a constructor for the new class."""
        for key, value in kwargs_ontology.items():
            setattr(self, key, value)
        entity_id = lib_util.KWArgsToEntityId(class_name, **kwargs_ontology)
        BaseCIMClass.__init__(self, agent_url, entity_id, kwargs_ontology)

    if not lib_util.is_py3:
        # Python 2 does not want Unicode class name.
        class_name = class_name.encode()

    # sys.stderr.write("className: %s/%s\n"%(str(type(className)),className))
    newclass = type(class_name, (BaseCIMClass,), {"__init__": Derived__init__})
    newclass.m_instances_cache = {}
    return newclass


# Classes are keyed with their name.
# Each class contain a dictionary of its instances, with a key
# mostly made of the URL parameters plus the agent.
# Classes are the same for all agents, therefore the agent is not needed in the key.
_cache_cim_classes = {}


def create_CIM_class(agent_url, class_name, **kwargs_ontology):
    global _cache_cim_classes
    entity_id = lib_util.KWArgsToEntityId(class_name, **kwargs_ontology)

    # No need to use the class in the key, because the cache is class-specific.
    logging.debug("create_CIM_class agentUrl=%s className=%s entity_id=%s", agent_url, class_name, entity_id)

    try:
        new_cim_class = _cache_cim_classes[class_name]
        #logging.debug("Found existing className=%s",className)
    except KeyError:
        # This class is not yet created.
        # TODO: If entity_label contains slashes, submodules must be imported.
        new_cim_class = CIM_class_factory_no_cache(class_name)

        _cache_cim_classes[class_name] = new_cim_class

    # Now, it creates a new instance and stores it in the cache of the CIM class.
    new_instance = new_cim_class(agent_url, class_name, **kwargs_ontology)
    return new_instance

################################################################################


def entity_id_to_instance(agent_url, class_name, entity_id):
    """This receives the URL of an object, its class and the moniker.
    It splits the moniker in key-value pairs.
    These are used to create a CIM object with key-value pairs transformed in attributes.
    Example: xid="CIM_Process.Handle=2092"
    BEWARE: Some arguments should be decoded from Base64."""

    xid_dict = lib_util.SplitMoniker(entity_id)

    new_instance = create_CIM_class(agent_url, class_name, **xid_dict)
    return new_instance


def url_to_instance(instance_url):
    """
    This creates an object from an URI.
    Input example: instanceUrl="http://LOCALHOST:80/LocalExecution/entity.py?xid=CIM_Process.Handle=2092"
    """
    if instance_url.find("entity.py") < 0:
        # So maybe this is not an instance after all.
        return None

    # This parsing that all urls are not scripts but just define an instance
    # and therefore have the form "http://.../entity.py?xid=...",
    agent_url = instance_url_to_agent_url(instance_url)

    entity_label, entity_graphic_class, entity_id = lib_naming.ParseEntityUri(instance_url)
    # This extracts the host from the string "Key=Val,Name=xxxxxx,Key=Val"
    # TODO: Some arguments should be decoded from base64.

    new_instance = entity_id_to_instance(agent_url, entity_graphic_class, entity_id)
    return new_instance


# instanceUrl="http://LOCAL_MODE:80/LocalExecution/entity.py?xid=Win32_Group.Domain=local_mode,Name=Replicator"
# instanceUrl=http://LOCALHOST:80/LocalExecution/entity.py?xid=addr.Id=127.0.0.1:427
# instanceUrl="http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui"
def instance_url_to_agent_url(instance_url):
    parse_url = lib_util.survol_urlparse(instance_url)
    if parse_url.path.startswith(lib_util.prefixLocalExecution):
        agent_url = None
    else:
        idx_survol = instance_url.find("/survol")
        agent_url = instance_url[:idx_survol]

    logging.debug("instance_url_to_agent_url instanceUrl=%s agent_url=%s", instance_url, agent_url)
    return agent_url


class TripleStore:
    """This wraps rdflib triplestore.
    rdflib objects and subjects can be handled as WMI or WBEM objects."""

    # In this context, this is a rdflib graph.
    def __init__(self, grph_k_base=None):
        self.m_triplestore = grph_k_base

    def to_stream_xml(self, str_stream):
        lib_kbase.triplestore_to_stream_xml(self.m_triplestore, str_stream, 'xml')

    def __add__(self, other_triple):
        """This merges two triplestores. The package rdflib does exactly that,
        but it is better to isolate from it, just in case another triplestores implementation would be preferable. """
        return TripleStore(self.m_triplestore + other_triple.m_triplestore)

    def __sub__(self, other_triple):
        """This removes our triples which also belong to another set."""
        return TripleStore(self.m_triplestore - other_triple.m_triplestore)

    def __len__(self):
        return len(self.m_triplestore)

    def _is_survol_url(self, an_url):
        """This keeps only Survol instances and scripts urls.
        For example, 'http://localhost:12345/#/vhosts/' is a RabbitMQ HTTP url."""

        # TODO: Make this test better.
        str_url = str(an_url)
        # anUrl=http://LOCALHOST:80/entity.py?xid=python/package.Id%3Drdflib
        # anUrl=http://LOCALHOST:80/LocalExecution/entity.py?xid=python/package.Id=sparqlwrapper
        if str_url.startswith("http://LOCALHOST:80/"):
            # "http://LOCALHOST:80/LocalExecution"
            # lib_util.prefixLocalScript = "/LocalExecution"
            assert(str_url.startswith("http://LOCALHOST:80" + lib_util.prefixLocalExecution))

        # These local scripts are always from Survol.
        if str_url.find(lib_util.prefixLocalExecution) >= 0:
            return True
        return str_url.find("/survol") >= 0

    def enumerate_urls(self):
        urls_dict = lib_kbase.unique_urls_dict(self.m_triplestore)
        for instance_url, key_value_list in urls_dict.items():
            if self._is_survol_url(instance_url):
                yield instance_url

    def get_instances(self):
        """This creates a CIM object for each unique URL, subject or object found in a triplestore.
        If needed, the CIM class is created on-the-fly."""

        # TODO: Is is really useful to build objects, given that the edges are lost ??
        # TODO: And what about connected objects ? Can a value be an object ?
        urls_dict = lib_kbase.unique_urls_dict(self.m_triplestore)

        instances_list = []
        for instance_url, urls_key_value_dict in urls_dict.items():
            if self._is_survol_url(instance_url):
                new_instance = url_to_instance(instance_url)
                if new_instance:
                    new_instance.graph_attributes = urls_key_value_dict
                    instances_list.append(new_instance)
        return instances_list

    def get_connected_instances(self, start_instance, filter_predicates):
        """This returns the set of all nodes connected directly or indirectly to the input."""
        set_filter_predicates = {pc.property_script, pc.property_rdf_data_nolist2}
        if filter_predicates:
            set_filter_predicates.update(filter_predicates)

        urls_adjacency_list = lib_kbase.get_urls_adjacency_list(self.m_triplestore, start_instance, set_filter_predicates)

        # Now the adjacency list between scripts must be transformed into an adjacency list between instances only.
        instances_adjacency_list = dict()
        for one_url in urls_adjacency_list:
            one_instance = url_to_instance(one_url)
            if one_instance:
                adj_urls_list = urls_adjacency_list[one_url]
                adj_insts = []
                for one_adj_url in adj_urls_list:
                    one_adj_instance = url_to_instance(one_adj_url)
                    if one_adj_instance:
                        adj_insts.append(one_adj_instance)
                if adj_insts:
                    instances_adjacency_list[one_instance] = adj_insts

        set_connected_instances = set()

        def __merge_connected_instances_to(one_instance):
            """This recursively merges all nodes connected to this one."""

            if not one_instance in instances_adjacency_list:
                return

            assert one_instance in instances_adjacency_list, "oneInst not there:%s" % one_instance
            insts_connected = instances_adjacency_list[one_instance]

            set_connected_instances.update(insts_connected)

            del instances_adjacency_list[one_instance]
            for end_inst in insts_connected:
                __merge_connected_instances_to(end_inst)

        __merge_connected_instances_to(start_instance)

        # All the nodes connected to the input one.
        INFO("startInstance=%s len(set_connected_instances)=%d", start_instance, len(set_connected_instances))
        return set_connected_instances

    def get_matching_strings_triples(self, search_string):
        return lib_kbase.triplestore_matching_strings(self.m_triplestore, search_string)

    def get_all_strings_triples(self):
        for trp_subj, trp_pred, trp_obj in lib_kbase.triplestore_all_strings(self.m_triplestore):
            yield lib_util.urllib_unquote(trp_obj.value)

    def filter_objects_with_predicate_class(self, associator_key_name, result_class_name):
        """This returns only the objects of a given class and for a given predicate."""
        logging.warning("TripleStore.ObjectFromPredicate associator_key_name=%s, result_class_name=%s",
                associator_key_name, result_class_name)

        dict_objects = {}

        # First pass to filter the objects nodes of a given class labelled with the predicate..
        for source_subject, source_predicate, source_object in self.m_triplestore:
            #logging.warning("TripleStore.ObjectFromPredicate s=%s, p=%s, o=%s",
            #        source_subject, source_predicate, source_object)

            # This transforms for example "http://primhillcomputers.com/survol#Domain" into "Domain"
            predicate_name = lib_properties.PropToQName(source_predicate)

            # logging.warning("filter_objects_with_predicate_class predicate_name=%s",predicate_name)
            # s=http://LOCALHOST:80/LocalExecution/entity.py?xid=CIM_Process.Handle=2544
            # p=http://primhillcomputers.com/survol#ppid
            # o=http://LOCALHOST:80/LocalExecution/entity.py?xid=CIM_Process.Handle=2092

            if predicate_name == associator_key_name:
                # class_object = source_object
                object_instance = url_to_instance(source_object)
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
                dict_objects[source_subject].m_key_value_pairs[predicate_name] = object_value

        for dict_objects, object_instance in dict_objects.items():
            node_path = str(dict_objects)
            # The keys of the key-value dictionary must be nodes, not string,
            # for example: rdflib.term.URIRef(u'http://primhillcomputers.com/survol#runs')
            dict_nodes_keys_values = {
                lib_properties.MakeProp(dict_key): dict_value
                for dict_key, dict_value in object_instance.m_key_value_pairs.items()}
            yield (node_path, dict_nodes_keys_values)

    def copy_to_graph(self, grph):
        """This adds the triples to another triplestore."""

        # Maybe this is a test mode.
        if not grph:
            logging.warning("copy_to_graph Graph is None. Leaving")
            return

        for the_triple in self.m_triplestore:
            grph.add(the_triple)


################################################################################


def script_url_to_source(calling_url):
    """This receives an URL, parses it and creates a Source object.
    It is able to detect if the URL is local or not.
    Input examples:
    "http://LOCAL_MODE:80/LocalExecution/sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py?xid=Win32_UserAccount.Domain%3Dthe_machine%2CName%3Drchateau"
    "http://the_machine:8000/survol/sources_types/CIM_Directory/doxygen_dir.py?xid=CIM_Directory.Name%3DD%3A"
    """
    url_path, entity_type, entity_id_dict = lib_util.split_url_to_entity(calling_url)

    # parse_url.path=/LocalExecution/sources_types/Win32_UserAccount/Win32_NetUserGetInfo.py
    # This is a very simple method to differentiate local from remote scripts
    if url_path.startswith(lib_util.prefixLocalExecution):
        # This also chops the leading slash.
        path_script = url_path[len(lib_util.prefixLocalExecution) + 1:]
        obj_source = SourceLocal(path_script, entity_type, **entity_id_dict)

        # Note: This should be True: parse_url.netloc.startswith("LOCAL_MODE")
    else:
        obj_source = SourceRemote(calling_url, entity_type, **entity_id_dict)

    return obj_source

################################################################################

class Agent:
    """This models a Survol agent, or the local execution of survol scripts."""
    def __init__(self, agent_url=None):
        self.m_agent_url = agent_url

    def __str__(self):
        if self.m_agent_url:
            return "Agent=%s" % self.m_agent_url
        else:
            return "Agent=<NO AGENT>"

    def __getattr__(self, attribute_name):
        """This allows the creation of CIM instances."""

        class CallDispatcher(object):
            def __init__(self, caller, agent_url, name):
                self.m_name = name
                self.m_caller = caller
                self.m_agent_url = agent_url

            def __call__(self, *argsCall, **kwargsCall):
                new_instance = create_CIM_class(self.m_agent_url, self.m_name, **kwargsCall)
                return new_instance

            def __getattr__(self, attribute_name):
                return CallDispatcher(self, self.m_agent_url, self.m_name + "/" + attribute_name)

        #sys.stdout.write("Agent.__getattr__ attr=%s\n"%(str(attribute_name)))
        return CallDispatcher(self, self.m_agent_url, attribute_name)

    def exec_http_script(self, a_script):
        if self.m_agent_url:
            an_url = self.m_agent_url + a_script
            logging.debug("get_internal_data an_url=%s" % an_url)
            url_content = _load_moded_urls(an_url)
            return url_content
        else:
            raise Exception("exec_http_script: Feature not implemented yet")

    def get_internal_data(self):
        """This adds "?xid=" at the end, otherwise it is parsed differently, depending on the path."""
        url_content = self.exec_http_script("/survol/print_internal_data_as_json.py" + lib_util.xidCgiDelimiter)
        return json.loads(url_content)


################################################################################

def check_ontology_graph(ontology_key, survol_agent=None):
    """This checks that a full ontology contains a minimal subset of classes and attributes.
    This is for testing purpose only."""

    url_script = {
            "survol": "ontologies/Survol_RDFS.py",
            "wmi": "ontologies/WMI_RDFS.py",
            "wbem": "ontologies/WBEM_RDFS.py"}[ontology_key]

    if survol_agent:
        # TODO: The url syntax differences between SourceLocal and SourceRemote are not convenient.
        # TODO: Remove this leading "/" slash.
        my_source = SourceRemote(survol_agent + "/survol/" + url_script)
    else:
        my_source = SourceLocal(url_script)
    ontology_survol = my_source.get_content_moded(None)
    assert isinstance(ontology_survol, six.binary_type)
    ontology_graph = rdflib.Graph()
    result = ontology_graph.parse(data=ontology_survol, format="application/rdf+xml")

    return lib_kbase.CheckMinimalRdsfOntology(ontology_graph)

################################################################################

# TODO: Connect to a Jupyter Python kernel which will execute the Python scripts.
# Jupyter kernel is now a new type of agent, after Survol, WMI, WBEM and local execution in lib_client.
# Find a way to detect a Jupyter Kernel socket address. Or start it on request.

# TODO: Create the merge URL. What about a local script ?
# Or: A merged URL needs an agent anyway.

################################################################################

