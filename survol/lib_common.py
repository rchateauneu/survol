"""Common code for Survol agent"""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__     = "GPL"

import socket
import urllib
import subprocess

try:
    import simplejson as json
except ImportError:
    import json

import signal
import sys
import cgi
import os
import re
import time
import rdflib

import lib_kbase
import lib_credentials
import lib_util
import lib_naming
import lib_properties
from lib_properties import MakeProp
import lib_exports
import lib_export_ontology
import lib_export_dot
import lib_export_html
import lib_export_json
import lib_daemon
import lib_command_line

from lib_util import NodeUrl
from lib_util import TimeStamp

# Functions for creating uris are imported in the global namespace.
from lib_uris import *
import lib_uris

################################################################################

nodeMachine = gUriGen.HostnameUri( lib_util.currentHostname )

################################################################################


def is_useless_process(proc):
    # Could be reused if we want to focus on some processes only.
    # proc in [ 'bash', 'gvim', 'konsole' ]
    # FIXME: THIS IS DEPRECATED.
    return False


################################################################################
    
## Also, the Apache 2.2 docs have a slightly different location for the registry key:
## HKEY_CLASSES_ROOT\.cgi\Shell\ExecCGI\Command\(Default) => C:\Perl\bin\perl.exe -wT

################################################################################


# The result can be sent to the Web browser in several formats.
# TODO: The nodes should be displayed always in the same order.
# THIS IS NOT THE CASE IN HTML AND SVG !!
def OutCgiMode(theCgi, top_url, mode, error_msg=None, is_sub_server=False):
    theCgi._bind_identical_nodes()

    grph = theCgi.m_graph
    page_title = theCgi.m_page_title
    parameters = theCgi.m_parameters
    parameterized_links = theCgi.m_parameterized_links

    collapsed_properties, commutative_properties = lib_properties.extract_properties_metadata(grph)
    collapsed_properties.extend(theCgi.m_collapsed_properties)

    if mode == "html":
        # Used rarely and performance not very important. This returns a HTML page.
        lib_export_html.Grph2Html(theCgi, top_url, error_msg, is_sub_server, globalCgiEnvList)
    elif mode == "json":
        lib_export_json.Grph2Json(page_title, error_msg, is_sub_server, parameters, grph)
    elif mode == "menu":
        lib_export_json.Grph2Menu(page_title, error_msg, is_sub_server, parameters, grph)
    elif mode == "rdf":
        lib_export_ontology.Grph2Rdf(grph)
    elif mode == "daemon":
        # This is the end of a loop, or events transaction, in the script which does not run in CGI context,
        # but in a separate daemon process. This stores the results to the persistent graph database for events.
        try:
            triples_count = lib_kbase.write_graph_to_events(theCgi.m_url_without_mode, theCgi.m_graph)
        except Exception as exc:
            ERROR("OutCgiMode Exception exc=%s", exc)
            raise
    elif mode in ["svg", ""]:
        # Default mode, because graphviz did not like several CGI arguments in a SVG document (Bug ?),
        # probably because of the ampersand which must be escaped, or had to be in old versions.

        # This test holds because for the moment, all collapsed properties are known in advance.
        # This will be more flexible.
        sys.stderr.write("collapsed_properties=%s\n" % str(collapsed_properties))
        sys.stderr.write("commutative_properties=%s\n" % str(commutative_properties))

        lib_export_dot.GraphToSvg(page_title, error_msg, is_sub_server, parameters, grph, parameterized_links, top_url,
                      theCgi.m_layout_style, collapsed_properties, commutative_properties)
    else:
        ERROR("OutCgiMode invalid mode=%s", mode)
        ErrorMessageHtml("OutCgiMode invalid mode=%s" % mode)

    # TODO: Add a special mode where the triplestore grph is simply returned, without serialization.
    # TODO: This is much faster when in the client library because no marshalling is needed.
    # TODO: Implementation: Store grph in a global variable. This can work with one client only.
    # TODO: Maybe a thread-specific variable.
    # TODO: The caller must destroy the grph triplestore after using it.

    # TODO: Other modes stored in a configuration file:
    # These mode define a reporting mechanism to send the triplestore
    # to an external repository:
    # - Graph database such as Neo4J
    # - Log file.
    # The client, when reporting, must make a specific call to this script.
    # An acknowledgment and status HTML message is sent back to the caller.


################################################################################


def _get_calling_module_doc():
    """
        Works if called from Apache, cgiserver.py or wsgiserver.py
        This is a global and can be fetched differently, if needed.
        It returns the whole content.
    """

    #sys.stderr.write("_get_calling_module_doc Main module:%s\n"% str(sys.modules['__main__']))


    # If it uses an unique CGI script.
    if globalMergeMode or lib_util.is_wsgi_server():
        try:
            # This is a bit of a hack.
            import inspect
            frame=inspect.currentframe()
            frame=frame.f_back.f_back
            code=frame.f_code
            filnam_caller = code.co_filename
            filnam_caller = filnam_caller.replace("\\", ".").replace("/", ".")
            filnam_caller = filnam_caller[:-3] # Strings ".py" at the end.
            module_prefix = "survol."
            htbin_idx = filnam_caller.find(module_prefix)
            filnam_caller = filnam_caller[htbin_idx + len(module_prefix):]

            try:
                # Another try if "survol." is duplicated, possibly for Win10 and Py3.8:
                if filnam_caller.startswith(module_prefix):
                    filnam_caller = filnam_caller[len(module_prefix):]
                module_caller = sys.modules[filnam_caller]
            except:
                return filnam_caller + ":No doc"

            the_doc = module_caller.__doc__
            if the_doc:
                the_doc = the_doc.strip()
            else:
                the_doc = ""
            #sys.stderr.write("_get_calling_module_doc  module_caller.__doc__=%s\n" % the_doc)
            return the_doc
        except:
            exc = sys.exc_info()[1]
            WARNING("_get_calling_module_doc Caught when getting doc:%s",str(exc))
            return "Caught when getting doc:"+str(exc)
    else:
        try:
            # This does not work when in WSGI mode, nor when merging.
            main_modu = sys.modules['__main__']
            #sys.stderr.write("_get_calling_module_doc Main module:%s\n"% main_modu.__name__ )
            page_title = main_modu.__doc__
            if page_title:
                page_title = page_title.strip()
                return page_title
            else:
                return "No __main__ doc"
        except Exception as exc:
            return "_get_calling_module_doc (Caught %s)" % str(exc)


################################################################################

globalMergeMode = False
globalCgiEnvList = []
globalGraph = None


def _global_create_graph():
    """This creates a RDF triplestore. """
    return rdflib.Graph()


def CgiEnvMergeMode():
    """There is only one cgiEnv and "cgiEnv.OutCgiRdf()" does not generate anything.
    It is related to WSGI in the extent that global variables should not harm things.
    """
    global globalMergeMode
    global globalCgiEnvList
    global globalGraph

    globalMergeMode = True
    globalCgiEnvList = []
    globalGraph = _global_create_graph()


def MergeOutCgiRdf(the_mode, cumulated_error):
    """OutCgiRdf has been called by each script without writing anything,
    but the specific parameters per script are stored inside."""
    global globalMergeMode
    global globalCgiEnvList
    global globalGraph

    page_title = "Merge of %d scripts:\n" % len(globalCgiEnvList)
    delim_title = ""

    # This is equivalent to: make_dot_layout( "", [] )
    layout_style = ""
    collapsed_properties = []
    cgi_params = {}
    cgi_param_links = {}
    for theCgiEnv in globalCgiEnvList:
        # theCgiEnv.m_page_title contains just the first line.
        (page_title_first, page_title_rest) = (theCgiEnv.m_page_title, theCgiEnv.m_page_subtitle)
        page_title += delim_title + page_title_first
        if page_title_rest:
            page_title += " (" + page_title_rest + ")"
        delim_title = ", "

        # TODO: The values will be overriden. Which one to keep ?
        if layout_style == "":
            layout_style = theCgiEnv.m_layout_style
        collapsed_properties.extend(theCgiEnv.m_collapsed_properties)

        # The dictionaries of parameters and corresponding links are merged.
        try:
            cgi_params.update(theCgiEnv.m_parameters)
            cgi_param_links.update(theCgiEnv.m_parameterized_links)
        except ValueError as error_msg:
            WARNING("Error:%s Parameters:%s", error_msg, str(theCgiEnv.m_parameters))

    # Eliminate duplicates in the list of collapsed properties.
    my_set = set(collapsed_properties)
    collapsed_properties = list(my_set)

    top_url = lib_util.TopUrl("", "")

    pseudo_cgi = CgiEnv()
    pseudo_cgi.m_graph = globalGraph
    pseudo_cgi.m_page_title = page_title
    pseudo_cgi.m_page_subtitle = ""
    pseudo_cgi.m_layout_style = layout_style
    pseudo_cgi.m_collapsed_properties = collapsed_properties
    # Not sure this is the best value, but this is usually done.
    # TODO: We should have a plain map for all m_arguments occurences.
    pseudo_cgi.m_arguments = cgi.FieldStorage()
    pseudo_cgi.m_parameters = cgi_params
    pseudo_cgi.m_parameterized_links = cgi_param_links
    pseudo_cgi.m_entity_type = ""
    pseudo_cgi.m_entity_id = ""
    pseudo_cgi.m_entity_id_dict = {}
    pseudo_cgi.m_entity_host = ""

    # A single rendering of all RDF nodes and links merged from several scripts.
    OutCgiMode(pseudo_cgi, top_url, the_mode, error_msg=cumulated_error)

    return

################################################################################


class CgiEnv():
    """
        This class parses the CGI environment variables which define an entity.
    """
    def __init__(self,
                 parameters=None,
                 can_process_remote=False,
                 layout_style="",
                 collapsed_properties=None):
        # It is possible to run these scripts as CGI scripts, so this transforms
        # command line arguments into CGI arguments. This is very helpful for debugging.
        # TODO: At the moment, the mode cannot be changed.
        lib_command_line.command_line_to_cgi_args()
        assert "QUERY_STRING" in os.environ

        # Some limitations of cgiserver.py and Python2:
        # TODO: When running from cgiserver.py, and if QUERY_STRING is finished by a dot ".", this dot
        # TODO: is removed. Workaround: Any CGI variable added after.
        # TODO: Also: Several slashes "/" are merged into one.
        # TODO: Example: "xid=http://192.168.1.83:5988/." becomes "xid=http:/192.168.1.83:5988/"
        # TODO: ... or "xx.py?xid=smbshr.Id=////WDMyCloudMirror///rchateau" become "xx.py?xid=smbshr.Id=/WDMyCloudMirror/rchateau"
        # TODO: Replace by "xid=http:%2F%2F192.168.1.83:5988/."
        # Maybe a bad collapsing of URL ?

        mode = lib_util.GuessDisplayMode()

        # Contains the optional arguments of the script, entered as CGI arguments..
        self.m_parameters = parameters if parameters else {}

        self.m_parameterized_links = dict()

        self.m_layout_style = layout_style
        self.m_collapsed_properties = collapsed_properties if collapsed_properties else []

        # When in merge mode, the display parameters must be stored in a place accessible by the graph.

        doc_modu_all = _get_calling_module_doc()

        # Take only the first non-empty line. See lib_util.FromModuleToDoc()
        self.m_page_title, self.m_page_subtitle = lib_util.SplitTextTitleRest(doc_modu_all)

        # Title page contains __doc__ plus object label.

        # Example: REQUEST_URI=/Survol/survol/print_environment_variables.py
        # This does NOT contain the host and the port, which implies a confusion if severl Survol agents
        # use the same database. It makes sense, because the result should not depend in the agent.
        self.m_calling_url = lib_util.RequestUri()
        self.m_url_without_mode = lib_util.url_mode_replace(self.m_calling_url, "")

        full_title, entity_class, entity_id, entity_host = lib_naming.ParseEntityUriWithHost(
            self.m_calling_url,
            long_display=False,
            force_entity_ip_addr=None)
        # Here, the commas separating the CGI arguments are intact, but the commas in the arguments are encoded.
        entity_id_dict = lib_util.SplitMoniker(entity_id)

        self._concatenate_entity_documentation(full_title, entity_class, entity_id)

        # Global CanProcessRemote has precedence over parameter can_process_remote
        # which should probably be deprecated, although they do not have exactly the same role:
        # * Global CanProcessRemote is used by entity.py to display scripts which have this capability.
        # * Parameter can_process_remote is used to inform, at execution time, of this capability.
        # Many scripts are not enumerated by entity.py so a global CanProcessRemote is not necessary.
        # For clarity, it might be fine to replace the parameter can_process_remote by the global value.
        # There cannot be nasty consequences except that some scripts might not be displayed
        # when they should be, and vice-versa.
        try:
            globalCanProcessRemote = globals()["CanProcessRemote"]
        except KeyError:
            globalCanProcessRemote = False

        if can_process_remote != globalCanProcessRemote:
            # sys.stderr.write("INCONSISTENCY CanProcessRemote\n") # ... which is not an issue.
            can_process_remote = True

        self.m_can_process_remote = can_process_remote

        self.m_arguments = cgi.FieldStorage()

        self.m_entity_type = entity_class
        self.m_entity_id = entity_id
        self.m_entity_host = entity_host
        self.m_entity_id_dict = entity_id_dict

        self._create_or_get_graph()

        # Depending on the caller module, maybe the arguments should be 64decoded. See "sql/query".
        # As the entity type is available, it is possible to import it and check if it encodes it arguments.
        # See presence of source_types.sql.query.DecodeCgiArg(keyWord,cgiArg) for example.

        # This is probably too generous to indicate a local host.
        self.test_remote_if_possible(can_process_remote)

        if mode == "edit":
            self.enter_edition_mode()
            assert False

        # Scripts which can run as events generator must have their name starting with "events_generator_".
        # This allows to use CGI programs as events genetors not written in Python.
        # TODO: Using the script name is enough, the module is not necessary.
        full_script_path, _, _ = self.m_calling_url.partition("?")
        script_basename = os.path.basename(full_script_path)
        daemonizable_script = os.path.basename(script_basename).startswith("events_generator_")

        if not daemonizable_script:
            # This would be absurd to have a normal CGI script started in this mode.
            assert mode != "daemon", "Script is not an events generator:" + self.m_calling_url
            # Runs as usual as a CGI script. The script will fill the graph.
            return

        # The events graph must be specified because, from here, everything will access the events graph.
        set_events_credentials()

        # Maybe this is in the daemon.
        if mode == "daemon":
            # Just runs as usual. At the end of the script, OutCgiRdf will write the RDF graph in the events.
            # Here, this process is started by the supervisor process; It is not started by the HTTP server,
            # in CGI or WSGI.
            return

        if not lib_daemon.is_events_generator_daemon_running(self.m_url_without_mode):
            # This is the case of a daemonizable script, normally run.
            lib_daemon.start_events_generator_daemon(self.m_url_without_mode)
            # After that, whether the daemon dedicated to the script and its parameters is started or not,
            # the script is then executed in normal, snapshot mode, as a CGI script.
        else:
            # Events are probably stored in the big events graph. The host and port are not used in the URL.
            lib_kbase.read_events_to_graph(self.m_url_without_mode, self.m_graph)

            # TODO: IT SHOULD BE WITH THE PARAMETERS OF OutCgiRdf() IN THIS SCRIPT !!
            # TODO: THESE LAYOUT PARAMETERS: dot_layout, collapsed_properties SHOULD BE IN THE CONSTRUCTOR.
            # TODO: Or ... simply go on with the script in snapshot mode ??
            self.OutCgiRdf()
            exit(0)

    def _concatenate_entity_documentation(self, full_title, entity_class, entity_id):
        """This appends to the title, the documentation of the class of the object, if there is one. """
        if entity_id:
            # If there is an object to display.
            # Practically, we are in the script "entity.py" and the single doc string is "Overview"
            self.m_page_title += " " + full_title

            # We assume there is an object, and therefore a class and its description.

            # Similar code in objtypes.py
            # This is different of _get_calling_module, which takes the __doc__ of the script.
            entity_module = lib_util.GetEntityModule(entity_class)
            ent_doc = entity_module.__doc__
            # The convention is the first line treated as a title.
            if ent_doc:
                ent_doc = ent_doc.strip()
                self.m_page_title += "\n" + ent_doc

    def test_remote_if_possible(self,can_process_remote):
        # This is probably too generous to indicate a local host.
        if can_process_remote or self.m_entity_host is None:
            return

        if lib_util.IsLocalAddress(self.m_entity_host):
            return

        ErrorMessageHtml("Script %s cannot handle remote hosts on host=%s" % ( sys.argv[0], self.m_entity_host ) )

    def _create_or_get_graph(self):
        global globalMergeMode
        try:
            assert self.m_graph
            raise Exception("self.m_graph must not be defined")
        except AttributeError:
            pass
        if globalMergeMode:
            # When in merge mode, the same object must be always returned.
            self.m_graph = globalGraph
        else:
            self.m_graph = _global_create_graph()
        return self.m_graph

    def GetGraph(self):
        return self.m_graph

    def ReinitGraph(self):
        """This is used by events generators in daemon mode."""
        try:
            del self.m_graph
        except AttributeError:
            pass
        self._create_graph()
        return self.m_graph

    # TODO: If no arguments, allow to edit it.
    # TODO: Same font as in SVG mode.
    # TODO: Use Jinja or any other HTML library to edit the script parameters.
    # Suggest all available scritps for this entity type.
    # Add legend in RDF mode:
    # http://stackoverflow.com/questions/3499056/making-a-legend-key-in-graphviz
    def enter_edition_mode(self):
        """This allow to edit the CGI parameters when in SVG (Graphviz) mode"""
        import lib_export_html
        import lib_edition_parameters

        form_action = os.environ['SCRIPT_NAME']
        DEBUG("enter_edition_mode form_action=%s", form_action)

        lib_util.WrtHeader('text/html')

        # It uses the same CSS as in HTML mode.
        lib_export_html.display_html_text_header(self.m_page_title + " - parameters")


        # TODO: Move this to lib_edition_parameters.py
        print("<body>")

        print("<h3>%s</h3><br>"%self.m_page_title)

        html_form = "".join(lib_edition_parameters.FormEditionParameters(form_action, self))
        print(html_form)

        print("</body>")
        print("</html>")
        sys.exit(0)

    def get_parameters(self, paramkey):
        """These are the parameters specific to the script, which are edit in our HTML form, in enter_edition_mode().
        They must have a default value. Maybe we could always have an edition mode when their value is not set.
        If the parameter is "cimom", it will extract the host of Uris like these: Wee GetHost()
        https://jdd:test@acme.com:5959/cimv2:CIM_RegisteredProfile.InstanceID="acme:1"
        """

        # Default value if no CGI argument.
        try:
            dflt_value = self.m_parameters[paramkey]
            # sys.stderr.write("get_parameters %s Default=%s\n" % ( paramkey, dflt_value ) )
            has_dflt_val = True
        except KeyError:
            has_dflt_val = False

        # unchecked_hidden
        has_arg_value = True
        try:
            # If the script parameter is passed as a CGI argument.
            # BEWARE !!! An empty argument triggers an exception !!!
            # Same problem if the same argument appears several times: This will be a list.
            param_val = self.m_arguments[paramkey].value
        except KeyError:
            DEBUG("get_parameters paramkey='%s' not as CGI", paramkey )
            has_arg_value = False

        # Now converts it to the type of the default value. Otherwise untouched.
        if has_dflt_val:
            if has_arg_value:
                param_typ = type(dflt_value)
                param_val = param_typ(param_val)
            else:
                # If the parameters were edited but the value did not appear,
                # it can only be a Boolean with a clear check box.
                # https://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
                # Unchecked check boxes are not POSTed.
                try:
                    self.m_arguments["edimodtype"]
                    param_val = False

                    # Sets the right value of the parameter because HTML form do not POST unchecked check boxes.
                    # Therefore, if in edit mode, a parameter is not returned, it can only be a False boolean.
                    self.m_parameters[paramkey] = param_val
                    DEBUG("get_parameters paramkey='%s' set to FALSE", paramkey )
                except KeyError:
                    param_val = dflt_value
                    DEBUG("get_parameters paramkey='%s' set to param_val='%s'", paramkey, param_val )
        else:
            if not has_arg_value:
                param_val = ""
            else:
                DEBUG("get_parameters nothing for paramkey='%s'", ( paramkey ))

        # TODO: Beware, empty strings are NOT send by the HTML form,
        # TODO: so an empty string must be equal to the default value.

        return param_val

    def GetId(self):
        """This is used for some scripts which have a single parameter (For example pid and file name).
        GetId() just returns the value of an unique key-value pair.
        """
        DEBUG("GetId m_entity_type=%s m_entity_id=%s", self.m_entity_type, str( self.m_entity_id ) )
        try:
            # If this is a top-level url, no object type, therefore no id.
            if self.m_entity_type == "":
                return ""

            split_kv = self.m_entity_id_dict
            DEBUG("GetId split_kv=%s", str( split_kv))

            # If this class is defined in our ontology, then we know the first property.
            ent_onto = lib_util.OntologyClassKeys(self.m_entity_type)
            if ent_onto:
                key_first = ent_onto[0]
                # Only if this mandatory key is in the dict.
                try:
                    return split_kv[key_first]
                except KeyError:
                    # This is a desperate case...
                    pass
            # Returns the first value but this is not reliable at all.
            for key in split_kv:
                return split_kv[key]
        except KeyError:
            pass

        # If no parameters is found, although one was requested.
        self.enter_edition_mode()
        assert False
        return ""

    def GetHost(self):
        return self.m_entity_host

    # TODO: Would probably be faster by searching for the last "/".
    # '\\\\MYHOST-HP\\root\\cimv2:Win32_Process.Handle="0"'  => "root\\cimv2:Win32_Process"
    # https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"  => ""
    def get_namespace_type(self):
        return lib_util.parse_namespace_type(self.m_entity_type)

    # When in merge mode, these parameters must be aggregated, and used only during
    # the unique generation of graphic data.
    # TODO: "OutCgiRdf" should be changed to a more appropriate name, such as "DisplayTripleStore"
    # cgiEnv.OutCgiRdf() will fill self.GetGraph() with events returned by a script in daemon mode.
    def OutCgiRdf(self, layout_style="", collapsed_properties=[]):
        global globalCgiEnvList
        DEBUG("OutCgiRdf globalMergeMode=%d m_calling_url=%s m_page_title=%s",
              globalMergeMode, self.m_calling_url, self.m_page_title.replace("\n", "<NL>"))

        # TODO: Get these values from the RDF document, if these were added on-the-fly by CGI scripts.
        if layout_style:
            self.m_layout_style = layout_style
        self.m_collapsed_properties.extend(collapsed_properties)

        mode = lib_util.GuessDisplayMode()

        top_url = lib_util.TopUrl(self.m_entity_type, self.m_entity_id)

        if self.m_page_title is None:
            self.m_page_title = "PAGE TITLE SHOULD BE SET"
            self.m_page_subtitle = "PAGE SUBTITLE SHOULD BE SET"

        # TODO: See if this can be used in lib_client.py and merge_scripts.py.
        if globalMergeMode:
            # At the end, only one call to OutCgiMode() will be made.
            globalCgiEnvList.append(self)
        else:
            OutCgiMode(self, top_url, mode)

    # Example: cgiEnv.add_parameterized_links( "Next", { paramkeyStartIndex : startIndex + maxInstances } )
    def add_parameterized_links(self, url_label, params_map):
        """
        This edits an URL by changing some CGI parameters. For example,
        if the script displays a list, we wish to change the number of displayed items or the first and last index.
        This is not used for objects (as it would create new objects because the URL would be different),
        but only for scripts (and then, indeed the script is different because it returns different objects).
        """

        # We want to display links associated to the parameters.
        # The use case is "Prev/Next" when paging between many values.
        # This calculates the URLS and returns a map of { "label":"urls" }

        # Copy the existing parameters of the script. This will be updated.
        prms_copy = dict()
        for arg_k in cgi.FieldStorage():
            arg_v = cgi.FieldStorage()[arg_k].value
            # sys.stderr.write("add_parameterized_links arg_k=%s arg_v=%s\n"%(arg_k,arg_v))
            prms_copy[arg_k] = lib_util.urllib_quote(arg_v)

        # Update these parameters with the values specific for this label.
        for param_key in params_map:
            # Check that it is a valid parameter.
            try:
                self.m_parameters[param_key]
            except KeyError:
                ErrorMessageHtml("Parameter %s should be defined for a link" % param_key)
            prms_copy[param_key] = params_map[param_key]

        DEBUG("prms_copy=%s", str(prms_copy))

        # Now create an URL with these updated params.
        idx_cgi = self.m_calling_url.find("?")
        if idx_cgi < 0:
            labelled_url = self.m_calling_url
        else:
            labelled_url = self.m_calling_url[:idx_cgi]

        # FIXME: ENCODING PROBLEM HERE.
        # OK http://127.0.0.1/Survol/survol/class_wbem.py?Start+index=0&Max+instances=800&xid=http%3A%2F%2Fprimhillcomputers.ddns.net%3A5988%2Froot%2Fcimv2%3APG_UnixProcess.&edimodtype=root%2Fcimv2%3APG_UnixProcess
        # OK http://rchateau-hp:8000/survol/class_wbem.py?xid=http%3A%2F%2F192.168.0.17%3A5988%2Froot%2Fcimv2%3APG_UnixProcess.
        # KO http://rchateau-hp:8000/survol/class_wbem.py?xid=http%3A//192.168.0.17%3A5988/root/cimv2%3APG_UnixProcess.
        # Conversion to str() because of integer parameters.
        kv_pairs_concat = "&amp;amp;".join(
            "%s=%s" % (param_key, str(prms_copy[param_key]).replace("/", "%2F"))
            for param_key in prms_copy)
        labelled_url += "?" + kv_pairs_concat

        DEBUG("labelled_url=%s", labelled_url)

        self.m_parameterized_links[url_label] = labelled_url

    # Graphs might contain the same entities calculated by different servers.
    # This can happen here, when several URLs are merged.
    # This can happen also in the JavaScript client, where several URLs
    # are dragged and dropped in the same browser session.
    # The same object will have different URLs depending on the server where it is detected.
    # For example, a remote database might be seen from different machines.
    # These different nodes, representing the same object, must be associated.
    # For this, we calculated for each node, its universal alias.
    # This is done, basically, by taking the URL, replacing the host name of where
    # the object sits, by an IP address.
    # Nodes with the same alias are graphically linked with a dashed red line.
    def _bind_identical_nodes(self):

        # This maps each universal alias to the set of nodes which have it.
        # At the end, all nodes with the same universal alias are linked with a special property.
        dict_uni_to_objs = dict()

        def _has_univ_alias(an_object):
            if lib_kbase.IsLiteral(an_object):
                return False

            if (an_object.find("entity.py") >= 0) or \
               (an_object.find("entity_wbem.py") >= 0) or \
               (an_object.find("entity_wmi.py") >= 0):
                return True

            return False

        # This calculates the universal alias for each node representing an object.
        def _prepare_binding(an_object):

            if not _has_univ_alias(an_object):
                return

            uni_descr = lib_exports.NodeToUniversalAlias(an_object)
            try:
                dict_uni_to_objs[uni_descr].add(an_object)
            except KeyError:
                dict_uni_to_objs[uni_descr] = {an_object}

        for a_subj, a_pred, an_obj in self.m_graph:
            _prepare_binding(a_subj)
            _prepare_binding(an_obj)

        for an_uni_descr in dict_uni_to_objs:
            related_nodes = dict_uni_to_objs[an_uni_descr]
            if len(related_nodes) < 2:
                continue

            node_previous = None

            # These specific links must be very visible and short.
            # They should be displayed identically in SVG and D3.
            # Ideally, all objects with the same alias should be a single graphic shape,
            # with all scripts of each object.
            for other_node in related_nodes:
                if node_previous:
                    self.m_graph.add((node_previous, lib_properties.pc.property_alias, other_node))
                node_previous = other_node


################################################################################

globalErrorMessageEnabled = True


# Used when merging several scripts, otherwise there is no way to find
# which scripts produced an error.
def enable_error_message(flag):
    global globalErrorMessageEnabled
    globalErrorMessageEnabled = flag


def ErrorMessageHtml(message):
    """This is called by CGI scripts to leave with an error message.
    At this stage, the CGI scripts did not write anything to stdout.
    Therefore, it is possible to return any MIME document.
    The challenge is to return an error message in the expected output format: html, json, rdf etc..."""
    if globalErrorMessageEnabled:
        ERROR("ErrorMessageHtml %s. Exiting.", message)
        try:
            # Use RequestUri() instead of "REQUEST_URI", because this CGI environment variable
            # is not set in minimal HTTP servers such as CGIHTTPServer.
            request_uri = lib_util.RequestUri()
            url_mode = lib_util.get_url_mode(request_uri)
            sys.stderr.write("ErrorMessageHtml request_uri=%s url_mode=%s\n" % (request_uri, url_mode))
            if url_mode == "json":
                # If we are in Json mode, this returns a special json document with the error message.
                lib_export_json.WriteJsonError(message)
                sys.exit(0)
            if url_mode == "rdf":
                # If we are in Json mode, this returns a special RDF document with the error message.
                lib_export_ontology.WriteRdfError(message, request_uri)
                sys.exit(0)
        except KeyError:
            pass

        # 'SERVER_SOFTWARE': 'SimpleHTTP/0.6 Python/2.7.10', 'WSGIServer/0.2'
        try:
            server_software = os.environ['SERVER_SOFTWARE']
        except KeyError:
            server_software = "Unknown_SERVER_SOFTWARE"
        lib_util.InfoMessageHtml(message)
        DEBUG("ErrorMessageHtml about to leave. server_software=%s" % server_software)

        if server_software.find('WSGIServer') >= 0:
            # WSGI server is persistent and should not exit.
            raise RuntimeError("Server software=" + server_software)
        else:
            sys.exit(0)
    else:
        # Instead of exiting, it throws an exception which can be used by merge_scripts.py
        DEBUG("ErrorMessageHtml DISABLED")
        # It might be displayed in a HTML document.
        message_clean = lib_util.html_escape(message)
        raise Exception("ErrorMessageHtml raised:%s\n" % message_clean)

################################################################################


def SubProcPOpen(command):
    try:
        ret_pipe = subprocess.Popen(command, bufsize=100000, shell=False,
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        ErrorMessageHtml("Cannot run " + " ".join(command))

    # For the win32/script windows_network_devices.py,
    # we need shell=True, because it runs the command "wmic",
    # but this might be a security hole.
    return ret_pipe


def SubProcCall(command):
    # For doxygen, we should have shell=True but this is NOT safe.
        # Shell is however needed for unit tests.
    DEBUG("command=%s", command)
    ret = subprocess.call(command, stdout=sys.stderr, stderr=sys.stderr, shell=True)
    return ret

################################################################################


################################################################################

def _is_shared_library(path):
    """This is deprecated and was used to reduce the number fo displayed filed,
    by hiding the ones which are not really interesting."""

    if lib_util.isPlatformWindows:
        tmp, file_ext = os.path.splitext(path)
        return file_ext.upper() in [".DLL"]

    if lib_util.isPlatformLinux:
        # We could also check if this is really a shared library.
        # file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
        if path.endswith(".so"):
            return True

        # Not sure about "M" and "I". Also: Should precompile regexes.
        for rgx in [r'/lib/.*\.so\..*', r'/usr/lib/.*\.so\..*']:
            if re.match(rgx, path, re.M|re.I):
                return True

        for start in [
            '/usr/share/locale/',
            '/usr/share/fonts/',
            '/etc/locale/',
            '/var/cache/fontconfig/',
            '/usr/lib/jvm/']:
            if path.startswith(start):
                return True

    return False


def _is_fonts_file(path):
    """A file containing fonts and other stuff not useful to understand how a process works.
    So by default they are ot displayed. This should be deprecated."""

    if lib_util.isPlatformWindows:
        tmp, file_ext = os.path.splitext(path)
        # sys.stderr.write("_is_fonts_file file_ext=%s\n" % file_ext)
        return file_ext in [ ".ttf", ".ttc" ]

    elif lib_util.isPlatformLinux:
        for start in [
            '/usr/share/locale/',
            '/usr/share/fonts/',
            '/etc/locale/',
            '/var/cache/fontconfig/',
            '/usr/lib/jvm/'] :
            if path.startswith(start):
                return True
    return False

def is_meaningless_file(path, remove_shared_libs, remove_fonts_file):
    """Used when displaying all files open by a process: There are many of them,
    so the irrelevant files are hidden. This should be an option."""
    if remove_shared_libs:
        if _is_shared_library(path):
            return True

    if remove_fonts_file:
        if _is_fonts_file(path):
            # sys.stderr.write("YES is_meaningless_file path=%s\n" % path)
            return True

    return False


################################################################################
# Reformat the username because in psutil.users() it is "John",
# but from process.username(), it is "MYPC\John"
#
# http://msdn.microsoft.com/en-gb/library/windows/desktop/aa380525(v=vs.85).aspx
# User principal name (UPN) format is used to specify an Internet-style name,
# such as UserName@Example.Microsoft.com.
#
# The down-level logon name format is used to specify a domain
# and a user account in that domain, for example, DOMAIN\UserName.
# The following table summarizes the parts of a down-level logon name.
#
# Some say that: UserName@DOMAIN also works.
# 
# http://serverfault.com/questions/371150/any-difference-between-domain-username-and-usernamedomain-local
def format_username(usrnam):
    # BEWARE: THIS TRUNCATES THE DOMAIN NAME.
    shortnam = usrnam.split('\\')[-1]

    # return shortnam + "@" + lib_util.currentHostname
    return shortnam


def set_events_credentials():
    """This sets the global parameter telling where the events are stored."""
    storage_credential = lib_credentials.GetCredentials("Storage", "Events")
    if not storage_credential:
        credentials_filename = lib_credentials.credentials_filename()
        raise Exception("No storage credential in:%s" % credentials_filename)

    storage_style, storage_url = storage_credential
    lib_kbase.set_storage_style(storage_style, storage_url)

