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
import lib_daemon

from lib_util import NodeLiteral
from lib_util import NodeUrl
from lib_util import TimeStamp

# Functions for creating uris are imported in the global namespace.
from lib_uris import *
import lib_uris

################################################################################

nodeMachine = gUriGen.HostnameUri( lib_util.currentHostname )

################################################################################


# Could be reused if we want to focus on some processes only.
# proc in [ 'bash', 'gvim', 'konsole' ]
def is_useless_process(proc):
    return False

################################################################################
    
## Also, the Apache 2.2 docs have a slightly different location for the registry key:
## HKEY_CLASSES_ROOT\.cgi\Shell\ExecCGI\Command\(Default) => C:\Perl\bin\perl.exe -wT

################################################################################

def write_dot_header( page_title, layout_style, stream, grph ):
    # Some cleanup.
    page_title_clean = page_title.strip()
    page_title_clean = page_title_clean.replace("\n", " ")
    # Title embedded in the page.
    stream.write('digraph "' + page_title_clean + '" { \n')

    # CSS style-sheet should be in the top-level directory ?
    # Not implemented in 2010: http://graphviz.org/bugs/b1874.html
    # Add a CSS-like "class" attribute
    # stream.write(' stylesheet = "rdfmon.css" \n')

    # Maybe the layout is forced.
    # dot - "hierarchical" or layered drawings of directed graphs. This is the default tool to use if edges have directionality.
    # neato - "spring model'' layouts.  This is the default tool to use if the graph is not too large (about 100 nodes) and you don't know anything else about it. Neato attempts to minimize a global energy function, which is equivalent to statistical multi-dimensional scaling.
    # fdp - "spring model'' layouts similar to those of neato, but does this by reducing forces rather than working with energy.
    # sfdp - multiscale version of fdp for the layout of large graphs.
    # twopi - radial layouts, after Graham Wills 97. Nodes are placed on concentric circles depending their distance from a given root node.
    # circo - circular layout, after Six and Tollis 99, Kauffman and Wiese 02. This is suitable for certain diagrams of multiple cyclic structures, such as certain telecommunications networks.
    # This is a style more than a dot layout.
    # sys.stderr.write("Lay=%s\n" % (layout_style) )
    if layout_style == "LAYOUT_RECT":
        dot_layout = "dot"
        # Very long lists: Or very flat tree.
        stream.write(" splines=\"ortho\"; \n")
        stream.write(" rankdir=\"LR\"; \n")
    elif layout_style == "LAYOUT_RECT_RL":
        dot_layout = "dot"
        # Very long lists: Or very flat tree.
        stream.write(" splines=\"ortho\"; \n")
        stream.write(" rankdir=\"RL\"; \n")
    elif layout_style == "LAYOUT_RECT_TB":
        dot_layout = "dot"
        # Very long lists: Or very flat tree.
        stream.write(" splines=\"ortho\"; \n")
        # stream.write(" rank=\"source\"; \n")
        stream.write(" rankdir=\"TB\"; \n")
    elif layout_style == "LAYOUT_TWOPI":
        # Used specifically for file/file_stat.py : The subdirectories
        # are vertically stacked.
        dot_layout = "twopi"
        stream.write(" rankdir=\"LR\"; \n")
    elif layout_style == "LAYOUT_SPLINE":
        # Win32_Services, many interconnections.
        dot_layout = "fdp"
        # stream.write(" splines=\"curved\"; \n") # About as fast as straight lines
        stream.write(" splines=\"spline\"; \n") # Slower than "curved" but acceptable.
        stream.write(" rankdir=\"LR\"; \n")
        # stream.write(" splines=\"compound\"; \n") ### TRES LENT
    else:
        dot_layout = "fdp" # Faster than "dot"
        # TODO: Maybe we could use the number of elements len(grph)  ?
        stream.write(" rankdir=\"LR\"; \n")
    stream.write(" layout=\"" + dot_layout + "\"; \n")

    # TODO: Take the font from the CSS html_exports.css
    # Example on Windows: stream.write(" node [ fontname=\"DejaVu Sans\" ] ; \n")
    stream.write(" node [ %s ] ; \n" % lib_exports.FontString() )
    return dot_layout

################################################################################

# Copies a file to standard output.
# TODO: On Linux, consider splice.
# See lib_kbase.triplestore_to_stream_xml for a similar situation.
def copy_to_output_destination(logfil, svg_out_filnam, out_dest):
    logfil.write( TimeStamp() + " Output without conversion: %s\n" % svg_out_filnam  )
    infil = open(svg_out_filnam,'rb')
    strInRead = infil.read()
    try:
        nbOut = out_dest.write(strInRead)
    except TypeError as exc:
        # This happens when:
        # Python 2 and wsgiref.simple_server: unicode argument expected, got 'str'
        # Python 3 and wsgiref.simple_server: string argument expected, got 'bytes'
        nbOut = out_dest.write(strInRead.decode('latin1'))

    logfil.write( TimeStamp() + " End of output without conversion: %s chars\n" % str(nbOut) )
    infil.close()

################################################################################


# TODO: Consider using the Python module pygraphviz: Small speedup probably.
# But the priority is to avoid graphes which are too long to route.
# TODO: Consider using the Python module pydot,
# but anyway it needs to have graphviz already installed.
# Also, creating an intermediary files helps debugging.
def _dot_to_svg(dot_filnam_after, logfil, viztype, out_dest):
    DEBUG("viztype=%s",viztype)
    tmp_svg_fil = TmpFile("_dot_to_svg","svg")
    svg_out_filnam = tmp_svg_fil.Name
    # dot -Kneato

    # Dot/Graphviz no longer changes PATH at installation. It must be done BEFORE.
    dot_path = "dot"

    if lib_util.isPlatformLinux:
        # TODO: This is arbitrary because old Graphviz version.
        # TODO: Take the fonts from html_exports.css
        # dot_fonts = ["-Gfontpath=/usr/share/fonts/TTF", "-Gfontnames=svg", "-Nfontname=VeraBd.ttf","-Efontname=VeraBd.ttf"]
        dot_fonts = [
                    # "-Gfontpath=/usr/share/fonts/dejavu", 
                    "-Gfontpath=/usr/share/fonts", 
                    "-Gfontnames=svg",
                    "-Nfontname=DejaVuSans.ttf",
                    "-Efontname=DejaVuSans.ttf"]
    else:
         dot_fonts = []

    # Old versions of dot need the layout on the command line.
    # This is maybe a bit faster than os.open because no shell and direct write to the output.
    svg_command = [dot_path, "-K", viztype, "-Tsvg", dot_filnam_after, "-o", svg_out_filnam,
                   "-v", "-Goverlap=false"] + dot_fonts
    msg = "svg_command=" + " ".join(svg_command)
    DEBUG(msg)
    logfil.write(TimeStamp()+" "+msg+"\n")

    ret = subprocess.call(svg_command, stdout=logfil, stderr=logfil, shell=False)
    logfil.write(TimeStamp()+" Process ret=%d\n" % ret)

    if not os.path.isfile(svg_out_filnam):
        ErrorMessageHtml("SVG file " + svg_out_filnam + " could not be created.")

    # TODO: If there is an error, we should write it as an HTML page.
    # On the other hand it is impossible to pipe the output because it would assume a SVG document.

    # https://stackoverflow.com/questions/5667576/can-i-set-the-html-title-of-a-pdf-file-served-by-my-apache-web-server
    dictHttpProperties = [ ( "Content-Disposition", 'inline; filename="Survol_Download"') ]

    logfil.write(TimeStamp() + " Writing SVG header\n")
    lib_util.WrtHeader("image/svg+xml", dictHttpProperties)

    # Here, we are sure that the output file is closed.
    copy_to_output_destination(logfil, svg_out_filnam, out_dest)

################################################################################


# This transforms a RDF triplestore into a temporary DOT file, which is
# transformed by GraphViz into a SVG file sent to the HTTP browser.
def _graph_to_svg(page_title, error_msg, isSubServer, parameters, grph, parameterized_links, topUrl, dot_style):
    tmp_log_fil = TmpFile("_graph_to_svg", "log")
    try:
        logfil = open(tmp_log_fil.Name, "w")
    except Exception as exc:
        ERROR("_graph_to_svg caught %s when opening:%s", str(exc), tmp_log_fil.Name)
        ErrorMessageHtml("_graph_to_svg caught %s when opening:%s\n" % (str(exc), tmp_log_fil.Name))

    logfil.write("Starting logging\n")

    tmp_dot_fil = TmpFile("Grph2Dot", "dot")
    dot_filnam_after = tmp_dot_fil.Name
    rdfoutfil = open(dot_filnam_after, "w")
    logfil.write(TimeStamp() + " Created " + dot_filnam_after + "\n")

    dot_layout = write_dot_header(page_title, dot_style['layout_style'], rdfoutfil, grph)
    lib_exports.WriteDotLegend(page_title, topUrl, error_msg, isSubServer, parameters, parameterized_links, rdfoutfil,
                               grph)
    logfil.write(TimeStamp() + " Legend written\n")
    lib_export_dot.Rdf2Dot(grph, logfil, rdfoutfil, dot_style['collapsed_properties'])
    logfil.write(TimeStamp() + " About to close dot file\n")

    # BEWARE: Do this because the file is about to be reopened from another process.
    rdfoutfil.flush()
    os.fsync(rdfoutfil.fileno())
    rdfoutfil.close()

    out_dest = lib_util.get_default_output_destination()

    _dot_to_svg(dot_filnam_after, logfil, dot_layout, out_dest)
    logfil.write(TimeStamp() + " closing log file\n")
    logfil.close()

################################################################################


# The result can be sent to the Web browser in several formats.
# TODO: The nodes should be displayed always in the same order.
# THIS IS NOT THE CASE IN HTML AND SVG !!
def OutCgiMode(theCgi, topUrl, mode, errorMsg = None, isSubServer=False):
    theCgi._bind_identical_nodes()

    grph = theCgi.m_graph
    page_title = theCgi.m_page_title
    dot_layout = theCgi.m_layoutParams
    parameters = theCgi.m_parameters
    parameterized_links = theCgi.m_parameterized_links

    if mode == "html":
        # Used rarely and performance not very important. This returns a HTML page.
        lib_export_html.Grph2Html(theCgi, topUrl, errorMsg, isSubServer, globalCgiEnvList)
    elif mode == "json":
        lib_exports.Grph2Json(page_title, errorMsg, isSubServer, parameters, grph)
    elif mode == "menu":
        lib_exports.Grph2Menu(page_title, errorMsg, isSubServer, parameters, grph)
    elif mode == "rdf":
        lib_export_ontology.Grph2Rdf(grph)
    elif mode == "daemon":
        # This is the end of a loop, or events transaction, in the script which does not in CGI context,
        # but in a separate daemon process.
        # This sends the results to the Events directory. See EventsGeneratorDaemon
        set_events_credentials()
        lib_kbase.write_graph_to_events(theCgi.m_url_without_mode, theCgi.m_graph)
        pass
    elif mode in ["svg",""]:
        # Default mode, because graphviz did not like several CGI arguments in a SVG document (Bug ?).
        _graph_to_svg(page_title, errorMsg, isSubServer, parameters, grph, parameterized_links, topUrl, dot_layout)
    else:
        ERROR("OutCgiMode invalid mode=%s",mode)
        ErrorMessageHtml("OutCgiMode invalid mode=%s"%mode)

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


def make_dot_layout(dot_layout, collapsed_properties):
    return {'layout_style': dot_layout, 'collapsed_properties':collapsed_properties}

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
            filnam_caller = filnam_caller.replace("\\",".").replace("/",".")
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

# There is only one cgiEnv and "cgiEnv.OutCgiRdf()" does not generate anything.
# It is related to WSGI in the extent that global variables should not harm things.
def CgiEnvMergeMode():
    global globalMergeMode
    global globalCgiEnvList
    global globalGraph

    globalMergeMode = True
    globalCgiEnvList = []
    globalGraph = lib_kbase.MakeGraph()


# OutCgiRdf has been called by each script without writing anything,
# but the specific parameters per script are stored inside.
def MergeOutCgiRdf(theMode,cumulatedError):
    global globalMergeMode
    global globalCgiEnvList
    global globalGraph

    page_title = "Merge of %d scripts:\n" % len(globalCgiEnvList)
    delim_title = ""
    # This is equivalent to: make_dot_layout( "", [] )
    layout_params = {'layout_style': "", 'collapsed_properties': []}
    cgi_params = {}
    cgi_param_links = {}
    for theCgiEnv in globalCgiEnvList:
        # theCgiEnv.m_page_title contains just the first line.
        (page_title_first, page_title_rest) = (theCgiEnv.m_page_title, theCgiEnv.m_page_subtitle)
        page_title += delim_title + page_title_first
        if page_title_rest:
            page_title += " (" + page_title_rest + ")"
        delim_title = ", "

        layout_params['layout_style'] = theCgiEnv.m_layoutParams['layout_style']
        layout_params['collapsed_properties'].extend( theCgiEnv.m_layoutParams['collapsed_properties'])

        # The dictionaries of parameters and corresponding links are merged.
        try:
            cgi_params.update(theCgiEnv.m_parameters)
            cgi_param_links.update(theCgiEnv.m_parameterized_links)
        except ValueError:
            errorMsg = sys.exc_info()[1]
            WARNING("Error:%s Parameters:%s",errorMsg,str(theCgiEnv.m_parameters))

    # Eliminate duplicates in the list of collapsed properties.
    my_list = layout_params['collapsed_properties']
    my_set = set(my_list)
    layout_params['collapsed_properties'] = list(my_set)

    top_url = lib_util.TopUrl("", "")

    pseudo_cgi = CgiEnv()
    pseudo_cgi.m_graph = globalGraph
    pseudo_cgi.m_page_title = page_title
    pseudo_cgi.m_page_subtitle = ""
    pseudo_cgi.m_layoutParams = layout_params
    # Not sure this is the best value, but this is usually done.
    # TODO: We should have a plain map for all m_arguments occurences.
    pseudo_cgi.m_arguments = cgi.FieldStorage()
    pseudo_cgi.m_parameters = cgi_params
    pseudo_cgi.m_parameterized_links = cgi_param_links
    pseudo_cgi.m_entity_type = ""
    pseudo_cgi.m_entity_id = ""
    pseudo_cgi.m_entity_host = ""

    # A single rendering of all RDF nodes and links merged from several scripts.
    OutCgiMode(pseudo_cgi, top_url, theMode, errorMsg=cumulatedError)

    return

################################################################################

class CgiEnv():
    """
        This class parses the CGI environment variables which define an entity.
    """
    def __init__(self, parameters = {}, can_process_remote = False ):
        # TODO: This value is read again in OutCgiRdf, we could save time by making this object global.
        #sys.stderr.write( "CgiEnv parameters=%s\n" % ( str(parameters) ) )

        # TODO: When running from cgiserver.py, and if QUERY_STRING is finished by a dot ".", this dot
        # TODO: is removed. Workaround: Any CGI variable added after.
        # TODO: Also: Several slashes "/" are merged into one.
        # TODO: Example: "xid=http://192.168.1.83:5988/." becomes "xid=http:/192.168.1.83:5988/"
        # TODO: ... or "xx.py?xid=smbshr.Id=////WDMyCloudMirror///rchateau" become "xx.py?xid=smbshr.Id=/WDMyCloudMirror/rchateau"
        # TODO: Replace by "xid=http:%2F%2F192.168.1.83:5988/."
        # Maybe a bad collapsing of URL ?
        # sys.stderr.write("QUERY_STRING=%s\n" % os.environ['QUERY_STRING'] )
        mode = lib_util.GuessDisplayMode()

        # Contains the optional arguments, needed by calling scripts.
        self.m_parameters = parameters

        self.m_parameterized_links = dict()

        # When in merge mode, the display parameters must be stored in a place accessible by the graph.

        doc_modu_all = _get_calling_module_doc()

        # Take only the first non-empty line. See lib_util.FromModuleToDoc()
        self.m_page_title, self.m_page_subtitle = lib_util.SplitTextTitleRest(doc_modu_all)

        # Title page contains __doc__ plus object label.
        self.m_calling_url = lib_util.RequestUri()
        self.m_url_without_mode = lib_util.url_mode_replace(self.m_calling_url, "")
        self._concatenate_entity_documentation()

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

        (self.m_entity_type,self.m_entity_id,self.m_entity_host) = self.GetXid()
        #sys.stderr.write("CgiEnv m_entity_type=%s m_entity_id=%s m_entity_host=%s\n"%(self.m_entity_type,self.m_entity_id,self.m_entity_host))
        self.m_entity_id_dict = lib_util.SplitMoniker(self.m_entity_id)

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

        # Maybe this is in the daemon.
        if mode == "daemon":
            # Just runs as usual. At the end of the script, OutCgiRdf will write the RDF graph in the events.
            # Here, this process is started by the supervisor process; It is not started by the HTTP server,
            # in CGI or WSGI.
            return

        if not lib_daemon.is_events_generator_daemon_running(self.m_url_without_mode):
            lib_daemon.start_events_generator_daemon(self.m_url_without_mode)
            # After that, whether the daemon dedicated to the script and its parameters is started or not,
            # the script is then executed in normal, snapshot mode, as a CGI script.
        else:
            lib_kbase.read_events_to_graph(self.m_url_without_mode, self.m_graph)

            # TODO: IT SHOULD BE WITH THE PARAMETERS OF OutCgiRdf() IN THIS SCRIPT !!
            # TODO: THESE LAYOUT PARAMETERS: dot_layout, collapsed_properties SHOULD BE IN THE CONSTRUCTOR.
            self.OutCgiRdf()
            exit(0)

    def _concatenate_entity_documentation(self):
        """This appends to the title, the documentation of the class of the object, if there is one. """
        DEBUG("CgiEnv m_page_title=%s m_calling_url=%s", self.m_page_title, self.m_calling_url)
        #sys.stderr.write("CgiEnv lib_util.globalOutMach:%s\n" %(lib_util.globalOutMach.__class__.__name__))
        parsed_entity_uri = lib_naming.ParseEntityUri(self.m_calling_url, longDisplay=False, force_entity_ip_addr=None)
        if parsed_entity_uri[2]:
            # If there is an object to display.
            # Practically, we are in the script "entity.py" and the single doc string is "Overview"
            full_title = parsed_entity_uri[0]
            self.m_page_title += " " + full_title

            # We assume there is an object, and therefore a class and its description.
            entity_class = parsed_entity_uri[1]

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

    def GetGraph(self):
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
            self.m_graph = lib_kbase.MakeGraph()
        return self.m_graph

    def ReinitGraph(self):
        """This is used by events generators in daemon mode."""
        try:
            del self.m_graph
        except AttributeError:
            pass
        return self.GetGraph()

    # We avoid several CGI arguments because Dot/Graphviz wants no ampersand "&" in the URLs.
    # This might change because I suspect bugs in old versions of Graphviz.
    def GetXid(self):
        try:
            # See variable xidCgiDelimiter.
            # TODO: Consider base64 encoding all arguments with "Xid=".
            # The benefit would be to have the same encoding for all arguments.
            xid = self.m_arguments["xid"].value
        except KeyError:
            # See function enter_edition_mode
            try:
                return ( "", "", "" )
                # TODO: Not finished, useless or debugging purpose ?
                entity_type = self.m_arguments["edimodtype"].value
                monik_delim = ""
                entity_id = ""
                for edi_key in self.m_arguments:
                    if edi_key[:11] == "edimodargs_":
                        monik_key = edi_key[11:]
                        monik_val = self.m_arguments[edi_key].value
                        entity_id += monik_delim + monik_key + "=" + monik_val
                        monik_delim = "&"

                return (entity_type, entity_id, "")
            except KeyError:
                # No host, for the moment.
                return ("", "", "")
        return lib_util.ParseXid( xid )
    
    # TODO: If no arguments, allow to edit it.
    # TODO: Same font as in SVG mode.
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
        lib_export_html.DisplayHtmlTextHeader(self.m_page_title + " - parameters")

        print("<body>")

        print("<h3>%s</h3><br>"%self.m_page_title)

        htmlForm = "".join(lib_edition_parameters.FormEditionParameters(form_action,self))
        print(htmlForm)

        print("</body>")
        print("</html>")
        sys.exit(0)

    # These are the parameters specific to the script, which are edit in our HTML form, in enter_edition_mode().
    # They must have a default value. Maybe we could always have an edition mode when their value
    # is not set.
    # If the parameter is "cimom", it will extract the host of Uris like these: Wee GetHost()
    # https://jdd:test@acme.com:5959/cimv2:CIM_RegisteredProfile.InstanceID="acme:1"

    def get_parameters(self,paramkey):
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
            #sys.stderr.write("get_parameters paramkey='%s' param_val='%s' as CGI\n" % ( paramkey, param_val ) )
        except KeyError:
            DEBUG("get_parameters paramkey='%s' not as CGI", paramkey )
            has_arg_value = False

        # Now converts it to the type of the default value. Otherwise untouched.
        if has_dflt_val:
            if has_arg_value:
                param_typ = type(dflt_value)
                param_val = param_typ(param_val)
                #sys.stderr.write("get_parameters paramkey='%s' param_val='%s' after conversion to %s\n" % ( paramkey, param_val, str(param_typ) ) )
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
                #sys.stderr.write("get_parameters no value nor default for paramkey='%s' m_parameters=%s\n" % ( paramkey, str(self.m_parameters)))
                param_val = ""
            else:
                DEBUG("get_parameters nothing for paramkey='%s'", ( paramkey ))

        # TODO: Beware, empty strings are NOT send by the HTML form,
        # TODO: so an empty string must be equal to the default value.

        return param_val

    # This is used for compatibility with the legacy scripts, which has a single id.
    # Now all parameters must have a key. As a transition, GetId() will return the value of
    # the value of an unique key-value pair.
    # If this class is not in DMTF, we might need some sort of data dictionary.
    def GetId(self):
        DEBUG("GetId m_entity_type=%s m_entity_id=%s", self.m_entity_type, str( self.m_entity_id ) )
        try:
            # If this is a top-level url, no object type, therefore no id.
            if self.m_entity_type == "":
                return ""

            split_kv = lib_util.SplitMoniker(self.m_entity_id)
            DEBUG("GetId split_kv=%s", str( split_kv))

            # If this class is defined in our ontology, then we know the first property.
            ent_onto = lib_util.OntologyClassKeys(self.m_entity_type)
            if ent_onto:
                keyFirst = ent_onto[0]
                # Only if this mandatory key is in the dict.
                try:
                    return split_kv[keyFirst]
                except KeyError:
                    # This is a desperate case...
                    pass
            # Returns the first value but this is not reliable at all.
            for key in split_kv:
                return split_kv[key]
        except KeyError:
            pass

        # If no parameters although one was requested.
        self.enter_edition_mode()
        assert False
        return ""

    # TODO: Ca va etre de facon generale le moyen d'acces aux donnees et donc inclure le cimom
    # soit par example cimom=http://192.168.1.83:5988  ou bien seulement un nom de machine.
    # C'est ce que WMI va utiliser. On peut imaginer aussi de mettre un serveur ftp ?
    # Ou bien un serveur SNMP ?
    # C est plus un serveur qu un host. Le host est une propriete de l'objet, pas une clef d'acces.
    # C est ce qui va permettre d acceder au meme fichier par un disque partage et par ftp.
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
    # cgiEnv.OutCgiRdf() will fill self.GetGraph() with events returned by EventsGeneratorDaemon()
    def OutCgiRdf(self, dot_layout = "", collapsed_properties=[]):
        global globalCgiEnvList
        DEBUG("OutCgiRdf globalMergeMode=%d m_calling_url=%s m_page_title=%s",
              globalMergeMode, self.m_calling_url, self.m_page_title.replace("\n","<NL>"))

        self.m_layoutParams = make_dot_layout( dot_layout, collapsed_properties )

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
    def add_parameterized_links(self, urlLabel, paramsMap):
        """This adds the parameters of an URL which points to the same page,
        but with different CGI parameters. This URLS will displays basically
        the same things, from the same script."""

        # We want to display links associated to the parameters.
        # The use case is "Prev/Next" when paging between many values.
        # This calculates the URLS and returns a map of { "label":"urls" }

        # Copy the existing parameters of the script. This will be updated.
        prmsCopy = dict()
        for argK in cgi.FieldStorage():
            argV = cgi.FieldStorage()[argK].value
            # sys.stderr.write("add_parameterized_links argK=%s argV=%s\n"%(argK,argV))
            prmsCopy[argK] = lib_util.urllib_quote(argV)

        # Update these parameters with the values specific for this label.
        for paramKey in paramsMap:
            # Check that it is a valid parameter.
            try:
                self.m_parameters[paramKey]
            except KeyError:
                ErrorMessageHtml("Parameter %s should be defined for a link"%paramKey)
            prmsCopy[paramKey] = paramsMap[paramKey]

        DEBUG("prmsCopy=%s",str(prmsCopy))

        # Now create an URL with these updated params.
        idxCgi = self.m_calling_url.find("?")
        if idxCgi < 0:
            labelledUrl = self.m_calling_url
        else:
            labelledUrl = self.m_calling_url[:idxCgi]

        # FIXME: ENCODING PROBLEM HERE.
        # OK http://127.0.0.1/Survol/survol/class_wbem.py?Start+index=0&Max+instances=800&xid=http%3A%2F%2Fprimhillcomputers.ddns.net%3A5988%2Froot%2Fcimv2%3APG_UnixProcess.&edimodtype=root%2Fcimv2%3APG_UnixProcess
        # OK http://rchateau-hp:8000/survol/class_wbem.py?xid=http%3A%2F%2F192.168.0.17%3A5988%2Froot%2Fcimv2%3APG_UnixProcess.
        # KO http://rchateau-hp:8000/survol/class_wbem.py?xid=http%3A//192.168.0.17%3A5988/root/cimv2%3APG_UnixProcess.
        # Conversion to str() because of integer parameters.
        kvPairsConcat = "&amp;amp;".join( "%s=%s" % ( paramKey,str(prmsCopy[paramKey]).replace("/","%2F")) for paramKey in prmsCopy )
        labelledUrl += "?" + kvPairsConcat

        DEBUG("labelledUrl=%s",labelledUrl)

        self.m_parameterized_links[urlLabel] = labelledUrl

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
    # Nodes with the same
    def _bind_identical_nodes(self):

        # This maps each universal alias to the set of nodes which have it.
        # At the end, all nodes with the same universal alias are
        # linked with a special property.
        dict_uni_to_objs = dict()

        def _has_univ_alias(an_object):
            if lib_kbase.IsLiteral(an_object):
                return False

            if (an_object.find("entity.py") >= 0) or (an_object.find("entity_wbem.py") >= 0) or(an_object.find("entity_wmi.py") >= 0):
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

        for aSubj, aPred, anObj in self.m_graph:
            _prepare_binding(aSubj)
            _prepare_binding(anObj)

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
        ERROR("ErrorMessageHtml %s. Exiting.",message)
        try:
            # Use RequestUri() instead of "REQUEST_URI", because this CGI environment variable
            # is not set in minimal HTTP servers such as CGIHTTPServer.
            request_uri = lib_util.RequestUri()
            url_mode = lib_util.get_url_mode(request_uri)
            sys.stderr.write("ErrorMessageHtml request_uri=%s url_mode=%s\n" % (request_uri, url_mode))
            if url_mode == "json":
                # If we are in Json mode, this returns a special json document with the error message.
                lib_exports.WriteJsonError(message)
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
        ErrorMessageHtml("Cannot run "+" ".join(command))

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

def __check_if_directory(dir):
    if( os.path.isdir(dir) ):
        return lib_util.standardized_file_path(dir)
    raise Exception("Not a dir:"+dir)

# The temp directory as specified by the operating system.
def get_temporary_directory():

    # TODO: For some reason, the user "apache" used by httpd cannot write,
    # on some Linux distributions, to the directory "/tmp"
    # https://blog.lysender.com/2015/07/centos-7-selinux-php-apache-cannot-writeaccess-file-no-matter-what/
    # This is a temporary fix. Maybe related to SELinux.
    try:
        if lib_util.isPlatformLinux:
            # 'SERVER_SOFTWARE': 'Apache/2.4.29 (Fedora)'
            if os.environ["SERVER_SOFTWARE"].startswith("Apache/"):
                # 'HTTP_HOST': 'vps516494.ovh.net'
                if os.environ["HTTP_HOST"].startswith("vps516494."):
                    return "/home/rchateau/tmp_apache"
    except:
        pass

    try:
        # Maybe these environment variables are undefined for Apache user.
        return __check_if_directory(os.environ["TEMP"])
    except Exception:
        pass

    try:
        return __check_if_directory(os.environ["TMP"])
    except Exception:
        pass

    if lib_util.isPlatformWindows:
        try:
            return __check_if_directory(os.path.join(os.environ["USERPROFILE"]), "AppData", "Local", "Temp")
        except Exception:
            pass

        try:
            return __check_if_directory("C:/Windows/Temp")
        except Exception:
            pass

        return __check_if_directory("C:/Temp")
    else:
        return __check_if_directory("/tmp")


# This will not change during a process.
global_temp_directory = get_temporary_directory()


# Creates and automatically delete, a file and possibly a dir.
# TODO: Consider using the module tempfile.
class TmpFile:
    def __init__(self, prefix="tmp", suffix="tmp", subdir=None):
        proc_pid = os.getpid()
        curr_dir = global_temp_directory

        if subdir:
            custom_dir = "/%s.%d" % (subdir, proc_pid)
            curr_dir += custom_dir
            if not os.path.isdir(curr_dir):
                os.mkdir(curr_dir)
            else:
                # TODO: Cleanup ??
                pass
            self.TmpDirToDel = curr_dir
        else:
            self.TmpDirToDel = None

        if prefix is None or suffix is None:
            self.Name = None
            return

        self.Name = "%s/%s.%d.%s" % (curr_dir, prefix, proc_pid, suffix)
        DEBUG("tmp=%s", self.Name )

    def DbgDelFil(self, fil_nam):
        if True:
            DEBUG("Deleting=%s", fil_nam)
            os.remove(fil_nam)
        else:
            WARNING("NOT Deleting=%s", fil_nam)

    def __del__(self):
        try:
            if self.Name:
                self.DbgDelFil(self.Name)

            # Extra check, not to remove everything.
            if self.TmpDirToDel not in [None,"/",""]:
                DEBUG("About to del %s", self.TmpDirToDel )
                for root, dirs, files in os.walk(self.TmpDirToDel, topdown=False):
                    for name in files:
                        self.DbgDelFil(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                        pass

        except Exception:
            exc = sys.exc_info()[1]
            ERROR("__del__.Caught: %s. TmpDirToDel=%s Name=%s", str(exc), str(self.TmpDirToDel), str(self.Name))
        return


################################################################################

# This is deprecated and was used to reduce the number fo displayed filed,
# by hiding the ones which are not really interesting.
def _is_shared_library(path):

    if lib_util.isPlatformWindows:
        tmp, fileExt = os.path.splitext(path)
        return fileExt.upper() in [ ".DLL" ]

    if lib_util.isPlatformLinux:
        # We could also check if this is really a shared library.
        # file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
        if path.endswith(".so"):
            return True

        # Not sure about "M" and "I". Also: Should precompile regexes.
        for rgx in [ r'/lib/.*\.so\..*', r'/usr/lib/.*\.so\..*' ] :
            if re.match( rgx, path, re.M|re.I):
                return True

        for start in [ '/usr/share/locale/', '/usr/share/fonts/', '/etc/locale/', '/var/cache/fontconfig/', '/usr/lib/jvm/' ] :
            if path.startswith( start ):
                return True

    return False

# A file containing fonts and other stuff not usefull to understand how a process works.
# So by default they are ot displayed. This should be deprecated.
def _is_fonts_file(path):

    if lib_util.isPlatformWindows:
        tmp, fileExt = os.path.splitext(path)
        # sys.stderr.write("_is_fonts_file fileExt=%s\n" % fileExt)
        return fileExt in [ ".ttf", ".ttc" ]

    elif lib_util.isPlatformLinux:
        for start in [ '/usr/share/locale/', '/usr/share/fonts/', '/etc/locale/', '/var/cache/fontconfig/', '/usr/lib/jvm/' ] :
            if path.startswith( start ):
                return True

    return False

# Used when displaying all files open by a process: There are many of them,
# so the irrelevant files are hidden. This should be an option.
def is_meaningless_file(path, removeSharedLibs, removeFontsFile):
    if removeSharedLibs:
        if _is_shared_library(path):
            return True

    if removeFontsFile:
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

