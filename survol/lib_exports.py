# This library helps to generate the output of internal database (RDF-like)
# to the DOT output format, transformed into SVG by Graphviz.

import lib_kbase
import lib_patterns
import lib_naming
import lib_util
from lib_util import UrlToSvg
import lib_properties
from lib_properties import pc
import sys
import six
import time
import cgi
import re
import os
import json
import socket


# "http://primhillcomputers.com/ontologies/smbshare" = > "smbshare"
# TODO: See also PropToShortPropNam()
def AntiPredicateUri(uri):
    return uri[len(lib_properties.primns_slash):]

################################################################################


# Current URL but in edition mode.
# PROBLEM: SI PAS DE ENTITY_ID A EDITER CAR "TOP" ALORS ON REBOUCLE SUR Edit:
# DONC DETECTER LE TYPE DE L'ENTITE EN FOCNTION DU DIRECTORY ET AUCUN SI "TOP".
def ModedUrl(other_mode):
    return lib_util.request_uri_with_mode(other_mode)

################################################################################



# To display long strings in HTML-like labels, when Graphviz creates SVG.
_max_html_title_len_per_col = 40

# This is a HTML-like tag for Graphviz only.
_with_br_delim = '<BR ALIGN="LEFT" />'


def StrWithBr(a_raw_str, colspan = 1):
    """Inserts "<BR/>" in a string so it can be displayed in a HTML label.
    Beware that it is not really HTML, but only an HTML-like subset.
    See https://www.graphviz.org/doc/info/shapes.html#html """

    # First thing: Cleanup possible HTML tags, otherwise Graphviz stops.
    aStr = a_raw_str.replace("<", "&lt;").replace(">", "&gt;")

    len_str = len(aStr)
    max_html_title_len = colspan * _max_html_title_len_per_col
    if len_str < max_html_title_len:
        return aStr

    splt = aStr.split(" ")
    tot_len = 0
    resu = ""
    curr_line = ""
    for curr_str in splt:
        subLen = len(curr_str)
        if tot_len + subLen < max_html_title_len:
            curr_line += " " + curr_str
            tot_len += subLen
            continue
        if resu:
            resu += _with_br_delim
        resu += curr_line
        curr_line = curr_str
        tot_len = subLen

    if curr_line:
        if resu != "":
            resu += _with_br_delim
        resu += curr_line
    return resu

################################################################################


def DotBold(a_str):
    if not a_str: return ""
    return "<b>%s</b>" % a_str

def DotUL(a_str):
    if not a_str: return ""
    return "<u>%s</u>" % a_str

# Do not italicize empty string otherwise "Error: syntax error in line 1 ... <i></i> ..."
def DotIt(a_str):
    if not a_str: return ""
    return "<i>%s</i>" % a_str


################################################################################

_dict_node_to_universal_alias = {}


def NodeToUniversalAlias(an_object):

    def make_universal_alias_no_cache(an_object):
        # The prefix of the URL which contain the host name,
        # maybe with a port number, maybe with a WBEM prefix, WMI machine,
        # CGI script etc...
        # is simply replaced by the IP address of the machine.
        # The resulting string is the same for all servers
        # running on the same machine.
        parsed_url = lib_util.survol_urlparse(an_object)
        #sys.stderr.write("make_universal_alias_no_cache parsed_url=%s\n"%str(parsed_url))
        # netloc=u'desktop-ni99v8e:8000'
        entity_host = parsed_url.netloc.split(":")[0]
        #sys.stderr.write("make_universal_alias_no_cache entity_host=%s\n"%str(entity_host))

        # FIXME: This is very slow.
        if False:
            try:
                # Might throw: socket.gaierror: [Errno 11004] getaddrinfo failed with "entity_host=desktop-ni99v8e"
                entity_ip_addr = lib_util.GlobalGetHostByName(entity_host)
            except:
                entity_ip_addr = entity_host
        else:
            entity_ip_addr = entity_host

        # RFC4343: Hostname are case-insensitive.
        entity_ip_addr = entity_ip_addr.lower()

        # TODO: Many things are calculated several times.
        lab_text, subj_entity_graphic_class, entity_id = lib_naming.ParseEntityUri(
            an_object, long_display=True, force_entity_ip_addr=entity_ip_addr)

        # sys.stderr.write("make_universal_alias_no_cache anObject=%s lab_text=%s\n"%(str(anObject),lab_text))
        return lab_text

    try:
        return _dict_node_to_universal_alias[an_object]
    except KeyError:
        uni_alias = make_universal_alias_no_cache(an_object)
        _dict_node_to_universal_alias[an_object] = uni_alias
        return uni_alias

################################################################################

# def Graphic_shape():
#     return "egg"
#
# def Graphic_colorfill():
#     return "#CCCC33"
#
# def Graphic_colorbg():
#     return "#CCCC33"
#
# def Graphic_border():
#     return 0
#
# def Graphic_is_rounded():
#     return True

#        arrayGraphParams = TypeToGraphParams(type)

_node_json_number = 0

# This models a node as it will be saved to Json.
# TODO: This creates a useless layer of lookup that could be suppressed.
class NodeJson:
    def __init__(self,rdf_node):
        global _node_json_number
        subj_str = str(rdf_node)

        entity_label, entity_graphic_class, entity_id = lib_naming.ParseEntityUri(
            subj_str, long_display=False, force_entity_ip_addr=None)

        self.m_label = entity_label.strip()
        self.m_class = entity_graphic_class

        array_graph_params = lib_patterns.TypeToGraphParams(self.m_class)

        # "Graphic_shape","Graphic_colorfill","Graphic_colorbg","Graphic_border","Graphic_is_rounded"
        self.m_color = array_graph_params[1]

        # TODO: Display the doc in the module with FromModuleToDoc(importedMod,filDfltText):
        self.m_info_list = [entity_graphic_class]
        self.m_info_dict = dict()
        self.m_index = _node_json_number

        the_survol_url = lib_util.survol_unescape(rdf_node)
        self.m_survol_url = the_survol_url
        self.m_survol_universal_alias = NodeToUniversalAlias(rdf_node)

        _node_json_number += 1 # One more node.


# TODO: See also AntiPredicateUri
def PropToShortPropNamAndDict(node_predicate):
    """Transforms a RDF property URIRef into a plain alphanumeric string,
    which can be used as a DOT label or RDF property, or a label string.
    It also returns a dictionary of the key value pairs if any.
    Examples:
    nodePredicate=http://primhillcomputers.com/survol/script?property_description=Data_source
    nodePredicate=http://primhillcomputers.com/survol/user
    """
    str_predicate = str(node_predicate)
    idx_question = str_predicate.rfind("?")
    if idx_question == -1:
        dict_properties = None
        idx_last_slash = str_predicate.rfind(lib_properties.prefix_terminator)
        short_nam = str_predicate[idx_last_slash+1:]
    else:
        str_properties = str_predicate[idx_question+1:]
        vec_properties = str_properties.split("&")
        dict_properties = dict(one_s.split('=',1) for one_s in vec_properties)
        idx_last_slash = str_predicate.rfind(lib_properties.prefix_terminator,0,idx_question)
        short_nam = str_predicate[idx_last_slash+1:idx_question]

    # "sun.boot.class.path"
    # Graphviz just want letters.
    short_nam = short_nam.replace(".", "_")
    short_nam = short_nam.replace(" ", "_")

    # Some properties, such as "information", are sorted differently by adding a special not-displayed prefix.
    if short_nam.startswith(lib_properties.sortPrefix):
        short_nam = short_nam[len(lib_properties.sortPrefix):]
    assert short_nam != ""
    return short_nam, dict_properties


def PropToShortPropNam(node_predicate):
    return PropToShortPropNamAndDict(node_predicate)[0]


# Only some scripts and urls are exported to Json.
# The most frequent should come first.
# root=http://rchateau-HP:8000/survol
# url=http://rchateau-HP:8000/survol/class_type_all.py?xid=com.
# url=http://rchateau-HP:8000/survol/objtypes.py
# This must be a tuple because of startswith
_urls_for_json = (
    "/entity.py",
    "/entity_wmi.py",
    "/entity_wbem.py",
    "/entity_info_only.py",
    "/objtypes.py",
    "/class_type_all.py",
    "/class_wbem.py",
    "/class_wmi.py",
    # TODO: Maybe pass portal_wbem.py and portal_wmi.py ??
)

# This avoids creating a node form some URLs used for returning information. For example:
# http://rchateau-HP:8000/survol/entity_mime.py?xid=CIM_DataFile.Name=C://smh_installer.log&amp;amp;mode=mime:text/plain
# http://rchateau-HP:8000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name=C%3A%2F%2Fpkg
def _script_for_json(url):
    #sys.stderr.write("_script_for_json url=%s root=%s\n"%(url,lib_util.uriRoot))

    if url.startswith(lib_util.uriRoot):
        # Where the script starts from.
        idx_script = len(lib_util.uriRoot)
        # Other scripts are forbidden.
        return url.startswith(_urls_for_json, idx_script)
    # Foreign scripts are OK.
    return True


# What must be avoided: Cross-Origin Request Blocked:
# The Same Origin Policy disallows reading the remote resource at
# http://192.168.0.17/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.&mode=json.
# (Reason: CORS header 'Access-Control-Allow-Origin' missing)
#
# https://stackoverflow.com/questions/5027705/error-in-chrome-content-type-is-not-allowed-by-access-control-allow-headers
# The body of the reply is base-64 encoded.
def WriteJsonHeader(buf_json, with_content_length=False):
    arr_headers = [
        ('Access-Control-Allow-Origin','*'),
        ('Access-Control-Allow-Methods','POST,GET,OPTIONS'),
        ('Access-Control-Allow-Headers','Origin, X-Requested-With, Content-Type, Accept'),
    ]

    # It is difficult to calculate the length because the output is encoded
    # in Base64, which takes more room than JSon. And also, at least on Windows,
    # each line gets an extra character ("\n\r" ?).
    # So it is confusing.
    # The reason for adding the length is: When an error is detected, sometimes a second error
    # comes immediately after the one, even if the thread (or process ?) quits.
    #
    # Also, with Chrome and Android, sometimes it is not happy with the length,
    # even if we checked it. It works without the length, except if this is an error message.
    if with_content_length:
        num_lines = buf_json.count("\n")
        len_buf = len(buf_json) + num_lines

        arr_headers.append(('Content-Length', str(len_buf)))

    lib_util.WrtHeader('application/json', arr_headers)

    # No text conversion.
    # lib_util.outputHttp.write(bufJson)
    lib_util.WrtAsUtf(buf_json)


def WriteJsonError(message):
    """This is called only by ErrorMessageHtml when an error is detected and the output format is JSON.
    After that, the calling function makes an exit.
    The error message is formatted in the standard for returning errors.
    http://labs.omniti.com/labs/jsend
    """
    WARNING("WriteJsonError message="+message)
    json_err = {}
    json_err["status"] = "error"
    json_err["message"] = message

    # The only case where Content-Length is added.
    WriteJsonHeader(json.dumps(json_err, indent=2), True)

    # This closes manually the output, otherwise another thread is triggered
    # and writes another error message, with the header, on the same output.
    # And the client JSON parser does not like that:
    # lib_util.outputHttp.close()

    # "ValueError: I/O operation on closed file"
    #sys.exit(0)


# Transforms a RDF graph into a JSON document.
# This returns a graph made of Json objects.
def Grph2Json(page_title, error_msg, isSubServer, parameters, grph):

    # Must be reset to zero between several executions, when run by WSGI.
    global _node_json_number
    _node_json_number = 0

    # It contains a cache because the same nodes may appear several times.
    def NodeToJsonObj(the_nod):
        try:
            return NodeToJsonObj.dictNod2Json[the_nod]
        except KeyError:
            json_obj = NodeJson(the_nod)
            NodeToJsonObj.dictNod2Json[the_nod] = json_obj
            return json_obj

    NodeToJsonObj.dictNod2Json = dict()

    links = []
    for subj, pred, obj in grph:
        # This applies only to entity.py : In rendering based on Json, scripts are not displayed as nodes,
        # but in hierarchical menus. The node must not appear at all.

        # TODO: Should probably also eliminate pc.property_rdf_data_nolist2 etc ... See lib_client.
        if pred == pc.property_script:
            DEBUG("continue subj=%s obj=%s",subj,obj)
            continue

        # Normal data scripts are not accepted. This should apply only to file_directory.py and file_to_mime.py
        if not _script_for_json(subj):
            continue

        if not _script_for_json(obj):
            continue

        subj_obj = NodeToJsonObj(subj)
        subj_id = subj_obj.m_survol_url

        prop_nam = PropToShortPropNam(pred)

        # TODO: BUG: If several nodes for the same properties, only the last one is kept.
        if lib_kbase.IsLink(obj):
            obj_obj = NodeToJsonObj(obj)
            obj_id = obj_obj.m_survol_url
            links.extend([{'source': subj_id, 'target': obj_id, 'survol_link_prop': prop_nam}])

            # TODO: Add the name corresponding to the URL, in m_info_dict so that some elements
            # of the tooltip would be clickable. On the other hand, one just need to merge
            # the nodes relative to the object, by right-clicking.
        elif lib_kbase.IsLiteral(obj):
            if pred == pc.property_information:
                try:
                    subj_obj.m_info_list.append(str(obj.value))
                except UnicodeEncodeError:
                    # 'ascii' codec can't encode character u'\xf3' in position 17: ordinal not in range(128)
                    # https://stackoverflow.com/questions/9942594/unicodeencodeerror-ascii-codec-cant-encode-character-u-xa0-in-position-20
                    subj_obj.m_info_list.append(obj.value.encode('utf-8'))
            else:
                if isinstance(obj.value, six.integer_types) or isinstance(obj.value, six.string_types):
                    subj_obj.m_info_dict[prop_nam] = obj.value
                else:
                    # If the value cannot be serializable to JSON.
                    subj_obj.m_info_dict[prop_nam] = type(obj.value).__name__
        else:
            raise "Cannot happen here"

    # Now, this creates the nodes sent as json objects.
    num_nodes = len(NodeToJsonObj.dictNod2Json)
    # sys.stderr.write("Grph2Json num_nodes=%d\n"%num_nodes)
    nodes = [None] * num_nodes
    for nod in NodeToJsonObj.dictNod2Json:
        nod_obj = NodeToJsonObj.dictNod2Json[nod]
        nod_titl = nod_obj.m_label
        nod_id = nod_obj.m_index

        # The URL must not contain any HTML entities when in a XML or SVG document,
        # and therefore must be escaped. Therefore they have to be unescaped when transmitted in JSON.
        # This is especially needed for RabbitMQ because the parameter defining its connection name
        # has the form: "Url=LOCALHOST:12345,Connection=127.0.0.1:51748 -> 127.0.0.1:5672"

        # HTTP_MIME_URL
        the_survol_nam = lib_util.survol_unescape(nod_titl) # MUST UNESCAPE HTML ENTITIES !

        # TODO: Use the same object for lookup and Json.
        nodes[nod_id] = {
            'id'                     : nod_obj.m_survol_url, # Required by D3
            'name'                   : the_survol_nam,
            # Theoretically, this URL should be HTML unescaped then CGI escaped.
            'survol_url'             : nod_obj.m_survol_url, # Duplicate of 'id'
            'survol_universal_alias' : nod_obj.m_survol_universal_alias,
            'survol_fill'            : nod_obj.m_color,
            'entity_class'           : nod_obj.m_class, # TODO: Maybe not needed because also in the URL ?
            'survol_info_list'       : nod_obj.m_info_list,
            'survol_info_dict'       : nod_obj.m_info_dict
        }

    graph = {}
    graph["page_title"] = page_title
    graph["nodes"] = nodes
    graph["links"] = links

    WriteJsonHeader(json.dumps(graph, indent=2))
    # print(json.dumps(graph, indent=2))

# This returns a tree of scripts, usable as a contextual menu.
# The RDF content is already created, so this keeps only the nodes related to scripts.
# TODO: It would be faster to keep only the tree of scripts. The script "entity.py"
# should have a different output when mode=json.
# It does not return a network but a tree to be displayed in a contextual menu.
# It has a completely different layout as a normal RDF transformed into JSON,
# so probably the URL should be different as well.
# Input example: "http://127.0.0.1:8000/survol/entity.py?xid=CIM_Process.Handle=3812&mode=json"

# TODO: Should add WBEM and WMI ?

def Grph2Menu(page_title, error_msg, isSubServer, parameters, grph):
    # For each node, the subscripts. Therefore it can only be a directory.
    nodes_to_items = {}

    # Nodes of scripts which have a parent.
    nodes_with_parent = set()

    # Later used to calculate the list of scripts which do not have a parent
    # directory: They will be displayed at the top of the contextual menu.
    subject_nodes = set()

    # The name of each node.
    nodes_to_names = dict()

    for subj, pred, obj in grph:
        if pred == pc.property_script:
            #sys.stderr.write("subj=%s\n"%str(subj))
            #sys.stderr.write("obj=%s\n"%str(obj))
            try:
                nodes_to_items[subj].append(obj)
            except KeyError:
                nodes_to_items[subj] = [obj]

            if lib_kbase.IsLiteral(obj):
                # This is the name of a subdirectory containing scripts.
                # sys.stderr.write("obj LITERAL=%s\n"%str(subj))
                nodes_to_names[obj] = obj

            nodes_with_parent.add(obj)
            subject_nodes.add(subj)
        elif pred == pc.property_information:
            if lib_kbase.IsLiteral(obj):
                #sys.stderr.write("subj=%s\n"%str(subj))
                #sys.stderr.write("obj.value=%s\n"%obj.value)
                nodes_to_names[subj] = obj.value
            else:
                raise Exception("Cannot happen here also")
        else:
            pass

    top_level_nodes = subject_nodes - nodes_with_parent

    # The output result must be sorted.
    def add_stuff(the_nod_list, depth=0):
        list_json_items = {}

        for one_rdf_nod in the_nod_list:
            #sys.stderr.write("one_rdf_nod=%s\n"%one_rdf_nod)
            one_json_nod = {}
            # This should be the sort key.
            one_json_nod["name"] = nodes_to_names.get(one_rdf_nod, "No name")
            # sys.stderr.write( (" " * depth) + "name=%s\n" % (one_json_nod["name"]) )
            one_json_nod["url"] = one_rdf_nod

            # Maybe it does not have subitems.
            try:
                lst_item = nodes_to_items[one_rdf_nod]
                one_json_nod["items"] = add_stuff(lst_item, depth+1)
            except KeyError:
                pass

            list_json_items[one_rdf_nod] = one_json_nod
        return list_json_items

    menu_json = add_stuff(top_level_nodes)

    # sys.stderr.write("menu_json=%s\n"%str(menu_json))

    # There is only one top-level element.
    one_menu_val = {}
    for one_menu_key in menu_json:
        one_menu_val = menu_json[one_menu_key]["items"]
        break

    #sys.stderr.write("menu_json=%s\n"%str(one_menu_val))

    WriteJsonHeader(json.dumps(one_menu_val, sort_keys=True, indent=2))
    # print(json.dumps(one_menu_val, sort_keys = True, indent=2))

################################################################################


def FontString():
    # fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
    # stream.write("node [shape=plaintext fontpath=\"/usr/share/fonts\" fontname=\"DejaVuSans\" ]")

    if lib_util.isPlatformWindows:
        return 'fontname="DejaVu Sans"'
    else:
        # fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
        return 'fontpath="/usr/share/fonts" fontname="DejaVuSans"'


_htbin_prefix_script = "/survol"


# Link to help page:
# http://www.primhillcomputers.com/ui/help.htm
# http://rchateau-hp:8000/survol/www/help.htm
# http://127.0.0.1/Survol/survol/www/help.htm
# http://primhillcomputers.ddns.net/Survol/survol/www/help.htm
def UrlWWW(pageHtml):
    calling_url = ModedUrl("")
    #sys.stderr.write("UrlToMergeD3 calling_url=%s\n"%(calling_url))
    htbin_idx = calling_url.find(_htbin_prefix_script)

    # We needs the beginning of the URL.
    url_host = calling_url[:htbin_idx]
    #sys.stderr.write("UrlToMergeD3 url_host=%s\n"%(url_host))

    d3_url_dir = "/survol/www"

    script_d3_url = url_host + d3_url_dir + "/" + pageHtml
    #sys.stderr.write("UrlToMergeD3 script_d3_url=%s\n"%script_d3_url)
    return script_d3_url

# This logic should go to lib_client.py


# This returns an URL to the Javascript D3 interface, editing the current data.
def UrlToMergeD3():
    calling_url = ModedUrl("")
    #sys.stderr.write("UrlToMergeD3 calling_url=%s\n"%(calling_url))
    htbin_idx = calling_url.find(_htbin_prefix_script)
    url_without_host = calling_url[htbin_idx:]
    #sys.stderr.write("UrlToMergeD3 url_without_host=%s\n"%(url_without_host))

    # Consider lib_client.py

    # Maybe this URL is already a merge of B64-encoded URLs:
    htbin_prefix_merge_script = "/survol/merge_scripts.py"
    if url_without_host.startswith(htbin_prefix_merge_script):
        # If so, no need to re-encode.
        url_without_host_b64 = url_without_host[len(htbin_prefix_merge_script):]
    else:
        # This works on Windows with cgiserver.py just because the full script starts with "/survol"
        # url_without_host_b64 = "?url=" + lib_util.Base64Encode(url_without_host)
        # Complete URL with the host. This is necessary because index.htm has no idea
        # of where the useful part of the URL starts.
        # This works on Linux with Apache.
        url_without_host_b64 = "?url=" + lib_util.Base64Encode(calling_url)
    #sys.stderr.write("UrlToMergeD3 url_without_host_b64=%s\n"%url_without_host_b64)

    script_d3_url = UrlWWW("index.htm") + url_without_host_b64
    #sys.stderr.write("UrlToMergeD3 script_d3_url=%s\n"%script_d3_url)
    return script_d3_url


# In SVG/Graphiz documents, this writes the little rectangle which contains various information.
def WriteDotLegend(page_title, topUrl, errMsg, is_sub_server, parameters, parameterized_links, stream, grph):

    # This allows to enter directly the URL parameters, so we can access directly an object.
    # This will allow to choose the entity type, and each parameter of the URL (Taken
    # from the ontology). It also edits the parameters of the current URL.
    # TODO: MUST FINISH THIS.
    #def UrlDirectAccess():
    #    return "direct_access.py"

    # This adds links which can display the same content in a different output format.
    def legend_add_alternate_display_links(stream):
        # So we can change parameters of this CGI script.
        url_html = ModedUrl("html")
        url_json = ModedUrl("json")
        url_rdf = ModedUrl("rdf")
        urlD3 = UrlToMergeD3()

        # Stupid replacement of dot: "\\" transformed into "\"
        # Fix for : "http://rchateau-hp:8000/survol/class_wmi.py?xid=\\machine\root\CIMV2%3ACIM_Directory.&mode=html"
        def UrlForDot(mdUrl):
            mdUrl = mdUrl.replace("\\\\", "\\\\\\")
            return UrlToSvg(mdUrl)

        stream.write("<tr><td colspan='4'><table border='0'>")
        stream.write(
            "<tr>"
            "<td>(</td>"
            "<td align='left' href='" + UrlForDot( url_html ) + "'>" + DotUL("HTML") + "</td>"
            "<td>,</td>"
            "<td align='left' href='" + UrlForDot( url_json ) + "'>" + DotUL("JSON") + "</td>"
            "<td>,</td>"
            "<td align='left' href='" + UrlForDot( url_rdf ) + "'>" + DotUL("RDF") + "</td>"
            "<td>,</td>"
            "<td align='left' href='" + UrlForDot( urlD3 ) + "'>" + DotUL("D3") + "</td>"
            "<td>)</td></tr>"
        )
        stream.write("</table></td></tr>")

    def legend_add_parameters_links(stream, parameters, parameterized_links):
        """This displays the parameters of the URL and a link allowing to edit them.
        It assumes that it writes in the middle of a table with two columns."""

        if parameters :
            url_edit = ModedUrl("edit")
            url_edit_replaced = UrlToSvg(url_edit)
            stream.write("<tr><td colspan='4' href='" + url_edit_replaced + "' align='left'>"
                         + DotBold(DotUL( "Edit script parameters" )) + "</td></tr>" )

            arguments = cgi.FieldStorage()
            for key_param, val_param in parameters.items():
                try:
                    actual_param = arguments[key_param].value
                except KeyError:
                    actual_param = val_param
                stream.write('<tr><td colspan="2">%s:</td><td colspan="2">%s</td></tr>' % (key_param, DotIt(actual_param)))

        # We want to display links associated to the parameters.
        # The use case is "Prev/Next" when paging between many values.
        # This could be nicely modelled by just specifying special set of values,
        # and the links would be calculated here.
        # For example: { "next" : { "index": curr + 80 }, "prev" : { "index": curr - 80 } }
        # This simplifies the edition in Json.
        # It might also simplify formatting.
        # There will be a similar piece of code in Javascript and plain HTML:
        # (1) The calling script provides the values to CgiEnv.
        # (2) A method in CgiEnv calculates the URLS and returns a map
        # of { "label":"urls" }

        for url_label in parameterized_links:
            param_url = parameterized_links[url_label]
            stream.write("<tr><td colspan='4' href='" + param_url + "' align='left'>"
                         + DotBold(DotUL(url_label)) + "</td></tr>")

    def legend_footer():

        url_help = UrlToSvg(UrlWWW("help.htm"))

        stream.write("<tr>")
        stream.write('<td align="left" href="' + topUrl + '">' + DotBold(DotUL("Home")) + '</td>')
        urlEdtConfiguration = lib_util.uriRoot + "/edit_configuration.py"
        stream.write("<td href='" + urlEdtConfiguration + "' align='left'>" + DotBold(DotUL("Setup")) + "</td>")
        urlEdtCredentials = lib_util.uriRoot + "/edit_credentials.py"
        stream.write("<td href='" + urlEdtCredentials+"' align='left'>" + DotBold(DotUL("Credentials")) + "</td>")
        stream.write("<td href='" + url_help+"' align='left'>" + DotBold(DotUL("Help")) + "</td>")
        stream.write("</tr>")


    # stream.write("node [shape=plaintext fontname=\"DejaVu Sans\" ]")
    # fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
    # stream.write("node [shape=plaintext fontpath=\"/usr/share/fonts\" fontname=\"DejaVuSans\" ]")
    stream.write("node [shape=plaintext %s ]" % FontString())

    # The first line is a title, the rest, more explanations.
    # The first line also must be wrapped if it is too long.
    # TODO: This logic should be factorised because it seems to be used when merging ?

    page_title_first, page_title_rest = lib_util.SplitTextTitleRest(page_title)

    page_title_first_wrapped = StrWithBr(page_title_first, 2)
    page_title_rest_wrapped = StrWithBr(page_title_rest, 2)
    page_title_full = DotBold(page_title_first_wrapped) + _with_br_delim + page_title_rest_wrapped

    stream.write("""
  subgraph cluster_01 {
    subgraph_cluster_key [shape=none, label=<<table border="1" cellpadding="0" cellspacing="0" cellborder="0">""")

    stream.write("<tr><td colspan='4'>" + page_title_full + "</td></tr>" )
    legend_add_alternate_display_links(stream)
    legend_add_parameters_links(stream,parameters,parameterized_links)

    legend_footer()

    # The error message could be None or an empty string.
    if errMsg:
        fullErrMsg = DotBold("Error: ") + errMsg
        stream.write('<tr><td align="left"  balign="left" colspan="2">%s</td></tr>' % StrWithBr(fullErrMsg, 2))

    if is_sub_server:
        url_stop = ModedUrl("stop")
        url_stop_replaced = UrlToSvg(url_stop)
        stream.write('<tr><td colspan="2" href="' + url_stop_replaced + '">' + DotUL("Stop subserver") + '</td></tr>' )
        # TODO: Add an URL for subservers management, instead of simply "stop"
        # Maybe "mode=ctrl".This will list the feeders with their entity_id.
        # So they can be selectively stopped.

    stream.write("""
      </table>>]
  }
     """)

