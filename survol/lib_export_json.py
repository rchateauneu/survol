import lib_kbase
import lib_patterns
import lib_naming
import lib_util
from lib_properties import pc
import sys
import six
import os
import json
import logging
import lib_exports

_node_json_number = 0


class NodeJson:
    """This models a node as it will be saved to Json."""

    # TODO: This creates a useless layer of lookup that could be suppressed.
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
        self.m_survol_universal_alias = lib_exports.NodeToUniversalAlias(rdf_node)

        _node_json_number += 1 # One more node.


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
def _write_json_header(buf_json, with_content_length=False):
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
    lib_util.WrtAsUtf(buf_json)


def WriteJsonError(message):
    """This is called only by ErrorMessageHtml when an error is detected and the output format is JSON.
    After that, the calling function makes an exit.
    The error message is formatted in the standard for returning errors.
    http://labs.omniti.com/labs/jsend
    """
    logging.warning("WriteJsonError message="+message)
    json_err = {}
    json_err["status"] = "error"
    json_err["message"] = message

    # The only case where Content-Length is added.
    _write_json_header(json.dumps(json_err, indent=2), True)


def Grph2Json(page_title, error_msg, parameters, grph):
    """
    Transforms a RDF graph into a JSON document.

    This returns a graph made of Json objects which are suitable for visualisation in D3.
    """

    # Must be reset to zero between several executions, when run by WSGI.
    global _node_json_number
    _node_json_number = 0

    # It contains a cache because the same nodes may appear several times.
    def node_to_json_obj(the_nod):
        try:
            return node_to_json_obj.dictNod2Json[the_nod]
        except KeyError:
            json_obj = NodeJson(the_nod)
            node_to_json_obj.dictNod2Json[the_nod] = json_obj
            return json_obj

    node_to_json_obj.dictNod2Json = dict()

    links = []
    for subj, pred, obj in grph:
        # This applies only to entity.py : In rendering based on Json, scripts are not displayed as nodes,
        # but in hierarchical menus. The node must not appear at all.

        # TODO: Should probably also eliminate pc.property_rdf_data_nolist2 etc ... See lib_client.
        if pred == pc.property_script:
            logging.debug("continue subj=%s obj=%s",subj,obj)
            continue

        # Normal data scripts are not accepted. This should apply only to file_directory.py and file_to_mime.py
        if not _script_for_json(subj):
            continue

        if not _script_for_json(obj):
            continue

        subj_obj = node_to_json_obj(subj)
        subj_id = subj_obj.m_survol_url

        prop_nam = lib_exports.PropToShortPropNam(pred)

        # TODO: BUG: If several nodes for the same properties, only the last one is kept.
        if lib_kbase.IsLink(obj):
            obj_obj = node_to_json_obj(obj)
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
            raise Exception(__file__ + " Cannot happen here")

    # Now, this creates the nodes sent as json objects.
    num_nodes = len(node_to_json_obj.dictNod2Json)
    # sys.stderr.write("Grph2Json num_nodes=%d\n"%num_nodes)
    nodes = [None] * num_nodes
    for nod in node_to_json_obj.dictNod2Json:
        nod_obj = node_to_json_obj.dictNod2Json[nod]
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

    _write_json_header(json.dumps(graph, indent=2))
    # print(json.dumps(graph, indent=2))


def Grph2Menu(page_title, error_msg, parameters, grph):
    """This returns a tree of scripts, usable as a contextual menu.
    The RDF content is already created, so this keeps only the nodes related to scripts.
    TODO: It would be faster to keep only the tree of scripts. The script "entity.py"
    should have a different output when mode=json.
    It does not return a network but a tree to be displayed in a contextual menu.
    It has a completely different layout as a normal RDF transformed into JSON,
    so probably the URL should be different as well.
    Input example: "http://127.0.0.1:8000/survol/entity.py?xid=CIM_Process.Handle=3812&mode=json"
    """

    # TODO: Should add WBEM and WMI ?

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

    _write_json_header(json.dumps(one_menu_val, sort_keys=True, indent=2))
    # print(json.dumps(one_menu_val, sort_keys = True, indent=2))

