# This library helps to generate the output of internal database (RDF-like)
# to the DOT output format, transformed into SVG by Graphviz.

import lib_naming
import lib_util
import lib_properties
import sys
import os


# "http://primhillcomputers.com/ontologies/smbshare" = > "smbshare"
# TODO: See also PropToShortPropNam()
def AntiPredicateUri(uri):
    return uri[len(lib_properties.primns_slash):]


def ModedUrl(other_mode):
    return lib_util.request_uri_with_mode(other_mode)


################################################################################

_dict_node_to_universal_alias = {}


def NodeToUniversalAlias(an_object):

    def make_universal_alias_no_cache(an_object):
        # The prefix of the URL which contain the host name,
        # maybe with a port number, maybe with a WBEM prefix, WMI machine, CGI script etc...
        # is simply replaced by the IP address of the machine.
        # The resulting string is the same for all servers running on the same machine.
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
        short_nam = str_predicate[idx_last_slash + 1:]
    else:
        str_properties = str_predicate[idx_question + 1:]
        vec_properties = str_properties.split("&")
        dict_properties = dict(one_s.split('=', 1) for one_s in vec_properties)
        idx_last_slash = str_predicate.rfind(lib_properties.prefix_terminator, 0, idx_question)
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


################################################################################


_htbin_prefix_script = "/survol"


def UrlWWW(page_html):
    """Link to help page:
    http://www.primhillcomputers.com/ui/help.htm
    http://rchateau-hp:8000/survol/www/help.htm
    http://127.0.0.1/Survol/survol/www/help.htm
    http://primhillcomputers.ddns.net/Survol/survol/www/help.htm
    """
    calling_url = ModedUrl("")
    #sys.stderr.write("UrlToMergeD3 calling_url=%s\n"%(calling_url))
    htbin_idx = calling_url.find(_htbin_prefix_script)

    # We needs the beginning of the URL.
    url_host = calling_url[:htbin_idx]
    #sys.stderr.write("UrlToMergeD3 url_host=%s\n"%(url_host))

    d3_url_dir = "/survol/www"

    script_d3_url = url_host + d3_url_dir + "/" + page_html
    #sys.stderr.write("UrlToMergeD3 script_d3_url=%s\n"%script_d3_url)
    return script_d3_url


def UrlToMergeD3():
    """This returns an URL to the Javascript D3 interface URL, which displays the current url in Javascript."""
    calling_url = ModedUrl("")
    #sys.stderr.write("UrlToMergeD3 calling_url=%s\n"%(calling_url))
    htbin_idx = calling_url.find(_htbin_prefix_script)
    url_without_host = calling_url[htbin_idx:]
    #sys.stderr.write("UrlToMergeD3 url_without_host=%s\n"%(url_without_host))

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

