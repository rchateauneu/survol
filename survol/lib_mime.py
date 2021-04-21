import os
import sys
import lib_util
import lib_uris
from lib_properties import pc

try:
    import mimetypes
    mimelib_present = True
except ImportError:
    mimelib_present = False


def filename_to_mime(path_name):
    """
    This returns the MIME type of a file
    """

    # Avoid access to the credentials file, just in case. Ideally the file should not be visible.
    if path_name.upper().find("CREDENTIALS") >= 0:
        return [None, None]

    # On Linux, we can read text files in /proc filesystem.
    if path_name.startswith("/proc/"):
        return ['text/plain', None]

    # Some types might not be well processed.
    file_name, file_ext = os.path.splitext(path_name)
    ext_upper = file_ext.upper()

    if ext_upper in [".LOG", ".JSON"]:
        return ['text/plain', None]

    if mimelib_present:
        # For example: ('text/plain', None)
        return mimetypes.guess_type(path_name)
    else:
        # Last chance if module is not available.
        # TODO: This can easily be completed.
        if ext_upper in [".JPG", ".JPEG"]:
            return ['image/jpeg', None]
        if ext_upper in [".TXT"]:
            return ['image/jpeg', None]

    return [None, None]


# This encodes the Mime type in the mode associated to an Url.
# The CGI "mode" parameter can be for example:
# "svg"                 Must be displayed in SVG after conversion to DOT.
# "rdf"                 Displayed as an RDF document.
# "html"                Displayed into HTML.
# "json"                Into JSON, read by a D3 Javascript library.
# "menu"                Generates a hierarchical menu for Javascript.
# "edit"                Edition of the other CGI parametgers.
# "mime:text/plain"     Displayed as a Mime document.
# "mime:image:bmp"      Same ...
_mime_mode_prefix = "mime:"


def AddMimeUrl(grph, fil_node, entity_type, mime_type, entity_id_arr):
    mime_node = lib_uris.gUriGen.UriMakeFromScript('/entity_mime.py', entity_type, *entity_id_arr)

    # So that the MIME type is known without loading the URLs.
    # Also, it allows to force a specific MIME type.
    # The MIME type is not coded in the property because it is an attribute of the object.
    mime_node_with_mode = mime_node + "&amp;amp;" + "mode=" + _mime_mode_prefix + mime_type

    grph.add((fil_node, pc.property_rdf_data_nolist2, lib_util.NodeUrl(mime_node_with_mode)))


def mode_to_mime_type(url_mode):
    """This extracts the MIME type from a mode CGI parameter:
    If the CGI parameter is for example: "...&mode=
    This truncates the beginning of the tsring after "mime:", hence the length of five chars.
    It sounds hard-coded byt in fact very stable and perfectly matches the need.
    """
    return url_mode[5:]


def get_mime_type_from_url(url):
    """
    This deduces the mime type of the document returned by an URL.
    This is intended for Survol urls only.
    """
    url_mode = lib_util.get_url_mode(url)
    if url_mode and url_mode.startswith(_mime_mode_prefix):
        return mode_to_mime_type(url_mode)
    else:
        return ""

