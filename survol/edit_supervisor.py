#!/usr/bin/env python

import os
import sys
import lib_export_html
import lib_common
import lib_util
import lib_kbase
import lib_naming

from lib_util import WrtAsUtf

from scripts import daemon_factory
import lib_daemon

"""
Display Survol events generators processes and their supervisor.
"""


def _get_daemons_data():
    """
    This returns in a dictionary, the list of deamons.
    These daemons can then be displayed in plain HTML or in a Jinja2 template.
    Some control is also provided by the interface of supervisord library, so its link is displayed.
    Some CGI scripts can run in two modes: "web" mode (CGI or WSGI), as usual, but also in daemon mode:
    their daemon process runs endlessly and instead of returning their events to the caller of the CGI script,
    these events are inserted into a RDF triplestore.
    This RDF triplestore is defined as an URL in the credentials: Any type of triplestore
    is allowed as long as it is supported by rdflib persistence API,
    see details here: https://rdflib.readthedocs.io/en/stable/persistence.html .
    Then, when the script is later run in "normal", CGI mode, the events are returned from this triplestore database.
    This allows to accumulate a complete history of events stored as RDF triples.
    
    Each of these daemons is associated with a CGI script and also an object, defined with its class and the values 
    of the attributes listes in the ontology of the class.
    Of course, if this is a top-level script not associated with a class, there are no arguments.
    """

    urls_daemons_dict = lib_daemon.get_running_daemons()
    for daemon_url, daemon_object in urls_daemons_dict.items():
        #entity_type, entity_id, entity_host = lib_util.split_url_to_entity(daemon_url)
        sys.stderr.write("daemon_url=%s\n" % daemon_url)

        url_label, entity_type, entity_id = lib_naming.ParseEntityUri(daemon_url, long_display=True)
        sys.stderr.write("url_label=%s\n" % url_label)
        sys.stderr.write("entity_type=%s\n" % entity_type)
        sys.stderr.write("entity_id=%s\n" % entity_id)

        daemon_object['url_title'] = url_label
        daemon_object['object_url'] = lib_util.EntityUri(entity_type, entity_id)
        entity_label = lib_naming.EntityToLabel(entity_type, entity_id, lib_util.HostName())
        sys.stderr.write("entity_label=%s\n" % entity_label)
        daemon_object['object_title'] = entity_label
        daemon_object['triples_number'] = lib_kbase.context_events_count(daemon_url)

    return urls_daemons_dict


def MainNoJinja(url_supervisor_control, urls_daemons_dict):
    lib_util.WrtHeader('text/html')
    lib_export_html.display_html_text_header("Events generators")

    WrtAsUtf("""
    <body><h2>Display events generators</h2>
    """)

    if url_supervisor_control:
        WrtAsUtf("""
        <a href="%s">Supervisor Control</a>
        """ % url_supervisor_control)

    WrtAsUtf("""
    <br><br>
    
    <table border="1">
    <tr><td>Daemon url</td><td>Object url</td><td>Triples number</td><td>Pid</td></tr>
    """)

    for daemon_url, daemon_object in urls_daemons_dict.items():
        WrtAsUtf("""
        <tr><td><a href="%s">%s</a></td><td><a href="%s">%s</a></td><td>%d</td><td>%d</td></tr>
        """ % (
            daemon_url,
            daemon_object['url_title'],
            daemon_object['object_url'],
            daemon_object['object_title'],
            daemon_object['triples_number'],
            daemon_object['pid']
            ))

    WrtAsUtf("""
    </table>
    <br><br>
    """)

    html_footer = "".join(lib_export_html.display_html_text_footer())
    WrtAsUtf(html_footer)

    WrtAsUtf("</body></html>")

    # TODO: Upload bookmarks file.

def MainJinja(url_supervisor_control, urls_daemons_dict):
    MainNoJinja(url_supervisor_control, urls_daemons_dict)
    return
    lib_common.ErrorMessageHtml("Not implemented yet")

    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    template_file_name = "www/edit_supervisor.template.htm"

    jinja2 = lib_util.GetJinja2()

    # Create the jinja2 environment.
    # Notice the use of trim_blocks, which greatly helps control whitespace.
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(THIS_DIR), trim_blocks=True)
    jinja_template = jinja_env.get_template(template_file_name)

    jinja_render = jinja_template.render(   )
    lib_util.WrtHeader('text/html')
    WrtAsUtf(jinja_render)

def Main():
    lib_common.set_events_credentials()
    url_supervisor_control = daemon_factory.supervisorctl_url()
    urls_daemons_dict = _get_daemons_data()
    if lib_util.GetJinja2():
        MainJinja(url_supervisor_control, urls_daemons_dict)
    else:
        MainNoJinja(url_supervisor_control, urls_daemons_dict)


if __name__ == '__main__':
    Main()
