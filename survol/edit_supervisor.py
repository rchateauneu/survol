#!/usr/bin/env python

import os
import sys
import datetime
import logging

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
        logging.debug("daemon_url=%s" % daemon_url)

        url_label, entity_type, entity_id = lib_naming.ParseEntityUri(daemon_url, long_display=True)
        logging.debug("url_label=%s" % url_label)
        logging.debug("entity_type=%s" % entity_type)
        logging.debug("entity_id=%s" % entity_id)

        daemon_object['url_title'] = url_label

        # Now that we have the class and the key-value pairs of the object related to the script, builds its url.
        # TODO: Simplify this, because it splits the id path to join it afterwards.
        # It might help to reorder properly the key-value pairs.
        entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)
        entity_url = lib_util.EntityUri(entity_type, *entity_ids_arr)
        logging.debug("entity_url=%s" % entity_url)
        daemon_object['object_url'] = entity_url
        entity_label = lib_naming.EntityToLabel(entity_type, entity_id, lib_util.HostName())
        logging.debug("entity_label=%s" % entity_label)
        daemon_object['object_title'] = entity_label
        daemon_object['triples_number'] = lib_kbase.context_events_count(daemon_url)
        daemon_object['start_time'] = datetime.datetime.fromtimestamp(daemon_object['start']).strftime("%m/%d/%Y, %H:%M:%S")

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
    
    <table border="1" width="100%">
    <tr><td>Daemon url</td><td>Object url</td><td>Triples number</td><td>Start time</td><td>State</td><td>Pid</td></tr>
    """)

    for daemon_url, daemon_object in urls_daemons_dict.items():
        WrtAsUtf("""
        <tr><td><a href="%s">%s</a></td><td><a href="%s">%s</a></td><td>%d</td><td>%s</td><td>%s</td><td>%d</td></tr>
        """ % (
            daemon_url,
            daemon_object['url_title'],
            daemon_object['object_url'],
            daemon_object['object_title'],
            daemon_object['triples_number'],
            daemon_object['start_time'],
            daemon_object['statename'],
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
    logging.info("url_supervisor_control=%s" % url_supervisor_control)
    try:
        urls_daemons_dict = _get_daemons_data()
    except Exception as exc:
        logging.error("Caught exc=%s" % exc)
        lib_common.ErrorMessageHtml("Supervisor %s display: Caught:%s" % (url_supervisor_control, exc))
    if lib_util.GetJinja2():
        MainJinja(url_supervisor_control, urls_daemons_dict)
    else:
        MainNoJinja(url_supervisor_control, urls_daemons_dict)


if __name__ == '__main__':
    Main()
