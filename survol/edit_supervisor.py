#!/usr/bin/env python

import os
import sys
import lib_export_html
import lib_common
import lib_util

from lib_util import WrtAsUtf

from scripts import daemon_factory


"""
Display Survol events generators processes and their supervisor.
"""


def MainNoJinja(url_supervisor_control):
    lib_util.WrtHeader('text/html')
    lib_export_html.display_html_text_header("Events generators")

    WrtAsUtf("""
    <body><h2>Display events generators</h2>
    """)

    if url_supervisor_control:
        WrtAsUtf("""
        <a href="%s">Supervisor Control</a>
        """ % url_supervisor_control)

    htmlFooter = "".join(lib_export_html.display_html_text_footer())
    WrtAsUtf(htmlFooter)

    WrtAsUtf("</body></html>")

    # TODO: Upload bookmarks file.

def MainJinja(url_supervisor_control):
    MainNoJinja(url_supervisor_control)
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
    url_supervisor_control = daemon_factory.supervisorctl_url()
    if lib_util.GetJinja2():
        MainJinja(url_supervisor_control)
    else:
        MainNoJinja(url_supervisor_control)


if __name__ == '__main__':
    Main()
