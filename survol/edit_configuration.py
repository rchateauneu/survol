#!/usr/bin/python

"""
Edits Survol configuration parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import os
import sys
import lib_export_html
import lib_exports
import lib_util

from lib_util import WrtAsUtf



def MainNoJinja():
    lib_export_html.DisplayHtmlTextHeader("Configuration")

    WrtAsUtf("""
    <body><h2>Edit Survol configuration</h2>
    """)

    WrtAsUtf("""
    <form method="post" action="edit_configuration.py" name="ServerConfiguration">
    <table border="0">
    <tr>
    <td>CGI server port number:</td>
    <td>&nbsp;<input name="server_port" value="8000"></td>
    </tr>
    <tr>
    <td>Bookmarks file or URL:</td>
    <td>&nbsp;<input name="bookmark_url" value="bookmarks.htm"></td>
    </tr>
    <tr>
    <td>HTML Jinja2 templates:</td>
    <td><input type="checkbox" name="html_jinja2"></td>
    </tr>
    <tr>
    <td colspan="2"><input value="Submit configuration" name="Hello" type="submit"></td>
    </tr>
    </table>
    </form>
    """)

    lib_export_html.DisplayHtmlTextFooter()

    #WrtAsUtf('<br><a href="edit_credentials.py">Credentials</a>')
    #WrtAsUtf('<br><a href="edit_configuration.py">Configuration</a>')

    #urlIndex = lib_exports.UrlWWW("index.htm")
    #WrtAsUtf('<br><a href="' + urlIndex + '">Return to Survol</a>')

    WrtAsUtf("</body></html>")

    # TODO: Upload bookmarks file.

def MainJinja():
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    template_file_name = "www/edit_configuration.template.htm"

    jinja2 = lib_util.GetJinja2()

    # Create the jinja2 environment.
    # Notice the use of trim_blocks, which greatly helps control whitespace.
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(THIS_DIR), trim_blocks=True)
    jinja_template = jinja_env.get_template(template_file_name)

    jinja_render = jinja_template.render(   )
    lib_util.WrtHeader('text/html')
    WrtAsUtf( jinja_render )

def Main():
    if lib_util.GetJinja2():
        MainJinja()
    else:
        MainNoJinja()


if __name__ == '__main__':
    Main()
