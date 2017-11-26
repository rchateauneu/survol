#!/usr/bin/python

"""
Edits Survol configuration parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import sys
import lib_export_html
import lib_exports

from lib_util import WrtAsUtf

def Main():
    lib_export_html.DisplayHtmlTextHeader("Configuration")

    WrtAsUtf("""
    <body><h2>Edit Survol configuration</h2><br>
    """)

    WrtAsUtf("""
    <form method="post" action="edit_configuration.py" name="ServerConfiguration">
    CGI server port number:
    <input name="server_port" value="8000"><br><br>
    <input value="Submit configuration" name="Hello" type="submit"><br>
    </form>
    """)

    WrtAsUtf('<br><a href="edit_credentials.py">Credentials</a>')

    urlIndex = lib_exports.UrlWWW("index.htm")
    WrtAsUtf('<br><a href="' + urlIndex + '">Return to Survol</a>')

    WrtAsUtf("</body></html>")

if __name__ == '__main__':
	Main()
