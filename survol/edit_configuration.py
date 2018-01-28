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
    <body><h2>Edit Survol configuration</h2>
    """)

    WrtAsUtf("""
    <form method="post" action="edit_configuration.py" name="ServerConfiguration">
    <table border="0">
    <tr>
    <td>CGI server port number:</td>
    <td><input name="server_port" value="8000"></td>
    </tr>
    <tr>
    <td>Bookmarks file or URL:</td>
    <td><input name="bookmark_url" value="bookmarks.htm"></td>
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

if __name__ == '__main__':
	Main()
