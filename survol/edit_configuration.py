#!/usr/bin/env python

"""
Edits Survol configuration parameters.
Also, it serves JSON queries from the HTML pages doing the same features, but in JSON.
"""

import cgi
import html
import json
import os

import lib_export_html
import lib_util
import lib_configuration

from lib_util import write_as_utf


def GetSubmittedConfig(loaded_config):
    """Return form values when the current request is a POST, otherwise None."""
    if os.environ.get("REQUEST_METHOD", "").upper() != "POST":
        return None

    form = cgi.FieldStorage()

    # An unchecked checkbox is absent from the POST request.
    return {
        "cgi_server_port": form.getfirst("cgi_server_port", loaded_config["cgi_server_port"]),
        "wsgi_server_port": form.getfirst("wsgi_server_port", loaded_config["wsgi_server_port"]),
        "bookmark_url": form.getfirst("bookmark_url", loaded_config["bookmark_url"]),
        "html_jinja2": form.getfirst("html_jinja2") is not None,
        "graphviz_wsl": form.getfirst("graphviz_wsl") is not None,
    }


def GetConfig():
    """Load the JSON file, then save any values submitted by the form."""
    config = lib_configuration.LoadConfig()
    submitted_config = GetSubmittedConfig(config)

    if submitted_config is not None:
        config.update(submitted_config)
        lib_configuration.SaveConfig(config)

    return config


def MainNoJinja(config):
    lib_util.WrtHeader('text/html')
    lib_export_html.display_html_text_header("Configuration")

    cgi_server_port = html.escape(config["cgi_server_port"], quote=True)
    wsgi_server_port = html.escape(config["wsgi_server_port"], quote=True)
    bookmark_url = html.escape(config["bookmark_url"], quote=True)
    checked_jinja2 = " checked" if config["html_jinja2"] else ""
    checked_graphviz_wsl = " checked" if config["graphviz_wsl"] else ""

    write_as_utf("""
    <body><h2>Edit Survol configuration</h2>
    <form method="post" action="edit_configuration.py" name="ServerConfiguration">
    <table border="0">
    <tr>
    <td>CGI server port number:</td>
    <td>&nbsp;<input name="cgi_server_port" value="%s"></td>
    </tr>
    <tr>
    <td>WSGI server port number:</td>
    <td>&nbsp;<input name="wsgi_server_port" value="%s"></td>
    </tr>
    <tr>
    <td>Bookmarks file or URL:</td>
    <td>&nbsp;<input name="bookmark_url" value="%s"></td>
    </tr>
    <tr>
    <td>HTML Jinja2 templates:</td>
    <td align="left"><input type="checkbox" name="html_jinja2"%s></td>
    </tr>
    <tr>
    <td>Graphviz on WSL (Windows only):</td>
    <td align="left"><input type="checkbox" name="graphviz_wsl"%s></td>
    </tr>
    <tr>
    <td colspan="2"><input value="Submit configuration" name="Hello" type="submit"></td>
    </tr>
    </table>
    </form>
    """ % (cgi_server_port, wsgi_server_port, bookmark_url, checked_jinja2, checked_graphviz_wsl))

    html_footer = "".join(lib_export_html.display_html_text_footer())
    write_as_utf(html_footer)
    write_as_utf("</body></html>")


def MainJinja(config):
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    template_file_name = "www/edit_configuration.template.htm"

    jinja2 = lib_util.GetJinja2()
    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(THIS_DIR),
        trim_blocks=True,
    )
    jinja_template = jinja_env.get_template(template_file_name)

    # Pass all four configuration values to the Jinja2 template.
    jinja_render = jinja_template.render(**config)
    lib_util.WrtHeader('text/html')
    write_as_utf(jinja_render)


def Main():
    config = GetConfig()

    if lib_util.GetJinja2():
        MainJinja(config)
    else:
        MainNoJinja(config)


if __name__ == '__main__':
    Main()
