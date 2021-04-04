#!/usr/bin/env python

"""
Edits credentials Survol parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import os
import sys
import cgi
import socket
import logging

import lib_uris
import lib_common
import lib_util
import lib_credentials
import lib_export_html
from lib_util import WrtAsUtf


def _create_credentials_map():
    """This lists the content of credentials and associates a variable name to each element.
    This variable name which must be unique, is later used to build a HTML form."""
    cred_type_list = lib_credentials.get_credentials_types()

    cred_types_dict = dict()

    for cred_type in sorted(cred_type_list):

        cred_types_dict[cred_type] = dict()

        # This is a homogeneous list, for example of machines names, or databases.
        cred_nams = lib_credentials.get_credentials_names(cred_type)

        for cred_name in sorted(cred_nams):
            cred = lib_credentials.GetCredentials(cred_type, cred_name)

            cred_input_prefix = cred_type + "_" + cred_name + "_" + cred[0]
            cred_input_password = cred_input_prefix + "_UPDATE_PASSWORD"
            cred_input_name_del = cred_input_prefix + "_DELETE_CREDENTIAL"

            cred_name_url = _cred_type_name_to_url(cred_type, cred_name)

            cred_types_dict[cred_type][cred_name] = [
                cred[0],
                cred[1],
                cred_input_password,
                cred_input_name_del,
                cred_name_url]

    return cred_types_dict


def _form_update_credentials_no_jinja(form_action, cred_map):
    """This applies only if the jinja2 module is not there."""
    WrtAsUtf("""
    <form method="post" action="%s" name="ServerCredentials">
    """ % (form_action))

    WrtAsUtf("""<tr>
    <td><b>Resource</b></td>
    <td><b>Account</b></td>
    <td><b>Password</b></td>
    <td><b>Del</b></td>
    </tr>
    """)

    for cred_type in sorted(cred_map):
        # This is a type of access: Oracle databse, Linux machine, Windows account etc...
        WrtAsUtf("<tr><td colspan=4><b>%s</b></td></tr>" % cred_type)

        # This is a homogeneous list, for example of machines names, or databases.
        cred_nams = cred_map[cred_type]
        for cred_name in sorted(cred_nams):
            # For a machine, this accepts only one user.
            # Same for a given database: Only one user. The reason is that the scripts
            # do not have to chosse when they need to display information about something.
            # Read-only access rights are enough.
            cred = cred_nams[cred_name]

            cred_name_url = cred[4]

            if cred_name_url:
                WrtAsUtf("""<tr>
                <td><a href="%s">%s</a></td>
                <td>%s</td>
                <td><input name="%s" value="%s"></td>
                <td><input type="checkbox" name="%s"></td>
                </tr>
                """ % (cred_name_url, cred_name, cred[0], cred[2], cred[1], cred[3]))
            else:
                # If no URL can be created. For example of the map misses a function
                # for a given credential type.
                WrtAsUtf("""<tr>
                <td>%s</td>
                <td>%s</td>
                <td><input name="%s" value="%s"></td>
                <td><input type="checkbox" name="%s"></td>
                </tr>
                """ % (cred_name, cred[0], cred[2], cred[1], cred[3]))

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4>""")
    WrtAsUtf("""
    <input value="Update / delete credential" name="SubmitCredUpdName" type="submit"><br>
    """)
    WrtAsUtf("""</td>""")
    WrtAsUtf("""</tr>""")
    WrtAsUtf("""
    </form>
    """)


def _form_insert_credentials_no_jinja(form_action, cred_type_list):
    WrtAsUtf("""
    <form method="post" action="edit_credentials.py" name="ServerCredentials">
    """)

    cred_input_add_prefix = "credentials_add_"
    cred_input_add_type = cred_input_add_prefix + "type"
    cred_input_add_name = cred_input_add_prefix + "name"
    cred_input_add_usr = cred_input_add_prefix + "usr"
    cred_input_add_pwd = cred_input_add_prefix + "pwd"

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4><b>Credentials creation</b></td>""")
    WrtAsUtf("""</tr>""")

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4><select name="%s">""" % cred_input_add_type)
    for cred_type in cred_type_list:
        WrtAsUtf("""<option value='%s'>%s</option>""" % (cred_type, cred_type))
    WrtAsUtf("""</select></td>""")
    WrtAsUtf("""</tr>""")

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""
    <td><input name="%s"></td>
    <td><input name="%s"></td>
    <td><input name="%s"></td>
    </tr>
    """ % (cred_input_add_name, cred_input_add_usr, cred_input_add_pwd))

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4>""")
    WrtAsUtf("""
    <input type="hidden" value="HiddenValue" name="HiddenName">
    <input value="Insert new credential" name="SubmitCredAddName" type="submit">
    """)
    WrtAsUtf("""</td>""")
    WrtAsUtf("""</tr>""")
    WrtAsUtf("""
    </form>
    """)


def _inserted_cred_map(cgi_arguments):
    """This is called if the form tries to insert a new credential"""
    try:
        cgi_arguments["SubmitCredAddName"]
        cred_type = cgi_arguments["credentials_add_type"].value
        cred_name = cgi_arguments["credentials_add_name"].value
        cred_usr = cgi_arguments["credentials_add_usr"].value
        cred_pwd = cgi_arguments["credentials_add_pwd"].value

        lib_credentials.add_one_credential(cred_type, cred_name, cred_usr, cred_pwd)

    except KeyError:
        pass


def _updated_cred_map(cgi_arguments):
    """
    This takes the list on input cgi variables and uses it to update the passwords
    or delete entire rows of credentials (user+pass).
    """
    cred_map = _create_credentials_map()

    cred_map_out = dict()

    # Writes to the output file only if the credentials are really changed.
    was_changed = False
    try:
        cgi_arguments["SubmitCredUpdName"]

        for cred_type in sorted(cred_map):
            cred_map_out[cred_type] = dict()
            cred_nams = cred_map[cred_type]
            for cred_name in sorted(cred_nams):
                cred = cred_nams[cred_name]

                try:
                    # If the "_del" variable is ticked, do not copy the credentials.
                    cgi_arguments[cred[3]]
                    was_changed = True
                    continue
                except:
                    pass

                try:
                    # If the "_upd" variable is ticked, copy the credentials with a new password.
                    # BEWARE / TODO / FIXME: If the password is empty, it is not taken into account.
                    # It does not seem possible to have an empty password.
                    upd_password = cgi_arguments[cred[2]].value
                    if upd_password != cred[1]:
                        was_changed = True
                        #   WrtAsUtf("Name=%s: Replace %s by %s<br>"%(cred[0],cred[1],upd_password))
                        cred[1] = upd_password
                except:
                    pass

                cred_map_out[cred_type][cred_name] = cred

    except KeyError:
        cred_map_out = cred_map

    if was_changed:
        # Change the file only if something really changed.
        lib_credentials.update_credentials(cred_map_out)
    return cred_map_out


def _cred_definitions():
    """
    This returns the list of known credential types and for each of them,
    a function which creates a URL for a credential resource name.
    """

    def CredUrlLogin(cred_name_machine):
        """ Return a node given a machine name"""
        # Example: credName_Machine="titi\\john.smith@hotmail.com"
        server_node = lib_uris.gUriGen.HostnameUri(cred_name_machine)
        return server_node

    def CredUrlWMI(hostname):
        node_wmi = lib_util.UrlPortalWmi(hostname)
        return node_wmi

    def CredUrlOracle(dbName):
        # Example: dbName = "XE", which must be defined in tnsnames-ora
        from sources_types.oracle import db as oracle_db
        node_oradb = oracle_db.MakeUri( dbName )
        return node_oradb

    def CredUrlSqlExpress(dbName):
        # Example: dbName = "MYMACHINE\\SQLEXPRESS". It contains the server name.
        # Connection with ODBC.
        # conn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;DATABASE=ExpressDB;UID=essaisql;PWD=tralala')
        # The ODBC connection string can be, from Fedora Linux:
        # 'DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;DATABASE=SQLEXPRESS;UID=xxxxxxx;PWD=yyyyyyy'

        # TODO: Finish this
        return None

    def CredUrlMySql(instance_my_sql):
        from sources_types.mysql import instance as survol_mysql_instance
        node_instance = survol_mysql_instance.MakeUri(instance_my_sql)
        return node_instance

    def CredUrlWBEM(cimomUrl):
        # Example: urlWbem = "http://192.168.0.17:5989"
        if False:
            hostname = cimomUrl[7:]
            node_wbem = lib_util.UrlPortalWbem(cimomUrl)
            return node_wbem
        else:
            import lib_wbem
            the_cimom = lib_credentials.key_url_cgi_encode(cimomUrl)
            node_wbem = lib_wbem.WbemAllNamespacesUrl(the_cimom)
            return node_wbem

    def CredUrlSurvol(survol_url):
        node_survol = lib_common.NodeUrl(survol_url)
        return node_survol

    def CredUrlRabbitMQ(config_nam):
        from sources_types.rabbitmq import manager as survol_rabbitmq_manager
        node_manager = survol_rabbitmq_manager.MakeUri(config_nam)
        return node_manager

    def CredUrlAzure(subscription_name):
        # Example: subscriptionName = "Visual Studio Professional"
        from sources_types.Azure import subscription as azure_subscription
        subscription_node = azure_subscription.MakeUri(subscription_name)
        return subscription_node

    def CredUrlODBC(dsn):
        from sources_types.odbc import dsn as survol_odbc_dsn
        node_dsn = survol_odbc_dsn.MakeUri( "DSN=" + dsn )
        return node_dsn

    # This hard-coded list allows also to create credentials for the first time.
    cred_types_well_known = {
        "Login": CredUrlLogin,
        "WMI": CredUrlWMI,
        "Oracle": CredUrlOracle,
        "SqlExpress": CredUrlSqlExpress,
        "MySql": CredUrlMySql,
        "WBEM": CredUrlWBEM,
        "Survol": CredUrlSurvol,
        "RabbitMQ": CredUrlRabbitMQ,
        "Azure": CredUrlAzure,
        "ODBC": CredUrlODBC,
    }

    return cred_types_well_known


def _cred_type_name_to_url(cred_type, cred_name):
    try:
        # Maybe we can create a URL for a credName of a given credType.
        # For example a machine name if 'Login', a database if 'Oracle',
        # an access to a WBEM server if 'WBEM' etc...
        node_generator = _cred_definitions()[cred_type]
        cred_name_url = node_generator(cred_name)
    except Exception as exc:
        # Maybe the key is not defined or the generator does not work
        logging.warning("node_generator exception:%s", str(exc))
        cred_name_url = None
    return cred_name_url


def Main():
    form_action = os.environ['SCRIPT_NAME']

    cgi_arguments = cgi.FieldStorage()

    cred_filename = os.path.normpath(lib_credentials.credentials_filename())
    page_title = "Edit Survol credentials in %s" % cred_filename

    # Hostname=Unknown-30-b5-c2-02-0c-b5-2.home
    # Host address=192.168.0.17
    # Remote client=82.45.12.63

    curr_host_nam = socket.gethostname()
    curr_host_addr = lib_util.GlobalGetHostByName(curr_host_nam)
    try:
        addr_remote = os.environ['REMOTE_ADDR']
    except KeyError:
        logging.error("Cannot get REMOTE_ADDR")
        raise

    # Hard-coded protection.
    if addr_remote not in ["82.45.12.63", "192.168.0.14", "192.168.1.10", "192.168.56.1", "127.0.0.1"]:
        lib_common.ErrorMessageHtml("Access forbidden from %s" % addr_remote)

    _inserted_cred_map(cgi_arguments)
    cred_map = _updated_cred_map(cgi_arguments)
    cred_types_well_known = _cred_definitions()
    cred_type_list = sorted(cred_types_well_known.keys())

    def main_no_jinja():
        """Simple HTML page if jinja2 is not installed."""
        lib_util.WrtHeader('text/html')
        lib_export_html.display_html_text_header(page_title)

        WrtAsUtf("""
        <body><h2>%s</h2>
        """ % page_title)

        WrtAsUtf("""
        <table border="1" width='100%%'>
        <tr><td><b>Host name</b></td><td>%s</td></tr>
        <tr><td><b>Host address</b></td><td>%s</td></tr>
        <tr><td><b>Remote address</b></td><td>%s</td></tr>
        """ % (curr_host_nam, curr_host_addr, addr_remote))

        WrtAsUtf("""<table border="1" width='100%%'>""")
        if cred_map:
            _form_update_credentials_no_jinja(form_action, cred_map)

        _form_insert_credentials_no_jinja(form_action, cred_type_list)
        WrtAsUtf("""</table>""")

        html_footer = "".join(lib_export_html.display_html_text_footer())
        WrtAsUtf(html_footer)

        WrtAsUtf("</body></html>")

    def main_jinja():
        THIS_DIR = os.path.dirname(os.path.abspath(__file__))
        template_file_name = "www/edit_credentials.template.htm"

        # Create the jinja2 environment.
        # Notice the use of trim_blocks, which greatly helps control whitespace.
        jinja2 = lib_util.GetJinja2()
        jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(THIS_DIR), trim_blocks=True)
        jinja_template = jinja_env.get_template(template_file_name)

        import collections

        ordered_map = collections.OrderedDict()
        for cred_type in sorted(cred_map):
            sub_ordered_map = collections.OrderedDict()
            for cred_nam in sorted(cred_map[cred_type]):
                sub_ordered_map[cred_nam] = cred_map[cred_type][cred_nam]
            ordered_map[cred_type] = sub_ordered_map

        jinja_render = jinja_template.render(
            page_title=page_title,
            currHostNam=curr_host_nam,
            currHostAddr=curr_host_addr,
            addrRemote=addr_remote,
            credMap=ordered_map,
            credTypeList=cred_type_list )
        lib_util.WrtHeader('text/html')
        WrtAsUtf(jinja_render)

    if lib_util.GetJinja2():
        main_jinja()
    else:
        main_no_jinja()


if __name__ == '__main__':
    Main()
