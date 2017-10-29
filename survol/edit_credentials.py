#!/usr/bin/python

"""
Edits credentials Survol parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import os
import sys
import lib_util
import lib_credentials

def Wrt(theStr):
    sys.stdout.write(theStr)

def FormUpdateCredentials(formAction,credTypeList):
    Wrt("""
    <form method="post" action="%s" name="ServerCredentials">
    """%(formAction))

    Wrt("""
    <table>
    """)

    sys.stderr.write("credTypeList=%s\n"%str(credTypeList))
    for credType in credTypeList:
        # This is a type of access: Oracle databse, Linux machine, Windows account etc...
        Wrt("""
        <tr>
        <td colspan=4>%s</td>
        </tr>
        """
            % (credType))

        # This is a homogeneous list, for example of machines names, or databases.
        credNams = lib_credentials.GetCredentialsNames( credType )
        for credName in credNams:
            # For a machine, this accepts only one user.
            # Same for a given database: Only one user. The reason is that the scripts
            # do not have to chosse when they need to display information about something.
            # Read-only access rights are enough.
            cred = lib_credentials.GetCredentials( credType, credName )
            credInputPrefix = credType + "_" + credName + "_" + cred[0] + "_upd_"
            credInputPassword = credInputPrefix + "_pwd"
            credInputNameDel = credInputPrefix + "_del"

            Wrt("""
            <tr>
            <td>%s</td>
            <td>%s</td>
            <td><input name="%s" value="%s"></td>
            <td><input type="checkbox" name="%s"></td>
            </tr>
            """%(credName,cred[0],credInputPassword,cred[1],credInputNameDel))
    Wrt("""
    </table>
    """)

    Wrt("""
    <input value="SubmitCredUpd" name="Hello" type="submit"><br>
    </form>
    """)

def FormInsertCredentials(formAction,credTypeList):
    Wrt("""
    <form method="post" action="edit_credentials.py" name="ServerCredentials">
    """)
    Wrt("""
    <table>
    """)
    credInputAddPrefix = "credentials_add_"
    credInputAddType = credInputAddPrefix + "_name"
    credInputAddName = credInputAddPrefix + "_name"
    credInputAddUsr = credInputAddPrefix + "_usr"
    credInputAddPwd = credInputAddPrefix + "_pwd"

    Wrt("""
    <tr>""")

    Wrt("""<td>Type:<select name="%s">"""%(credInputAddType))
    for credType in credTypeList:
        Wrt("""<option value='%s'>%s</option>""" % (credType, credType ))
    Wrt("""</select></td>""")

    Wrt("""
    <td>Name:<input name="%s"></td>
    <td>User:<input name="%s"></td>
    <td>Password:<input name="%s"></td>
    </tr>
    """ % (credInputAddName,credInputAddUsr,credInputAddPwd))

    Wrt("""
    </table>
    """)

    Wrt("""
    <input type="hidden" value="xxxxxx" name="yyyyyy">
    <input value="SubmitCredAdd" name="Hello" type="submit">
    </form>
    """)

def Main():
    formAction = os.environ['SCRIPT_NAME']

    lib_util.HttpHeaderClassic(sys.stdout, "text/html")

    Wrt("""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>Credentials</title></head>
    """)

    Wrt("""
    <body>Have the same "SURVOL" header<br><br>Edit Survol credentials<br><br>
    """)

    credTypeList = lib_credentials.GetCredentialsTypes()
    if credTypeList:
        FormUpdateCredentials(formAction,credTypeList)
    else:
        Wrt("""
        No credentials yet<br><br>
        """)

    credTypesWellKnown = [
        "Login",
        "WMI",
        "Oracle",
        "WBEM",
        "RabbitMQ",
        "Azure",
        "ODBC",
    ]

    FormInsertCredentials(formAction, credTypesWellKnown)


    Wrt("""
    <br><a href="edit_configuration.py">Configuration</a>
    <br><a href="index.htm">Return to Survol</a>
    """)

    Wrt("""
    </body></html>""")

if __name__ == '__main__':
	Main()
