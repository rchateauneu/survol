#!/usr/bin/python

"""
Edits Survol configuration parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import sys

def Wrt(theStr):
    sys.stdout.write(theStr)

def Main():
    Wrt("""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>Configuration</title></head>
    """)

Wrt("""
<body>Have the same "SURVOL" header<br><br>Edit Survol configuration<br><br>
""")

Wrt("""
<form method="post" action="edit_configuration.py" name="ServerConfiguration">
CGI server port number:
<input name="server_port" value="8000"><br><br>
<input value="MySubmit" name="Hello" type="submit"><br>
</form>
""")

Wrt("""
<br><a href="edit_credentials.py">Credentials</a>
""")
Wrt("""
<br><a href="index.htm">Return to Survol</a>
""")

Wrt("""
</body></html>""")
