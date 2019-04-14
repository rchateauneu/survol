#!/bin/lmishell

# https://blog.fpmurphy.com/2013/06/openlmi-open-linux-management-interface.html
#!/bin/python

import pywbem

url = "http://vps516494.ovh.net:5988"
username = "pegasus"
password = "*****"

conn = pywbem.WBEMConnection(url, (username, password),)

slct = 'select Name, userPassword from LMI_Account where Name = "root"'
#print c.ExecQuery('WQL', slct)[0].tomof()
p = conn.ExecQuery('WQL', 'select Name, userPassword from LMI_Account where Name = "root"')
print( p[0].tomof() )


