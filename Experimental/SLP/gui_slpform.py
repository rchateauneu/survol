#!/usr/bin/env python

import os
import re

# This generates a form containing the SLP urls.
# Much simpler than using Quik for preprocessing the HTML page.
# Maybe we could use it here, but here only.

class SlpService:
	def __init__( self, name, url, rest, label ):
		# print "Name="+ name + " url=" + url
		self.m_name = name
		self.m_url = url
		self.m_rest = rest
		self.m_label = label

service_filter = "http.rdf"

# Only the services we want.
def GetSlpServices(filter):
	services_list = []
	stream = os.popen("slptool findsrvs service:" + filter)
	# service:ftp.smallbox://192.168.100.1:21,65535
	lbl = 0
	for line in stream:
		# print "Li=" + line
		matchObj = re.match( r'service:([^:]*):/?/?([^,]*)(.*)', line, re.M|re.I)
		if matchObj:
			service = SlpService(
					matchObj.group(1) ,
					'http' + '://' + matchObj.group(2) ,
					matchObj.group(3) ,
					'label_' + str(lbl) )
			services_list.append( service )
		else:
			print "No match!!"
		lbl = lbl + 1
	return services_list

print "Content-type: text/html\n\n"

print "<table border=1>"

for svc in GetSlpServices(service_filter):
	print '<tr>'
	print '	<td><input type="checkbox" name="' + svc.m_label + '" value="' + svc.m_url + '"></td>'
	print '	<td>' + svc.m_name + '</td>'
	print '	<td>' + svc.m_rest + '</td>'
	print '	<td><a href="' + svc.m_url + '">' + svc.m_url + '</a></td>'
	print '</tr>'

print "</table>"

