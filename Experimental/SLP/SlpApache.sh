#!/bin/bash

# If the Python CGI scritps are served by Apache.

. SLP/SlpMgr.sh

# If the user hits control-c
control_c()
{
	SlpRegCgi deregister

	exit
}
 
# trap keyboard interrupt (control-c)
trap control_c SIGINT

# Needed by the SLP server.
# http://127.0.0.1/~rchateau/RevPython/sources/cgi_sockets.py
export CgiPortSources=80/~rchateau/RevPython

export SlpdHere=`ps -ef | grep slpd | grep -v grep`
if [ "$SlpdHere" == "" ]
then
	echo "Slpd not started"
	exit 1
fi

SlpRegCgi register

sleep 1
echo "SLP registered services"
slptool findsrvs service:http.rdf

# Maintenant, il faut enregistrer dans SLP
# la ou les pages de bookmarks? Ou tout simplement
# notre script CGI qui les edite,
# ce qui evite d'acceder au fichier lui-meme?
# Ca serait qd meme plus chic si c'etait affichable
# et pas simplement une variable javascript.

echo Started, based on Apache server.

sleep 999999
