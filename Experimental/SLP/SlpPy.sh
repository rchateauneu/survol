#!/bin/bash

# If the CGI Python scripts are served by a Python class.

. SLP/SlpMgr.sh

# If the user hits control-c
control_c()
{
	for MyPid in $PidCgiServerSources $PidCgiServerInternals
	do
		echo Killing $MyPid
		pkill -KILL -P $MyPid
		kill -9 $MyPid

	done

	SlpRegCgi deregister

	exit
}
 
# trap keyboard interrupt (control-c)
trap control_c SIGINT

# Two CGI servers because they are not reentrant. This one is needed by the SLP server.
export CgiPortSourcesOnly=8642
# export CgiPortSources=8642/htbin
export CgiPortSources=8642
# This one is used only internally.
export CgiPortInternalsOnly=2468
export CgiPortInternals=2468

# These URLs are sources of RDF document.
CgiServerSources()
{
	SlpRegCgi register
	echo "Starting CgiServerSources Port=${CgiPortSources} Pid=$$"
	python -m CGIHTTPServer ${CgiPortSourcesOnly}
}

# These CGI scripts are used internally. They must have a different port number
# than the server for RFD sources, because the web server is not multi-threaded.
CgiServerInternals()
{
	echo "Starting CgiServerInternals Port=${CgiPortInternals} Pid=$$"
	python -m CGIHTTPServer ${CgiPortInternalsOnly}
}

export SlpdHere=`ps -ef | grep slpd | grep -v grep`
if [ "$SlpdHere" == "" ]
then
	echo "Slpd not started"
	exit 1
fi

CgiServerSources &
export PidCgiServerSources=$!

CgiServerInternals &
export PidCgiServerInternals=$!

sleep 1
echo "SLP registered services"
slptool findsrvs service:http.rdf

# Maintenant, il faut enregistrer dans SLP
# la ou les pages de bookmarks? Ou tout simplement
# notre script CGI qui les edite,
# ce qui evite d'acceder au fichier lui-meme?
# Ca serait qd meme plus chic si c'etait affichable
# et pas simplement une variable javascript.

echo Started PidCgiServerSources=$PidCgiServerSources PidCgiServerInternals=$PidCgiServerInternals

sleep 999999
