#!/bin/bash

# Registers in SLP all the relevant CGI scripts.
SlpRegCgi()
{
	KeyWord=$1
	# For example 192.168.1.68 or "localhost" or "DuoLnx"
	# But "DuoLnx" does not work because it is unknown by the DNS or something else.
	Host=`hostname -i`
	echo ${KeyWord}ing CGIs
	# cd ..
	for fil in survol/sources_types/cgi_*.py
	do
		basna=`basename $fil`
		# echo SLP Base=$basna
		Svc="service:http.rdf://${Host}:${CgiPortSources}/survol/sources/${basna},en,65535"
		# Svc="service:http.rdf://${Host}:${CgiPortSources}/sources/${basna},en,65535"
		echo slptool $KeyWord $Svc
		slptool $KeyWord $Svc
	done
}

