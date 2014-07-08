#!/bin/bash

# Registers in SLP all the relevant CGI scripts.
SlpRegCgi()
{
	KeyWord=$1
	# For example 192.168.1.68 or "localhost" or "DuoLnx"
	Host=`hostname`
	echo ${KeyWord}ing CGIs
	# cd ..
	for fil in htbin/sources/cgi_*.py
	do
		basna=`basename $fil`
		# echo SLP Base=$basna
		# Svc="service:http.rdf://${Host}:${CgiPortSources}/htbin/sources/${basna},en,65535"
		Svc="service:http.rdf://${Host}:${CgiPortSources}/sources/${basna},en,65535"
		echo slptool $KeyWord $Svc
		slptool $KeyWord $Svc
	done
}

