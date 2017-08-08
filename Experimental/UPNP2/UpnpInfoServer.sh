#!/bin/bash

# If the glue between the services is UPNP.

control_c()
# run if user hits control-c
{
	for MyPid in $PidInfo $PidWeb $PidNotify $PidMSearch
	do
		echo Killing $MyPid
		# kill -9 $MyPid
		# kill -2 $MyPid
		pkill -KILL -P $MyPid
	done
	exit
}
 
# trap keyboard interrupt (control-c)
trap control_c SIGINT

InformationExtraction()
{
	while true
	do
		python svc_processes.py 2>&1 | tee -a svc_processes.log
		sleep 60
	done
}

WebServer()
{
	python webserver.py 2>&1 | tee -a webserver.log
}

UpnpNotify()
{
	python notify_ssdp.py 192.168.1.64 2>&1 | tee -a notify_ssdp.log
}

UpnpMSearch()
{
	python upnp-service.py 192.168.1.64 2>&1 | tee -a upnp-service.log
}

InformationExtraction &
export PidInfo=$!

WebServer &
export PidWeb=$!

UpnpNotify &
export PidNotify=$!

UpnpMSearch &
export PidMSearch=$!

echo "Started PidInfo=$PidInfo PidWeb=$PidWeb PidNotify=$PidNotify PidMSearch=$PidMSearch"

# main() loop
while true; do read x; done
