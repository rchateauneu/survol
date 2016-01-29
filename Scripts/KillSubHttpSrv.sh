
# Just a development tool for killing subprocess which runs a python script
# and have been started by lib_webserv.py
for pid in `ps -ef| grep python | grep -v grep | cut -c9-16`
do
	echo $pid
done

