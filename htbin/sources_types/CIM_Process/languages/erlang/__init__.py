# (1) Live inspection of running code without prior instrumentation is a great feature of Erlang

# Path: C:\Program Files\erl7.3\erts-7.3\bin\erlsrv.exe
# Autostart location: HKLM\System\CurrentControlSet\Services\RabbitMQ
#
# erl.exe:
# C:\Program Files\erl7.3\erts-7.3\bin

# erl.exe          "C:\Program Files\erl7.3\erts-7.3\bin\erl.exe" -service_event ErlSrv_RabbitMQ -nohup -sname rabbit@rchateau-HP  -pa "C:\\PROGRA~1\\RABBIT~1\\rabbitmq_server-3.6.6\\ebin" -boot start_sasl -s "rabbit" boot -config "C:\\Users\\rchateau\\AppData\\Roaming\\RabbitMQ\\rabbitmq" +W w +A "64" +P 1048576 +t 5000000 +stbt db +zdbbl 32000  -kernel inet_default_connect_options "[{nodelay,true}]"  -sasl errlog_type error -sasl sasl_error_logger false -rabbit error_logger {file,\""C:/Users/rchateau/AppData/Roaming/RabbitMQ/log/RABBIT~1.LOG"\"} -rabbit sasl_error_logger {file,\""C:/Users/rchateau/AppData/Roaming/RabbitMQ/log/RABBIT~2.LOG"\"} -rabbit enabled_plugins_file \""C:/Users/rchateau/AppData/Roaming/RabbitMQ/ENABLE~1"\" -rabbit plugins_dir \""C:/PROGRA~1/RABBIT~1/RABBIT~1.6/plugins"\" -rabbit plugins_expand_dir \""C:/Users/rchateau/AppData/Roaming/RabbitMQ/db/rabbit@rchateau-HP-plugins-expand"\" -rabbit windows_service_config \""C:/Users/rchateau/AppData/Roaming/RabbitMQ/rabbitmq"\" -os_mon start_cpu_sup false -os_mon start_disksup false -os_mon start_memsup false -mnesia dir \""C:/Users/rchateau/AppData/Roaming/RabbitMQ/db/RABBIT~1"\"  -kernel inet_dist_listen_min 25672 -kernel inet_dist_listen_max 25672  3132
# epmd.exe         "C:\Program Files\erl7.3\erts-7.3\bin\epmd" -daemon
# erlsrv.exe       "C:\Program Files\erl7.3\erts-7.3\bin\erlsrv.exe"
# inet_gethost.exe "C:\Program Files\erl7.3\erts-7.3\bin\inet_gethost.exe" 4
#
# http://stackoverflow.com/questions/1274681/query-an-erlang-process-for-its-state
# http://stackoverflow.com/questions/7160239/how-to-communicate-with-erlang-code-from-python-code

