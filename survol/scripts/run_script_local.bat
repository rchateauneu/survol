@REM The intention of this script is to run a URL in command line.
@REM The benefit is that it display much more information than we run from a HTTP server,
@REM because stderr is immediately available, and it can also be run in a debugger.
@REM
@REM Example:
@REM http://rchateau-hp:8000/survol/sources_types/events_generator_psutil_processes_perf.py?xid=.
@REM
@REM ... is transformed into:
@REM set "QUERY_STRING=xid=.&mode=daemon"&set PYTHONPATH=survol&py -2.7 survol/sources_types/events_generator_psutil_processes_perf.py
@REM
@REM Another possibility is to create a Python script which imports the target CGI script.

set SCRIPT_URL=%1
echo %SCRIPT_URL%

for /f "tokens=1,2 delims=?" %%a in ("%SCRIPT_URL%") do (
  set BEFORE_QM=%%a
  set AFTER_QM=%%b
)

echo BEFORE_QM=%BEFORE_QM%
echo AFTER_QM=%AFTER_QM%

set SCRIPT_NAME=%BEFORE_QM%&set "QUERY_STRING=%AFTER_QM%&mode=daemon"&set PYTHONPATH=survol&py -2.7 %BEFORE_QM%
