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
@REM
@REM Enclose the URL in double-quotes otherwise DOS strips "-" equal sign !!!

@echo 1=%~1
@set "SCRIPT_URL=%~1"
echo SCRIPT_URL=%SCRIPT_URL%
@echo off
for /f "tokens=1,2 delims=?" %%a in ("%SCRIPT_URL%") do (
  set "BEFORE_QM=%%a"
  set "AFTER_QM=%%b"
)
@echo on


@REM Usage example:
@REM survol\scripts\run_script_local.bat survol\sources_types\enumerate_CIM_Process.py

@echo BEFORE_QM=%BEFORE_QM%
@echo AFTER_QM=%AFTER_QM%

@REM set SCRIPT_NAME=%BEFORE_QM%&set "QUERY_STRING=%AFTER_QM%&mode=daemon"&set PYTHONPATH=survol&py -2.7 %BEFORE_QM%

@REM Preferred output mode is probably JSON or RDF because the overhead is very small.
@REM set SCRIPT_NAME=%BEFORE_QM%&set "QUERY_STRING=%AFTER_QM%&mode=rdf"&set PYTHONPATH=survol&py -2.7 %BEFORE_QM%

@REM Profiling a script:
@REM https://docs.python.org/3/library/profile.html
@REM python -m cProfile [-o output_file] [-s sort_order] (-m module | myscript.py)

set SCRIPT_NAME=%BEFORE_QM%&set "QUERY_STRING=%AFTER_QM%&mode=rdf"&set PYTHONPATH=survol&py -2.7 -m cProfile -s cumulative %BEFORE_QM%

@REM Linux only.
@REM py -2.7 -m cProfile -s cumulative -m pytest tests/test_dockit.py::ReplaySessionsTest::test_replay_all_trace_files

