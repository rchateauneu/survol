# This scripts rebuilds the set of input tests using the test programs
# and other various Linux commands.
# Some tests cannot be easily recreated.

# UnitTests/mineit_big_mysql_select.strace.18648.log
# UnitTests/mineit_copy_bigfile.strace.log
# UnitTests/mineit_find_grep.strace.log
# UnitTests/mineit_gcc_hello_world.ltrace.log
# UnitTests/mineit_gcc_incomplete.strace.log
# UnitTests/mineit_graphviz_ps.strace.log
# UnitTests/mineit_minusp_bash_while_sleep.strace.log
# UnitTests/mineit_mysql_show_databases.ltrace.log
# UnitTests/mineit_mysql_show_databases.strace.log
# UnitTests/mineit_oracle_db_schemas.ltrace.log
# UnitTests/mineit_oracle_db_schemas.strace.log
# UnitTests/mineit_plenty_of_clone.strace.log
# UnitTests/mineit_ps_ef.strace.log
# UnitTests/mineit_python_cobaye.strace.log
# UnitTests/mineit_sample_shell.ltrace.log
# UnitTests/mineit_sample_shell.strace.log
# UnitTests/mineit_sample_short_shell.ltrace.log
# UnitTests/mineit_short_graphviz_ps.strace.log
# UnitTests/mineit_vim.strace.log
# UnitTests/mineit_wget_hotmail.strace.866.log

# Execution of simple Perle programs.
./retrobatch.py -t strace -l UnitTests/mineit_simple_perl_file_write perl TestProgs/write_file_in_perl.pl
./retrobatch.py -t ltrace -l UnitTests/mineit_simple_perl_file_write perl TestProgs/write_file_in_perl.pl
