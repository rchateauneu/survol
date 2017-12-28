# This test the local agent with wget.
# The idea is to load as many URLs as possible,
# to detect errors, bugs etc..
wget --timeout=60 --directory-prefix=wget_test_output --recursive --level=2 http://rchateau-hp:8000/survol/entity.py?mode=html