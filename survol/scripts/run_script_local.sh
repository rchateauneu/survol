#
# This is made to debug things on OVH hosting.

echo "Run script locally"

cd survol

# PYTHONPATH=.
# PYTHONPATH=/homez.85/primhilltc/survol/survol

# TODO: The logic is OK but the script should be a parameter.

PYTHONPATH=/homez.85/primhilltc/survol/survol \
SERVER_NAME=debug.primhillcomputers.com \
SCRIPT_NAME=sources_types/CIM_ComputerSystem/mysql_databases.py \
QUERY_STRING="xid=CIM_ComputerSystem.Name%3Dprimhilltcsrvdb1.mysql.db&mode=json" \
python survol/sources_types/CIM_ComputerSystem/mysql_databases.py
