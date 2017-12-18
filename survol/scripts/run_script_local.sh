#

# http://primhillcomputers.com/cgi-bin/survol/survolcgi.py?script=/sources_types/CIM_ComputerSystem/mysql_databases.py&amp;xid=CIM_ComputerSystem.Name%3Dprimhilltcsrvdb1.mysql.db&mode=html
echo "Run script locally"

# cd survol/survol
cd survol

# PYTHONPATH=.
# PYTHONPATH=/homez.85/primhilltc/survol/survol

PYTHONPATH=/homez.85/primhilltc/survol/survol \
SERVER_NAME=1.2.3 \
SCRIPT_NAME=sources_types/CIM_ComputerSystem/mysql_databases.py \
QUERY_STRING="xid=CIM_ComputerSystem.Name%3Dprimhilltcsrvdb1.mysql.db&mode=json" \
python survol/sources_types/CIM_ComputerSystem/mysql_databases.py
