import pyodbc
import time

# RCHATEAU-HP\SQLEXPRESS
#
# User databases: "Insight_v50_0_81912336" and "SQLEXPRESS"
# TODO: Find a way to list these databases.
cnxn = pyodbc.connect(r'Driver={SQL Server};Server=.\SQLEXPRESS;Database=ExpressDB;Trusted_Connection=yes;')
while True:
    cursor = cnxn.cursor()
    cursor.execute("SELECT * FROM sys.tables")
    while 1:
        row = cursor.fetchone()
        if not row:
            break
        # (u'ExpressTbl1', 245575913, None, 1, 0, 'U ', u'USER_TABLE', datetime.datetime(2015, 7, 30, 22, 3, 47, 167000),
        #  datetime.datetime(2015, 7, 30, 22, 3, 47, 197000), False, False, False, 0, None, 2, False, True, False, False,
        #  False, False, False, 0, False, False, 0, u'TABLE', False)
        print(row)
    time.sleep(10)

cnxn.close()

