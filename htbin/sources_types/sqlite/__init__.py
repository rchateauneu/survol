import os

# Tells if a file is a sqlite databse.
def IsSqliteDatabase(filNam):
	# TODO: Checking the file extension may not be enough and we should check the content.
	filExt = os.path.splitext(filNam)[1]
	return filExt.upper() in [".SQLITE",".SQLITE2",".SQLITE3",".DB"]

