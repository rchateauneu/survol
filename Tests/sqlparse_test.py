import sys
sys.path.insert(1,r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\htbin\revlib')

import sqlparse
import lib_sql

examples = dict()

examples["Good"] = {
"select aa from bb": ["BB"],
"select b from a": ["A"],
"select b*(b+1) from a": ["A"],
"INSERT INTO table (nom_colonne_1, nom_colonne_2) VALUES ('valeur 1', 'valeur 2')" : ["TABLE"],
"select cola,colc,colb from tab13 alias13,tab23 alias23":["TAB13","TAB23"],
"select alias1.cola,colb from tab1 alias1, (select colb from tab2)":["TAB1","TAB2"],
"select alias25.cola from (select colb from tab22) alias25":["TAB22"],
"select tab22.cola from (select colb from tab22)":["TAB22"],
"select cola,colc,colb from tab14,tab24":["TAB14","TAB24"],
"select cola,colc,colb from tab14,tab24 alias24":["TAB14","TAB24"],
"select cola from (select colb from tab22) alias2":["TAB22"],
"select cola from tab11 alias1, (select colb from tab22) alias2":["TAB11","TAB22"],
"select alias1.cola,alias2.colb from tab11 alias1, (select colb from tab22) alias2":["TAB11","TAB22"],
"select cola from tab11, (select colb from tab22) alias2":["TAB11","TAB22"],
"select cola,colc,colb from tab14,tab24 alias24":["TAB14","TAB24"],
"""
SELECT sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid
  FROM v$session sess,
	   v$sql     sql,
	   v$process proc
 WHERE sql.sql_id(+) = sess.sql_id
   AND sess.type     = 'USER'
   and sess.paddr = proc.addr
""":["V$PROCESS","V$SESSION","V$SQL"],
"""
SELECT distinct sess.sid, sess.username, sess.schemaname, proc.spid,pid,sess.osuser,sess.machine,sess.process,
sess.port,proc.terminal,sess.program,proc.tracefile
  FROM v$session sess,
	   v$process proc
 WHERE sess.type     = 'USER'
   and sess.paddr = proc.addr
""":["V$PROCESS","V$SESSION"],
"select tab1.cola,tab2.colb,tab3.colc from (select cola from tab1),(select colb from tab2),(select colc from tab3)":["TAB1","TAB2","TAB3"],
"select cola,tab2.colb,tab3.colc from (select cola from tab1),(select colb from tab2),(select colc from tab3)":["TAB1","TAB2","TAB3"],
"select ca,tab2.cb,tab3.cc from tab1,(select cb from tab2),(select cc from tab3)":["TAB1","TAB2","TAB3"],
"select alias25.cola,alias15.colb from tab11 alias15,(select colb from tab22) alias25":["TAB11","TAB22"],
"select cola,colb from (select colb from tab22) alias25,tab11 alias15":["TAB11","TAB22"],
"select cola,colb from (select colb from tab22) alias25,tab11":["TAB11","TAB22"],
"select cola,colb from (select colb from tab22),tab11 alias15":["TAB11","TAB22"],
"select cola,colb from (select colb from tab22),tab11":["TAB11","TAB22"],
"select cola,colb,colc from tab00,(select colb from tab22),tab11":["TAB00","TAB11","TAB22"],
"select cola,colb,colc,cold from tab00,(select colb from tab22),tab11,(select colb from tab33)":["TAB00","TAB11","TAB22","TAB33"],
"select cola,colb,colc,cold from (select cola from tab00),(select colb from tab22),tab11,(select colb from tab33)":["TAB00","TAB11","TAB22","TAB33"],
"select cola,colb,colc,cold from tab00,tab22,tab11,(select colb from tab33)":["TAB00","TAB11","TAB22","TAB33"],
"select b from a union (select c from d)": ["A","D"],
"select b from a intersect (select c from d)": ["A","D"],
"""
select K.a,K.b from (select H.b from (select G.c from (select F.d from
(select E.e from A, B, C, D, E), F), G), H), I, J, K order by 1,2;
""" : ["A","B","C","D","E","F","G","H","I","J","K"],
"SELECT * FROM table_name": ["TABLE_NAME"],
"SELECT EmployeeID, FirstName, LastName, HireDate, City FROM Employees": ["EMPLOYEES"],
"SELECT EmployeeID, FirstName, LastName, HireDate, City FROM Employees WHERE City = 'London'": ["EMPLOYEES"],
"SELECT EmployeeID, FirstName, LastName, HireDate, City FROM Employees WHERE HireDate >= '1-july-1993'": ["EMPLOYEES"],
"""
SELECT EmployeeID, FirstName, LastName, HireDate, City
FROM Employees WHERE (HireDate >= '1-june-1992') AND (HireDate <= '15-december-1993')
""": ["EMPLOYEES"],
"""
SELECT EmployeeID, FirstName, LastName, HireDate, City
FROM Employees WHERE HireDate BETWEEN '1-june-1992' AND '15-december-1993'
""": ["EMPLOYEES"],
"""
SELECT EmployeeID, FirstName, LastName, HireDate, City FROM Employees
WHERE City = 'London' OR City = 'Seattle'
""": ["EMPLOYEES"],
"""
SELECT EmployeeID, FirstName, LastName, HireDate, City FROM Employees
ORDER BY City
""": ["EMPLOYEES"],
"""
SELECT EmployeeID, FirstName, LastName, HireDate, Country, City FROM Employees
ORDER BY Country, City DESC
""": ["EMPLOYEES"],
"""
SELECT sub.*
  FROM (
        SELECT *
          FROM tutorial.sf_crime_incidents_2014_01
         WHERE day_of_week = 'Friday'
       ) sub
 WHERE sub.resolution = 'NONE'
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"""
SELECT *
  FROM tutorial.sf_crime_incidents_2014_01
 WHERE Date = (SELECT MIN(date)
                 FROM tutorial.sf_crime_incidents_2014_01
              )
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"""
SELECT *
  FROM tutorial.sf_crime_incidents_2014_01
 WHERE Date IN (SELECT date
                 FROM tutorial.sf_crime_incidents_2014_01
                ORDER BY date
                LIMIT 5
              )
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"""
SELECT *
  FROM tutorial.sf_crime_incidents_2014_01 incidents
  JOIN ( SELECT date
           FROM tutorial.sf_crime_incidents_2014_01
          ORDER BY date
          LIMIT 5
       ) sub
    ON incidents.date = sub.date
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"""
SELECT *
  FROM tutorial.sf_crime_incidents_2014_01
 WHERE Date IN (SELECT date
                 FROM tutorial.sf_crime_incidents_2014_01
                ORDER BY date
                LIMIT 5
              )
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"""
SELECT    EmployeeID, FirstName, LastName, HireDate, City FROM      Employees WHERE     HireDate =1
""": ["EMPLOYEES"],
"""
SELECT LEFT(sub.date, 2) AS cleaned_month,
       sub.day_of_week,
       AVG(sub.incidents) AS average_incidents
  FROM (
        SELECT day_of_week,
               date,
               COUNT(incidnt_num) AS incidents
          FROM tutorial.sf_crime_incidents_2014_01
         GROUP BY 1,2
       ) sub
 GROUP BY 1,2
 ORDER BY 1,2
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"select * from Students S JOIN dbo.Advisors A ON S.Advisor_ID=A.Advisor_ID":["DBO.ADVISORS","STUDENTS"],
"select * from Schema.Students S JOIN Advisors A ON S.Advisor_ID=A.Advisor_ID":["ADVISORS","SCHEMA.STUDENTS"],
"select * from Schema.Students JOIN Advisors ON Advisor_ID=Advisor_ID":["ADVISORS","SCHEMA.STUDENTS"],
"select * from Schema.Students S JOIN Advisors ON Advisor_ID=Advisor_ID":["ADVISORS","SCHEMA.STUDENTS"],
"select * from Schema.Students S , Advisors ON Advisor_ID=Advisor_ID":["ADVISORS","SCHEMA.STUDENTS"], # A bit invalid anyway.
"""
SELECT incidents.*,
       sub.incidents AS incidents_that_day
  FROM tutorial.sf_crime_incidents_2014_01 incidents
  JOIN ( SELECT date,
          COUNT(incidnt_num) AS incidents
           FROM tutorial.sf_crime_incidents_2014_01
          GROUP BY 1
       ) sub
    ON incidents.date = sub.date
 ORDER BY sub.incidents DESC, time
""": ["TUTORIAL.SF_CRIME_INCIDENTS_2014_01"],
"select * from Students S LEFT OUTER JOIN dbo.Advisors A ON S.Advisor_ID=A.Advisor_ID":["DBO.ADVISORS","STUDENTS"],
"select * from dbo.Students S LEFT OUTER JOIN dbo.Advisors A ON S.Advisor_ID=A.Advisor_ID":["DBO.ADVISORS","DBO.STUDENTS"],
"select * from dbo.Students S FULL OUTER JOIN dbo.Advisors A ON S.Advisor_ID=A.Advisor_ID where A.Advisor_ID is null or S.Student_ID is null": ["DBO.ADVISORS","DBO.STUDENTS"],
"select * from dbo.Students S FULL OUTER JOIN dbo.Advisors A ON S.Advisor_ID=A.Advisor_ID where A.Advisor_ID is null": ["DBO.ADVISORS","DBO.STUDENTS"],
"""
        SELECT acquired_month AS month,
               COUNT(DISTINCT company_permalink) AS companies_acquired
          FROM tutorial.crunchbase_acquisitions
         GROUP BY 1
""":["TUTORIAL.CRUNCHBASE_ACQUISITIONS"],
"""
        SELECT funded_month AS month,
               COUNT(DISTINCT company_permalink) AS companies_rec_investment
          FROM tutorial.crunchbase_investments
         GROUP BY 1
""":["TUTORIAL.CRUNCHBASE_INVESTMENTS"],
"""
SELECT COALESCE(acquisitions.month, investments.month) AS month,
       acquisitions.companies_acquired,
       investments.companies_rec_investment
  FROM (
        SELECT acquired_month AS month,
               COUNT(DISTINCT company_permalink) AS companies_acquired
          FROM tutorial.crunchbase_acquisitions
       ) acquisitions
  FULL JOIN (
        SELECT funded_month AS month,
               COUNT(DISTINCT company_permalink) AS companies_rec_investment
          FROM tutorial.crunchbase_investments
       )investments
    ON acquisitions.month = investments.month
""": ["TUTORIAL.CRUNCHBASE_ACQUISITIONS","TUTORIAL.CRUNCHBASE_INVESTMENTS"],
"""
SELECT department_id, MIN (salary)
FROM employees
GROUP BY department_id
HAVING MIN (salary)  < (SELECT AVG (salary)
			FROM employees)
""":["EMPLOYEES"],
"""
    SELECT column1 = (SELECT columnname FROM tablename WHERE condition),
           columnnames
      FROM tablename
     WHERE condition
""":["TABLENAME"],
"""
DELETE FROM student WHERE name = 'alan'
""":["STUDENT"],
"""
CREATE TABLE student (id INTEGER PRIMARY KEY , name TEXT, age INTEGER)
""":["STUDENT"],
"SELECT * FROM (SELECT salary, department_id FROM employees WHERE salary BETWEEN 1000 and 2000)":["EMPLOYEES"],
"select cola from tab14 where cold in (select c from tab140)":["TAB14","TAB140"],
"""
SELECT column-names FROM tablename1
WHERE value IN (SELECT column_name FROM tablename2 WHERE condition)
""":["TABLENAME1","TABLENAME2"],
"""
SELECT ProductName FROM Product
WHERE Id IN (SELECT ProductId FROM OrderItem WHERE Quantity > 100)
""":["ORDERITEM","PRODUCT"],
"""
SELECT first_name, salary, department_id
FROM employees WHERE salary = (SELECT MIN (salary) FROM employees)
""":["EMPLOYEES"],
"""
SELECT	first_name, department_id FROM employees
WHERE department_id IN (SELECT department_id
FROM departments WHERE LOCATION_ID = 100)
""":["DEPARTMENTS","EMPLOYEES"],
"""
SELECT EMPLOYEE_ID, salary, department_id FROM   employees E
WHERE salary > (SELECT AVG(salary)
FROM   EMP T WHERE E.department_id = T.department_id)
""":["EMP","EMPLOYEES"],
"""
SELECT first_name, job_id, salary
FROM emp_history
WHERE (salary, department_id) in (SELECT salary, department_id
FROM employees
WHERE salary BETWEEN 1000 and 2000
AND department_id BETWEEN 10 and 20)
ORDER BY first_name
""":["EMPLOYEES","EMP_HISTORY"],
"""
select emp_last_name from emp
where emp_salary < (select job_min_sal from job
where emp.job_key = job.job_key)
""":["EMP","JOB"],
"select book_key from book where exists (select book_key from sales)":["BOOK","SALES"],
"""
select book_title from book
where pub_key in (select pub_key from publisher
where publisher.pub_key = book.pub_key)
""":["BOOK","PUBLISHER"],
"""
select book_key from book
where book_key not in (select book_key from sales)
""":["BOOK","SALES"],
"""
SELECT ProductName, UnitPrice FROM Products
WHERE CategoryID In (SELECT CategoryID FROM Categories WHERE CategoryName = 'Condiments')
""":["CATEGORIES","PRODUCTS"],
"""
SELECT ProductName, UnitPrice FROM Products
INNER JOIN Categories ON Products.CategoryID = Categories.CategoryID
WHERE CategoryName = 'Condiments'
""":["CATEGORIES","PRODUCTS"],
"""
SELECT Products.ProductName, Products.UnitPrice FROM Products
WHERE (((Products.UnitPrice) > (SELECT AVG([UnitPrice]) From Products)))
ORDER BY Products.UnitPrice DESC;
""":["PRODUCTS"],
"""
SELECT song_name FROM Album
WHERE band_name = 'Metallica' AND song_name IN
(SELECT song_name FROM Lyric WHERE song_lyric LIKE '%justice%')
""":["ALBUM","LYRIC"],
"""
SELECT song_name FROM Album
WHERE album_name = 'And Justice for All' AND band_name = 'Metallica' AND song_name NOT IN
(SELECT song_name FROM Lyric WHERE song_lyric LIKE '%justice%')
""":["ALBUM","LYRIC"],
"""
SELECT Album.song_name FROM Album
WHERE Album.band_name = 'Metallica' AND EXISTS
(SELECT Cover.song_name FROM Cover WHERE Cover.band_name = 'Damage, Inc.' AND Cover.song_name = Album.song_name)
""":["ALBUM","COVER"],
"""
SELECT AlbumInfo.album_name FROM AlbumInfo
WHERE AlbumInfo.band_name = 'Metallica' AND album_tracks <> (SELECT COUNT(*) FROM Album WHERE Album.album_name = AlbumInfo.album_name)
""":["ALBUM","ALBUMINFO"],
"""
SELECT * FROM AlbumSales WHERE album_gross > ALL (SELECT album_costs FROM AlbumProduction)
""":["ALBUMPRODUCTION","ALBUMSALES"],
"""
SELECT suppliers.supplier_name, subquery1.total_amt
FROM suppliers,
(SELECT supplier_id, SUM(orders.amount) AS total_amt
FROM orders GROUP BY supplier_id) subquery1
WHERE subquery1.supplier_id = suppliers.supplier_id
""":["ORDERS","SUPPLIERS"],
"""
SELECT e1.last_name, e1.first_name,
(SELECT MAX(salary) FROM employees e2 WHERE e1.employee_id = e2.employee_id) subquery2
FROM employees e1
""":["EMPLOYEES"],
"""
SELECT cs.CUSID,dp.DEPID
FROM CUSTMR cs LEFT OUTER JOIN
( SELECT DEPID,DEPNAME
FROM DEPRMNT WHERE dp.DEPADDRESS = 'TOKYO' ) ss
ON ( ss.DEPID = cs.CUSID AND ss.DEPNAME = cs.CUSTNAME )
WHERE cs.CUSID != ''
""":["CUSTMR","DEPRMNT"],
"""
SELECT WORKDEPT, MAX(SALARY)
FROM DSN8A10.EMP
GROUP BY WORKDEPT
HAVING MAX(SALARY) < (SELECT AVG(SALARY) FROM DSN8A10.EMP)
""":["DSN8A10.EMP"],
"""
SELECT EMP_ACT.EMPNO, PROJNO
FROM EMP_ACT
WHERE EMP_ACT.EMPNO IN
(SELECT EMPLOYEE.EMPNO FROM EMPLOYEE ORDER BY SALARY DESC FETCH FIRST 3 ROWS ONLY)
""":["EMPLOYEE","EMP_ACT"],
"""
SELECT SalesOrderID, SalesOrderDetailID, LineTotal,
(SELECT AVG(LineTotal) FROM   Sales.SalesOrderDetail WHERE  SalesOrderID = SOD.SalesOrderID)
AS AverageLineTotal FROM   Sales.SalesOrderDetail SOD
""":["SALES.SALESORDERDETAIL"],
"""
SELECT CompanyName FROM Suppliers
WHERE EXISTS (SELECT * FROM Products p, Categories c
WHERE p.SupplierID = s.SupplierID AND p.CategoryID = c.CategoryID AND CategoryName LIKE '*Dairy*')
""":["CATEGORIES","PRODUCTS","SUPPLIERS"],
"""
SELECT SalesOrderID, OrderDate, TotalDue,
(SELECT COUNT(SalesOrderDetailID)
FROM Sales.SalesOrderDetail
WHERE SalesOrderID = SO.SalesOrderID) as LineCount
FROM   Sales.SalesOrderHeader SO
""":["SALES.SALESORDERDETAIL","SALES.SALESORDERHEADER"],
"""
SELECT SalesOrderID, OrderDate, TotalDue,
(SELECT COUNT(SalesOrderDetailID)
FROM Sales.SalesOrderDetail
WHERE SalesOrderID = SO.SalesOrderID)
FROM   Sales.SalesOrderHeader
""":["SALES.SALESORDERDETAIL","SALES.SALESORDERHEADER"],
"""
SELECT AlbumInfo.album_name, album_tracks,
(SELECT COUNT(*) FROM Album
WHERE Album.album_name = AlbumInfo.album_name)
FROM  AlbumInfo
WHERE AlbumInfo.band_name = 'Metallica'
""":["ALBUM","ALBUMINFO"],
"""
select
(select count(*) from taba where taba.col = maintab.maincol),
(select count(*) from tabb where tabb.col = maintab.maincol),
(select count(*) from tabc where tabc.col = maintab.maincol)
from maintab
where maintab.maincol like "%"
""":["MAINTAB","TABA","TABB","TABC"],
"""
SELECT SalesOrderID, OrderDate,
    (SELECT MAX(OrdDet.UnitPrice)
     FROM AdventureWorks.Sales.SalesOrderDetail
     WHERE SalesOrderID = OrdDet.SalesOrderID)
FROM AdventureWorks2008R2.Sales.SalesOrderHeader
""":["ADVENTUREWORKS.SALES.SALESORDERDETAIL","ADVENTUREWORKS2008R2.SALES.SALESORDERHEADER"],
"""
SELECT AlbumInfo.album_name, album_tracks,
(SELECT COUNT(*) FROM Album
WHERE Album.album_name = AlbumInfo.album_name)
FROM  AlbumInfo
WHERE AlbumInfo.band_name = 'Metallica'
""":["ALBUM","ALBUMINFO"],
"""
SELECT SalesOrderID,
LineTotal,
(SELECT AVG(LineTotal) FROM   Sales.SalesOrderDetail) AS AverageLineTotal, LineTotal - (SELECT AVG(LineTotal) FROM   Sales.SalesOrderDetail) AS Variance
FROM   Sales.SalesOrderDetail
""":["SALES.SALESORDERDETAIL"],
"""
SELECT FirstName, LastName,
OrderCount = (SELECT COUNT(O.Id) FROM Order O WHERE O.CustomerId = C.Id)
FROM Customer C
""":["CUSTOMER","ORDER"],
"""
SELECT Count(r.id)                       AS cnt_total,
   (SELECT Count(r1.entity_id)
    FROM   auto_reminders_members r1
    WHERE  r1.reminder_id = r.reminder_id
           AND r1.date_last_reminder BETWEEN CONVERT(DATETIME, '03/28/2013',
                                             101)
                                             AND
               CONVERT(DATETIME,
               '03/28/2013' + ' 23:59:59.997 ', 101)
           AND r1.action = 'notnow') AS cnt_notnow,
   (SELECT Count(r1.entity_id)
    FROM   auto_reminders_members r1
    WHERE  r1.reminder_id = r.reminder_id
           AND r1.date_last_reminder BETWEEN CONVERT(DATETIME, '03/28/2013',
                                             101)
                                             AND
               CONVERT(DATETIME,
               '03/28/2013' + ' 23:59:59.997 ', 101)
           AND r1.action = 'insert') AS cnt_insert,
   (SELECT Count(r1.entity_id)
    FROM   auto_reminders_members r1
    WHERE  r1.reminder_id = r.reminder_id
           AND r1.date_last_reminder BETWEEN CONVERT(DATETIME, '03/28/2013',
                                             101)
                                             AND
               CONVERT(DATETIME,
               '03/28/2013' + ' 23:59:59.997 ', 101)
           AND r1.action = 'update') AS cnt_update,
   (SELECT Count(r1.entity_id)
    FROM   auto_reminders_members r1
    WHERE  r1.reminder_id = r.reminder_id
           AND r1.date_last_reminder BETWEEN CONVERT(DATETIME, '03/28/2013',
                                             101)
                                             AND
               CONVERT(DATETIME,
               '03/28/2013' + ' 23:59:59.997 ', 101)
           AND r1.action = 'verify') AS cnt_verify
FROM   auto_reminders_members r
WHERE  r.reminder_id = 1
       AND r.date_last_reminder BETWEEN CONVERT(DATETIME, '03/28/2013', 101) AND
                                            CONVERT(DATETIME,
                                            '03/28/2013' + ' 23:59:59.997 ', 101
                                            )
GROUP  BY r.reminder_id
""":["AUTO_REMINDERS_MEMBERS"],
}






examples["Bad"] = {
"""
SELECT COALESCE(acquisitions.acquired_month, investments.funded_month) AS month,
       COUNT(DISTINCT acquisitions.company_permalink) AS companies_acquired,
       COUNT(DISTINCT investments.company_permalink) AS investments
  FROM tutorial.crunchbase_acquisitions acquisitions
  FULL JOIN tutorial.crunchbase_investments investments
    ON acquisitions.acquired_month = investments.funded_month
 GROUP BY 1
""": [],
"""
SELECT COUNT(*)
      FROM tutorial.crunchbase_acquisitions acquisitions
      FULL JOIN tutorial.crunchbase_investments investments
        ON acquisitions.acquired_month = investments.funded_month
""": [],
"""
SELECT COUNT(*) AS total_rows
  FROM (
        SELECT *
          FROM tutorial.crunchbase_investments_part1
         UNION ALL
        SELECT *
          FROM tutorial.crunchbase_investments_part2
       ) sub
""": [],
"""
SELECT *
  FROM tutorial.crunchbase_investments_part1
 UNION ALL
 SELECT *
   FROM tutorial.crunchbase_investments_part2
""": [],
"""
SELECT CompanyName FROM Suppliers AS s
WHERE EXISTS (SELECT * FROM Products p, Categories c
WHERE p.SupplierID = s.SupplierID AND p.CategoryID = c.CategoryID AND CategoryName LIKE '*Dairy*')
""":["CATEGORIES","PRODUCTS","SUPPLIERS"],
"""
UPDATE AlbumInfo SET album_tracks =
SELECT COUNT(*) FROM Album
WHERE AlbumInfo.album_name = Album.album_name)
WHERE AlbumInfo.band_name = 'Metallica'
""":["ALBUM","ALBUMINFO"],
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2 ORDER BY 1) ) AS UTABLE
ORDER BY ORDER OF UTABLE
""":["T1","T2"],
"""
SELECT Count(r.id) AS cnt_total,
  SUM(CASE WHEN r1.action = 'notnow') THEN 1 ELSE 0 END) AS cnt_notnow,
  SUM(CASE WHEN r1.action = 'insert') THEN 1 ELSE 0 END) AS cnt_insert,
  SUM(CASE WHEN r1.action = 'update') THEN 1 ELSE 0 END) AS cnt_update,
  SUM(CASE WHEN r1.action = 'verify') THEN 1 ELSE 0 END) AS cnt_verify,

FROM   auto_reminders_members r
WHERE  r.reminder_id = 1
       AND r.date_last_reminder BETWEEN CONVERT(DATETIME, '03/28/2013', 101) AND
                                            CONVERT(DATETIME,
                                            '03/28/2013' + ' 23:59:59.997 ', 101
                                            )
GROUP  BY r.reminder_id
""":["AUTO_REMINDERS_MEMBERS"],
"""
SELECT Ord.SalesOrderID, Ord.OrderDate,
    (SELECT MAX(OrdDet.UnitPrice)
     FROM AdventureWorks.Sales.SalesOrderDetail AS OrdDet
     WHERE Ord.SalesOrderID = OrdDet.SalesOrderID) AS MaxUnitPrice
FROM AdventureWorks2008R2.Sales.SalesOrderHeader AS Ord
""":["ADVENTUREWORKS.SALES.SALESORDERDETAIL","ADVENTUREWORKS.SALES.SALESORDERHEADER"],
}

examples["Focus"] = {
}

def DisplayErrs(theDictNam,theDict):
	errnum = 0
	for sqlQry in theDict:
		print("\nQUERY="+sqlQry+"\n")
		resuXX = theDict[sqlQry]
		resVec = lib_sql.extract_sql_tables(sqlQry)
		resVec = [ s.upper() for s in resVec]
		vecUp = resVec
		vecUp.sort()
		if resuXX != vecUp:
			errnum += 1
			# print("QQQQQQQQQQQQQQQ="+sqlQry)
			print("Should be="+str(resuXX))
			# print("Actual is="+str(resVec))
			print("Sorted is="+str(vecUp))
			print("")
			print("")

	lenTot = len(theDict)
	print("Finished "+theDictNam+" with "+str(errnum)+" errors out of "+str(lenTot))

import sys
if len(sys.argv) == 1:
	for key in examples:
		print(key)
		DisplayErrs(key,examples[key])
else:
	for a in sys.argv[1:]:
		print(a)
		DisplayErrs(a,examples[a])

print("Fini")
