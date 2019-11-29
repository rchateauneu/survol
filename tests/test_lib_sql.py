#!/usr/bin/env python

from __future__ import print_function

# sys.path.insert(1,r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\revlib')

import unittest

from init import *

update_test_path()

import lib_sql

################################################################################


query_examples = dict()

query_examples["NoSelect"] = {
"INSERT INTO table (nom_colonne_1, nom_colonne_2) VALUES ('valeur 1', 'valeur 2')" : ["TABLE"],
"""
DELETE FROM student WHERE name = 'alan'
""":["STUDENT"],
"""
CREATE TABLE student (id INTEGER PRIMARY KEY , name TEXT, age INTEGER)
""":["STUDENT"],
"""
INSERT INTO USER_TABLE VALUES ('Perry', 'Jonathan')
""" : ["USER_TABLE"],
"""
CREATE TABLE USER_TABLE
(Userid int PRIMARY KEY IDENTITY(2,1),
Last_Name nvarchar(50),
First_Name nvarchar(50))
""" : ["USER_TABLE"],
"""
DELETE FROM Store_Information
WHERE Store_Name = 'Los Angeles'
""" : ["STORE_INFORMATION"],
"""
UPDATE Store_Information
SET Sales = 500
WHERE Store_Name = 'Los Angeles'
AND Txn_Date = 'Jan-08-1999'
""" : ["STORE_INFORMATION"],
}


query_examples["Good"] = {
"select aa from bb": ["BB"],
"select b from a": ["A"],
"select b*(b+1) from a": ["A"],
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
HAVING MIN (salary)  < (SELECT AVG (salary) FROM employees)
""":["EMPLOYEES"],
"""
SELECT column1 = (SELECT columnname FROM tablename WHERE condition), columnnames
FROM tablename
WHERE condition
""":["TABLENAME"],
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
"""
select distinct a.CustomerID, a.CompanyName
from customers as a
inner join orders as b
on a.CustomerID = b.CustomerID
where b.ShipCountry = 'UK'
""":["CUSTOMERS","ORDERS"],
"""
select distinct a.CustomerID, a.CompanyName
from customers as a
left join orders as b on a.CustomerID = b.CustomerID
where b.ShipCountry = 'UK' or b.ShipCountry is null
""":["CUSTOMERS","ORDERS"],
"""
select distinct a.ProductID, a.UnitPrice as Max_unit_price_sold
from order_details as a
inner join
(
    select ProductID, max(UnitPrice) as Max_unit_price_sold
    from order_details
    group by ProductID
) as b
on a.ProductID=b.ProductID and a.UnitPrice=b.Max_unit_price_sold
order by a.ProductID
""":["ORDER_DETAILS"],
"""
select distinct a.ProductID,
       p.ProductName,
       a.UnitPrice as Max_unit_price_sold
from order_details as a
inner join products as p on a.ProductID = p.ProductID
where a.UnitPrice =
(
    select max(UnitPrice)
    from order_details as b
    where a.ProductID = b.ProductID
)
order by a.ProductID
""":["ORDER_DETAILS","PRODUCTS"],
"""
select distinct a.ProductID, a.UnitPrice as Max_unit_price_sold
from order_details as a
inner join
(
    select ProductID, max(UnitPrice) as Max_unit_price_sold
    from order_details
    group by ProductID
) as b
on a.ProductID=b.ProductID and a.UnitPrice=b.Max_unit_price_sold
order by a.ProductID
""":["ORDER_DETAILS"],
"""
SELECT Ord.SalesOrderID, Ord.OrderDate,
    (SELECT MAX(OrdDet.UnitPrice)
     FROM AdventureWorks.Sales.SalesOrderDetail AS OrdDet
     WHERE Ord.SalesOrderID = OrdDet.SalesOrderID) AS MaxUnitPrice
FROM AdventureWorks2008R2.Sales.SalesOrderHeader AS Ord
""":["ADVENTUREWORKS.SALES.SALESORDERDETAIL","ADVENTUREWORKS2008R2.SALES.SALESORDERHEADER"],
"""
select x.ProductID,
    y.ProductName,
    x.max_unit_price
from
(
    select ProductID, max(UnitPrice) as max_unit_price
    from order_details
    group by ProductID
) as x
inner join products as y on x.ProductID = y.ProductID
""":["ORDER_DETAILS","PRODUCTS"],
"""
select ProductID,
       ProductName,
       concat((UnitsInStock / (select sum(UnitsInStock) from products))*100, '%')
       as Percent_of_total_units_in_stock
from products
order by ProductID
""":["PRODUCTS"],
"""
select ProductID,
       ProductName,
       concat((UnitsInStock / 3119)*100, '%')
       as Percent_of_total_units_in_stock
from products
order by ProductID
""":["PRODUCTS"],
"""
select CustomerID, CompanyName
from customers as a
where not exists
(
    select * from orders as b
    where a.CustomerID = b.CustomerID
    and ShipCountry <> 'UK'
)
""":["CUSTOMERS","ORDERS"],
"""
select CustomerID, CompanyName
from customers
where CustomerID in
(
    'BONAP',
    'DRACD',
    'ERNSH',
    'LEHMS',
    'LILAS',
    'PERIC',
    'QUEEN',
    'RATTC',
    'RICSU',
    'SIMOB',
    'TORTU'
)
""":["CUSTOMERS"],
"""
select a.OrderID,
       a.CustomerID
from orders as a
where
(
    select Quantity
    from order_details as b
    where a.OrderID = b.OrderID and b.ProductID = 6
) > 20
""":["ORDERS","ORDER_DETAILS"],
"""
select CustomerID, CompanyName
from customers as a
where exists
(
    select * from orders as b
    where a.CustomerID = b.CustomerID
    and ShipCountry = 'UK'
)
""":["CUSTOMERS","ORDERS"],
"""
select CustomerID, CompanyName
from customers
where CustomerID in
(
   select CustomerID
   from orders
   where orderDate > '1998-05-01'
)
""":["CUSTOMERS","ORDERS"],
"""
select EmployeeID, FirstName, LastName, City, Country
from employees
where row(City, Country) in
(select City, Country from customers)
""":["CUSTOMERS","EMPLOYEES"],
"""
select distinct ProductID, UnitPrice as Max_unit_price_sold
from order_details
where row(ProductID, UnitPrice) in
(
    select ProductID, max(UnitPrice)
    from order_details
    group by ProductID
)
order by ProductID
""":["ORDER_DETAILS"],
"""
SELECT CompanyName FROM Suppliers AS s
WHERE EXISTS (SELECT * FROM Products p, Categories c
WHERE p.SupplierID = s.SupplierID AND p.CategoryID = c.CategoryID AND CategoryName LIKE '*Dairy*')
""":["CATEGORIES","PRODUCTS","SUPPLIERS"],
"""
select distinct a.ProductID,
       a.UnitPrice as Max_unit_price_sold
from order_details as a
where a.UnitPrice =
(
    select max(UnitPrice)
    from order_details as b
    where a.ProductID = b.ProductID
)
order by a.ProductID
""":["ORDER_DETAILS"],
"""
SELECT SUM (Sales) FROM Store_Information
WHERE Store_Name IN
(SELECT Store_Name FROM Geography
WHERE Region_Name = 'West')
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"""
SELECT SUM (a1.Sales) FROM Store_Information a1
WHERE a1.Store_Name IN
(SELECT Store_Name FROM Geography a2
WHERE a2.Store_Name = a1.Store_Name)
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"""
SELECT DECODE (Store_Name,
  'Los Angeles', 'LA',
  'San Francisco', 'SF',
  'San Diego', 'SD',
  'Others') Area, Sales, Txn_Date
FROM Store_Information
""" : ["STORE_INFORMATION"],
"""
SELECT a1.Name, a1.Sales, COUNT (a2.Sales) Sales_Rank
FROM Total_Sales a1, Total_Sales a2
WHERE a1.Sales < a2.Sales OR (a1.Sales=a2.Sales AND a1.Name = a2.Name)
GROUP BY a1.Name, a1.Sales
ORDER BY a1.Sales DESC, a1.Name DESC
""" : ["TOTAL_SALES"],
"""
SELECT Sales Median FROM
(SELECT a1.Name, a1.Sales, COUNT(a1.Sales) Rank
FROM Total_Sales a1, Total_Sales a2
WHERE a1.Sales < a2.Sales OR (a1.Sales=a2.Sales AND a1.Name <= a2.Name)
group by a1.Name, a1.Sales
order by a1.Sales desc) a3
WHERE Rank = (SELECT (COUNT(*)+1) DIV 2 FROM Total_Sales)
""" : ["TOTAL_SALES"],
"""
SELECT a1.Name, a1.Sales, SUM(a2.Sales) Running_Total
FROM Total_Sales a1, Total_Sales a2
WHERE a1.Sales <= a2.sales or (a1.Sales=a2.Sales and a1.Name = a2.Name)
GROUP BY a1.Name, a1.Sales
ORDER BY a1.Sales DESC, a1.Name DESC
""" : ["TOTAL_SALES"],
"""
SELECT a1.Name, a1.Sales, a1.Sales/(SELECT SUM(Sales) FROM Total_Sales) Pct_To_Total
FROM Total_Sales a1, Total_Sales a2
WHERE a1.Sales <= a2.sales or (a1.Sales=a2.Sales and a1.Name = a2.Name)
GROUP BY a1.Name, a1.Sales
ORDER BY a1.Sales DESC, a1.Name DESC
""" : ["TOTAL_SALES"],
"""
SELECT a1.Name, a1.Sales, SUM(a2.Sales)/(SELECT SUM(Sales) FROM Total_Sales) Pct_To_Total
FROM Total_Sales a1, Total_Sales a2
WHERE a1.Sales <= a2.sales or (a1.Sales=a2.Sales and a1.Name = a2.Name)
GROUP BY a1.Name, a1.Sales
ORDER BY a1.Sales DESC, a1.Name DESC
""" : ["TOTAL_SALES"],
"""
SELECT A1.Store_Name, SUM(A2.Sales) SALES
FROM Geography A1, Store_Information A2
WHERE A1.Store_Name = A2.Store_Name (+)
GROUP BY A1.Store_Name
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"""
SELECT A1.Store_Name STORE1, A2.Store_Name STORE2, A2.Sales SALES
FROM Geography A1
JOIN Store_Information A2
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"""
SELECT Store_Name, Sales, Txn_Date
FROM Store_Information
ORDER BY Sales DESC
LIMIT 2
""" : ["STORE_INFORMATION"],
"""
SELECT SUM (Sales) FROM Store_Information
WHERE Store_Name IN
(SELECT Store_Name FROM Geography
WHERE Region_Name = 'West')
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"""
SELECT SUM (a1.Sales) FROM Store_Information a1
WHERE a1.Store_Name IN
(SELECT Store_Name FROM Geography a2
WHERE a2.Store_Name = a1.Store_Name)
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"""
SELECT A1.Store_Name Store, SUM(A1.Sales) AS "Total Sales"
FROM Store_Information AS A1
GROUP BY A1.Store_Name
""" : ["STORE_INFORMATION"],
"""
SELECT Store_Name, SUM(Sales)
FROM Store_Information
GROUP BY Store_Name
HAVING SUM(Sales) > 1500
""" : ["STORE_INFORMATION"],
"""
SELECT Txn_Date FROM Store_Information
INTERSECT
SELECT Txn_Date FROM Internet_Sales
""" : ["INTERNET_SALES","STORE_INFORMATION"],
"""
SELECT Txn_Date FROM Store_Information
MINUS
SELECT Txn_Date FROM Internet_Sales
""" : ["INTERNET_SALES","STORE_INFORMATION"],
"""
SELECT COUNT(*)
      FROM tutorial.crunchbase_acquisitions acquisitions
      FULL JOIN tutorial.crunchbase_investments investments
        ON acquisitions.acquired_month = investments.funded_month
""": ["TUTORIAL.CRUNCHBASE_ACQUISITIONS","TUTORIAL.CRUNCHBASE_INVESTMENTS"],
"""
SELECT COALESCE(acquisitions.acquired_month, investments.funded_month) AS month,
       COUNT(DISTINCT acquisitions.company_permalink) AS companies_acquired,
       COUNT(DISTINCT investments.company_permalink) AS investments
  FROM tutorial.crunchbase_acquisitions acquisitions
  FULL JOIN tutorial.crunchbase_investments investments
    ON acquisitions.acquired_month = investments.funded_month
 GROUP BY 1
""": ["TUTORIAL.CRUNCHBASE_ACQUISITIONS","TUTORIAL.CRUNCHBASE_INVESTMENTS"],
"""
SELECT wpoi.order_id As No_Commande
FROM  wp_woocommerce_order_items AS wpoi
LEFT JOIN wp_postmeta AS wpp ON wpoi.order_id = wpp.post_id
                            AND wpp.meta_key = '_shipping_first_name'
WHERE  wpoi.order_id =2198
""":["WP_POSTMETA","WP_WOOCOMMERCE_ORDER_ITEMS"],
"""
select y.CategoryID,
    y.CategoryName,
    round(x.actual_unit_price, 2) as \"Actual Avg Unit Price\",
    round(y.planned_unit_price, 2) as \"Would-Like Avg Unit Price\"
from
(
    select avg(a.UnitPrice) as actual_unit_price, c.CategoryID
    from order_details as a
    inner join products as b on b.ProductID = a.ProductID
    inner join categories as c on b.CategoryID = c.CategoryID
    group by c.CategoryID
) as x
inner join
(
    select a.CategoryID, b.CategoryName, avg(a.UnitPrice) as planned_unit_price
    from products as a
    inner join categories as b on b.CategoryID = a.CategoryID
    group by a.CategoryID
) as y on x.CategoryID = y.CategoryID
""":["CATEGORIES","ORDER_DETAILS","PRODUCTS"],
"""
SELECT Store_Name, CASE Store_Name
  WHEN 'Los Angeles' THEN Sales * 2
  WHEN 'San Diego' THEN Sales * 1.5
  ELSE Sales
  END
'New Sales',Txn_Date FROM Store_Information
""" : ["STORE_INFORMATION"],
"""
SELECT COUNT(*) AS total_rows
  FROM (
        SELECT *
          FROM tutorial.crunchbase_investments_part1
         UNION ALL
        SELECT *
          FROM tutorial.crunchbase_investments_part2
       ) sub
""": ["TUTORIAL.CRUNCHBASE_INVESTMENTS_PART1","TUTORIAL.CRUNCHBASE_INVESTMENTS_PART2"],
"""
SELECT A1.Store_Name, SUM(A2.Sales) SALES
FROM Geography A1, Store_Information A2
WHERE A1.Store_Name = A2.Store_Name (+)
GROUP BY A1.Store_Name
""" : ["GEOGRAPHY","STORE_INFORMATION"],
"select cola,colb from (select colb from tab22) alias25,tab11 alias15":["TAB11","TAB22"],
"""
SELECT *
  FROM tutorial.crunchbase_investments_part1
 UNION ALL
 SELECT *
   FROM tutorial.crunchbase_investments_part2
""": ["TUTORIAL.CRUNCHBASE_INVESTMENTS_PART1","TUTORIAL.CRUNCHBASE_INVESTMENTS_PART2"],
"""
SELECT Txn_Date FROM Store_Information
UNION ALL
SELECT Txn_Date FROM Internet_Sales
""" : ["INTERNET_SALES","STORE_INFORMATION"],
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2 ORDER BY 1) ) AS UTABLE
ORDER BY ORDER OF UTABLE
""":["T1","T2"],
"""
UPDATE AlbumInfo SET album_tracks =
SELECT COUNT(*) FROM Album
WHERE AlbumInfo.album_name = Album.album_name)
WHERE AlbumInfo.band_name = 'Metallica'
""":["ALBUM","ALBUMINFO"],
"""
UPDATE Sales_Import
SET Sales_Import.AccountNumber = RAN.AccountNumber
FROM Sales_Import SI
INNER JOIN RetrieveAccountNumber RAN
ON SI.LeadID = RAN.LeadID
""":["RETRIEVEACCOUNTNUMBER","SALES_IMPORT"],
"""
UPDATE Sales_Import SI, RetrieveAccountNumber RAN
SET SI.AccountNumber = RAN.AccountNumber
WHERE SI.LeadID = RAN.LeadID
""":["RETRIEVEACCOUNTNUMBER","SALES_IMPORT"],
"""
update foo set    foo.new = (select bar.new
from bar where foo.key = bar.key)
where exists (select 1
from bar where foo.key = bar.key)
""":["BAR","FOO"],
"""
UPDATE Sales_Import SI,RetrieveAccountNumber RAN
SET SI.AccountNumber = RAN.AccountNumber
WHERE SI.LeadID = RAN.LeadID
""":["RETRIEVEACCOUNTNUMBER","SALES_IMPORT"],
"""
UPDATE Sales_Import SI
SET AccountNumber = RAN.AccountNumber
FROM RetrieveAccountNumber RAN
WHERE RAN.LeadID = SI.LeadID
""":["RETRIEVEACCOUNTNUMBER","SALES_IMPORT"],
"""
UPDATE Sales_Import
SET    AccountNumber = (SELECT RetrieveAccountNumber.AccountNumber
FROM   RetrieveAccountNumber
WHERE  Sales_Import.leadid =RetrieveAccountNumber.LeadID)
WHERE Sales_Import.leadid = (SELECT  RetrieveAccountNumber.LeadID
FROM   RetrieveAccountNumber
WHERE  Sales_Import.leadid = RetrieveAccountNumber.LeadID)
""":["RETRIEVEACCOUNTNUMBER","SALES_IMPORT"],
"""
UPDATE application SET omts_received_date =
(SELECT date_created FROM application_history
WHERE application.id = application_history.application_id AND application_history.application_status_id = 8)
""":["APPLICATION","APPLICATION_HISTORY"],
"""
UPDATE table1 SET table1.column = 'some_new_val' WHERE table1.id IN (
SELECT * FROM (
SELECT table1.id FROM  table1
LEFT JOIN table2 ON ( table2.column = table1.column )
WHERE table1.column = 'some_expected_val'
AND table12.column IS NULL
) AS Xalias )
""":["TABLE1","TABLE2"],
"""
UPDATE table1 SET table1.column = 'some_new_val' WHERE table1.id IN (
SELECT *
FROM ( SELECT table1.id FROM  table1 JOIN table2 ON ( table2.column = table1.column )
		WHERE table1.column = 'some_expected_val'
) AS Xalias )
""":["TABLE1","TABLE2"],
"""
UPDATE Table1 t1, Table2 t2
SET t1.column = t2.column WHERE t1.ID = t2.ID
""":["TABLE1","TABLE2"],
"""
UPDATE TableOne
SET
field1 =(SELECT TableTwo.field1 FROM TableTwo WHERE TableOne.id=TableTwo.id),
field2 =(SELECT TableTwo.field2 FROM TableTwo WHERE TableOne.id=TableTwo.id)
WHERE TableOne.id = (SELECT  TableTwo.id
FROM   TableTwo
WHERE  TableOne.id = TableTwo.id)
""":["TABLEONE","TABLETWO"],
"""
DELETE FROM WorkRecord2
       FROM Employee
Where EmployeeRun=EmployeeNo
      And Company = '1'
      AND Date = '2013-05-06'
""":["EMPLOYEE","WORKRECORD2"],
"""
DELETE zpost
FROM zpost
INNER JOIN zcomment ON (zpost.zpostid = zcomment.zpostid)
WHERE zcomment.icomment = "first"
""":["ZCOMMENT","ZPOST"],
"""
DELETE Contact
FROM Contact
INNER JOIN Bedrijf ON Bedrijf.IDBedrijf = Contact.IDbedrijf
""":["BEDRIJF","CONTACT"],
"""
DELETE subscribers, subscriptions
         FROM subscribers INNER JOIN subscriptions
           ON subscribers.id = subscriptions.subscriber_id
         INNER JOIN magazines
           ON subscriptions.magazine_id = magazines.id
         WHERE subscribers.name='Wes';
""":["MAGAZINES","SUBSCRIBERS","SUBSCRIPTIONS"],
"""
DELETE offices, employees
FROM offices
INNER JOIN employees
      ON employees.officeCode = employees.officeCode
WHERE offices.officeCode = 5
""":["EMPLOYEES","OFFICES"],
"""
DELETE T1
FROM T1
LEFT JOIN T2 ON T1.key = T2.key
WHERE T2.key IS NULL
""":["T1","T2"],
"""
DELETE customers
FROM customers
LEFT JOIN orders ON customers.customerNumber = orders.customerNumber
WHERE orderNumber IS NULL
""":["CUSTOMERS","ORDERS"],
"""
DELETE Table1
FROM Table1 t1
INNER JOIN Table2 t2 ON t1.Col1 = t2.Col1
WHERE t2.Col3 IN ('Two-Three','Two-Four')
""":["TABLE1","TABLE2"],
"""
DELETE *
FROM Employees
WHERE DeptNo IN
  (SELECT DeptNo
  FROM Departments
  WHERE LCase(DeptName) LIKE '*sales*')
""":["DEPARTMENTS","EMPLOYEES"],
"""
DELETE a.*
FROM Employees AS a INNER JOIN Departments AS b
ON a.DeptNo = b.DeptNo
WHERE LCase(b.DeptName) LIKE '*sales*'
""":["DEPARTMENTS","EMPLOYEES"],
"""
DELETE a
FROM Employees AS a INNER JOIN Departments AS b
ON a.DeptNo = b.DeptNo
WHERE LOWER(b.DeptName) LIKE '%sales%'
""":["DEPARTMENTS","EMPLOYEES"],
"""
DELETE a
FROM Table1 AS a INNER JOIN Table2 AS b
ON a.id = b.id
""":["TABLE1","TABLE2"],
"""
SELECT name, count(*) AS name_count
FROM
(
  SELECT LCase(Trim(FirstName))& ' ' & LCase(Trim(LastName)) AS Name
  FROM Employees
   UNION ALL
  SELECT LCase(Trim(CustomerName)) AS Name
  FROM Customers
) AS a
GROUP BY name
""":["CUSTOMERS","EMPLOYEES"],
"""
SELECT name, count(*) AS name_count
FROM
(
  SELECT Lower(RTrim(FirstName))+ ' ' + Lower(RTrim(LastName)) AS name
  FROM Employees
   UNION ALL
  SELECT Lower(RTrim(CustomerName)) AS name
  FROM Customers
) AS a
GROUP BY name
""":["CUSTOMERS","EMPLOYEES"],
"""
SELECT a.EmpNo, TRIM(a.FirstName) & ' ' & TRIM(a.LastName) AS EmpName, SUM(b.Salary) AS TotalMoney
FROM Employees AS a INNER JOIN Employees AS b ON a.EmpNo=b.ManagerNo
GROUP BY a.EmpNo, TRIM(a.FirstName) & ' ' & TRIM(a.LastName)
ORDER BY SUM(b.Salary) DESC
""":["EMPLOYEES"],
"""
DELETE * FROM Clients WHERE remove_this = 1
""":["CLIENTS"],
"""
DELETE a.*
FROM Clients AS a INNER JOIN tmp_Min_Idno AS b ON a.CustomerID = b.CustomerID
WHERE a.idno <> b.min_id
""":["CLIENTS","TMP_MIN_IDNO"],
"""
UPDATE Clients AS a INNER JOIN tmp_Min_Idno AS b
ON a.CustomerID=b.CustomerID
SET a.remove_this = 1
WHERE a.idno <> b.min_id
""":["CLIENTS","TMP_MIN_IDNO"],
"""
SELECT City_EN, count(*) AS cn
FROM
(
  SELECT City_EN, City_IT
  FROM Address_Table
  GROUP BY City_EN, City_IT
) AS a
GROUP BY City_EN HAVING count(*) > 1
""":["ADDRESS_TABLE"],
"""
SELECT c.*
FROM Address_Table AS c INNER JOIN
(
  SELECT City_EN, count(*) AS cn
  FROM
  (
    SELECT City_EN, City_IT
    FROM Address_Table
    GROUP BY City_EN, City_IT
  ) AS a
  GROUP BY City_EN HAVING count(*) > 1
) AS b ON c.City_EN = b.City_EN
ORDER BY c.City_EN, c.City_IT
""":["ADDRESS_TABLE"],
"""
SELECT a.CustomerID, c.CustomerName, c.phone1
FROM ((Invoice AS a INNER JOIN InvLines AS b ON a.DocKey=b.DocKey)
INNER JOIN Customers AS c ON a.CustomerID = c.CustomerID)
INNER JOIN
(
SELECT a.ItemCode
FROM (InvLines AS a INNER JOIN Invoice AS b ON a.DocKey=b.DocKey)
INNER JOIN Customers AS c ON b.CustomerID = c.CustomerID
WHERE c.CustomerName = 'John Depp'
GROUP BY a.ItemCode
) AS d
ON b.ItemCode = d.ItemCode
WHERE c.CustomerName <> 'John Depp'
GROUP BY a.CustomerID, c.CustomerName, c.phone1
""":["CUSTOMERS","INVLINES","INVOICE"],
"""
SELECT a.CustomerID, c.CustomerName, c.phone1
FROM (Invoice AS a INNER JOIN InvLines AS b ON a.DocKey = b.DocKey)
INNER JOIN Customers AS c ON a.CustomerID = c.CustomerID
WHERE c.CustomerName <> 'John Depp' AND b.ItemCode IN
(
SELECT a.ItemCode
FROM (InvLines AS a INNER JOIN Invoice AS b ON a.DocKey = b.DocKey)
INNER JOIN Customers AS c ON b.CustomerID = c.CustomerID
WHERE c.CustomerName = 'John Depp'
GROUP BY a.ItemCode
)
GROUP BY a.CustomerID, c.CustomerName, c.phone1
""":["CUSTOMERS","INVLINES","INVOICE"],
"""
DELETE
FROM    guide_category AS gc
WHERE   id_guide NOT IN
        (
        SELECT  id_guide
        FROM    guide
        )
""":["GUIDE","GUIDE_CATEGORY"],
"""
DELETE guide_category
  WHERE id_guide_category IN (
        SELECT id_guide_category
          FROM guide_category AS gc
     LEFT JOIN guide AS g
            ON g.id_guide = gc.id_guide
         WHERE g.title IS NULL
  )
""":["GUIDE","GUIDE_CATEGORY"],
"""
DELETE
FROM Contacts
FROM Contacts, Customers
WHERE Contacts.Surname = Customers.Surname
AND Contacts.GivenName = Customers.GivenName
""":["CONTACTS","CUSTOMERS"],
}


query_examples["Bad"] = {
"""
SELECT MIN(a.idno) AS min_id, a.CustomerID
  INTO tmp_Min_Idno
FROM
  (SELECT idno, CustomerID FROM Clients) AS a
    INNER JOIN
  (SELECT CustomerID, count(*) AS cn
   FROM Clients GROUP BY CustomerID
   HAVING count(*) > 1) AS b
ON a.CustomerID=b.CustomerID
GROUP BY a.CustomerID
""":["CLIENTS","TMP_MIN_IDNO"],
"""
DELETE a
FROM \"dbo\".\"DM_ConformedPerson\" a
JOIN \"dbo\".\"TST_Fix_DM_ConformedPerson\" z
ON a.\"Person_SK\" = z.\"Person_SK\"
WHERE z.\"Person_SK\" <> z.\"MaxSK\"
""":["\"dbo\".\"DM_ConformedPerson\""],
"""
DELETE TOP (5) o
FROM #orders o
JOIN #customers c
    ON c.customer_id = o.customer_id
WHERE c.last_name = 'jones'
AND c.first_name = 'alexandria'
""":["#CUSTOMERS","#ORDERS"],
"""
DELETE pgc
     FROM guide_category pgc
LEFT JOIN guide g
       ON g.id_guide = gc.id_guide
    WHERE g.id_guide IS NULL
""":[],
"""
DELETE px
FROM #prodextend px
INNER JOIN #product p ON p.din = px.din
AND p.pkgSize = px.pkgSize
INNER JOIN #manu_clients mc ON mc.clientCode = p.clientCode
""":[],
"""
DROP TABLE Table1
""":["TABLE1"],
"""
UPDATE t1 SET t1.column = t2.column
FROM Table1 t1 INNER JOIN Table2 t2 ON t1.id = t2.id
""":["TABLE1","TABLE2"],
"""
UPDATE t1 SET t1.colmun = t2.column
FROM Table1 t1, Table2 t2 WHERE t1.ID = t2.ID
""":["TABLE1","TABLE2"],
"""
MERGE INTO Sales_Import
   USING RetrieveAccountNumber
      ON Sales_Import.LeadID = RetrieveAccountNumber.LeadID
WHEN MATCHED THEN
   UPDATE
      SET AccountNumber = RetrieveAccountNumber.AccountNumber
""":[],
"SELECT * FROM table_name": ["TABLE_NAME"],
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
"""
SELECT FirstName, LastName,
OrderCount = (SELECT COUNT(O.Id) FROM Order O WHERE O.CustomerId = C.Id)
FROM Customer C
""":["CUSTOMER","ORDER"],
"""
UPDATE AlbumInfo SET album_tracks =
SELECT COUNT(*) FROM Album
WHERE AlbumInfo.album_name = Album.album_name)
WHERE AlbumInfo.band_name = 'Metallica'
""":["ALBUM","ALBUMINFO"],
"""
INSERT INTO Store_Information (Store_Name, Sales, Txn_Date)
SELECT Store_Name, SUM(Sales), Txn_Date
FROM Sales_Data
GROUP BY Store_Name, Txn_Date
""" : ["SALES_DATA","STORE_INFORMATION"],
"""
SELECT sqltext.TEXT,
req.session_id,
req.status,
sess.host_process_id,
sess.host_name
FROM sys.dm_exec_requests req
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
, sys.dm_exec_sessions sess
where sess.session_id = req.session_id
""" : ["SYS.DM_EXEC_REQUESTS","SYS.DM_EXEC_SESSIONS","SYS.DM_EXEC_SQL_TEXT"],
}

################################################################################

query_examples["Focus"] = {
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2 ORDER BY 1) ) AS UTABLE
ORDER BY ORDER OF UTABLE
""":["T1","T2"],
"""
SELECT *
FROM (SELECT * FROM T1 )
""":["T1"],
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2 ORDER BY 1) )
""":["T1","T2"],
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2) )
""":["T1","T2"],
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2 UNION ALL (SELECT * FROM T3) ) )
""":["T1","T2","T3"],
"""
SELECT *
FROM (SELECT * FROM T1 UNION ALL (SELECT * FROM T2 UNION ALL (SELECT * FROM T3  UNION ALL (SELECT * FROM T4)) ) )
""":["T1","T2","T3","T4"],
"""
INSERT OR IGNORE INTO groups (id, name)
""":["GROUPS"],
"""
INSERT OR REPLACE INTO daily_counters VALUES ()
""":["DAILY_COUNTERS"],
}

################################################################################
# TODO: We should make the difference between input and output tables.

################################################################################

################################################################################

# if len(sys.argv) == 1:
# 	for key in examples:
# 		print(key)
# 		DisplayTablesAny(key,examples[key])
# else:
# 	for a in sys.argv[1:]:
# 		print(a)
# 		DisplayTablesAny(a,examples[a])
#
# print("Fini")

class SqlParse_Test(unittest.TestCase):
    @staticmethod
    def DispSqlNode(parentNode, sqlNode, depth):
        if depth == 0:
            print(("\t" * depth) + "DISPN=" + sqlNode)
        else:
            print(("\t" * depth) + "PARNT=" + parentNode.replace("\n", " ").replace("  ", " ").replace("  ", " "))
            print(("\t" * depth) + "DISPN=" + sqlNode.replace("\n", " ").replace("  ", " ").replace("  ", " "))

    def DisplayTablesAny(self, theDictNam, theDict):
        errnum = 0

        for sqlQry in theDict:
            print("_" * 40)
            expectedTables = theDict[sqlQry]
            sqlQry = sqlQry.replace("\n", " ").replace("  ", " ").replace("  ", " ")

            print("\nQUERY=" + sqlQry + "\n")
            lib_sql.SqlQueryWalkNodes(sqlQry, SqlParse_Test.DispSqlNode)
            print("")

            resVec = lib_sql.TableDependencies(sqlQry)
            resVec = [s.upper() for s in resVec]
            vecUp = resVec
            vecUp.sort()
            if expectedTables != vecUp:
                errnum += 1
                print("\nQUERY=" + sqlQry + "\n")
                print("Should be=" + str(expectedTables))
                # print("Actual is="+str(resVec))
                print("Result is=" + str(vecUp))
                print("")
                print("")
                self.assertTrue(expectedTables == vecUp)

        lenTot = len(theDict)
        print("Finished " + theDictNam + " with " + str(errnum) + " errors out of " + str(lenTot))

    def sql_parse_test_keyword(self, keyword):
        self.DisplayTablesAny(keyword, query_examples[keyword])

    def test_sql_parse_good(self):
        self.assertTrue(sorted(query_examples.keys()) == ["Bad", "Focus", "Good", "NoSelect"])
        self.sql_parse_test_keyword("Good")

    @unittest.skip("FIXME: Not finished yet")
    def test_sql_parse_focus(self):
        self.sql_parse_test_keyword("Focus")

    @unittest.skip("FIXME: Not finished yet")
    def test_sql_parse_bad(self):
        self.sql_parse_test_keyword("Bad")

    @unittest.skip("FIXME: Not finished yet")
    def test_sql_parse_noselect(self):
        self.sql_parse_test_keyword("NoSelect")

