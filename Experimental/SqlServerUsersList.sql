SELECT * FROM sys.dm_exec_sessions

/* where host_name is not null and session_id = 53 */

select * from sys.dm_exec_requests

/*
SELECT sqltext.TEXT,
req.session_id,
req.status,
req.command,
req.cpu_time,
req.total_elapsed_time
FROM sys.dm_exec_requests req
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
*/

/*
SELECT sqltext.TEXT,
req.session_id,
req.status,
req.command,
sess.host_process_id
FROM sys.dm_exec_requests req
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
, sys.dm_exec_sessions sess
where sess.session_id = req.session_id

	SELECT host_name,host_process_id,session_id,program_name,client_interface_name,original_login_name,nt_domain,nt_user_name
	FROM sys.dm_exec_sessions where host_name is not null


SELECT sqltext.TEXT,
req.session_id,
req.status,
req.command,
sess.host_process_id
FROM sys.dm_exec_requests req
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
, sys.dm_exec_sessions sess
where sess.session_id = req.session_id


select * from sys.dm_exec_connections
*/


/* exec sp_columns sys.dm_exec_connections */

/*
SELECT c.name AS ColName, t.name AS TableName
FROM sys.columns c
    JOIN sys.tables t ON c.object_id = t.object_id
WHERE c.name = 'SESSION_ID' */

/*select * from INFORMATION_SCHEMA.COLUMNS */

/*select COLUMN_NAME from sys.columns*/

/*
where COLUMN_NAME like '%session%' 
order by TABLE_NAME

select * from sys.dm_os_waiting_tasks
*/


select * from master.dbo.sysprocesses