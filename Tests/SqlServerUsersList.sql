SELECT * FROM sys.dm_exec_sessions where host_name is not null

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

SELECT sqltext.TEXT,
req.session_id,
req.status,
req.command,
sess.host_process_id
FROM sys.dm_exec_requests req
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
, sys.dm_exec_sessions sess
where sess.session_id = req.session_id