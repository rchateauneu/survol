import wmi

"""
select ?my_file_name ?my_process_handle
where {
?my_assoc rdf:type cim:CIM_ProcessExecutable .
?my_assoc cim:Dependent ?my_process .
?my_assoc cim:Antecedent ?my_file .
?my_process rdf:type cim:CIM_Process .
?my_process cim:Handle ?my_process_handle .
?my_file rdf:type cim:CIM_DataFile .
?my_file rdf:Name ?my_file_name .
}
"""

c = wmi.WMI()
#wql = "SELECT * FROM Win32_Service WHERE State = ""Running"""
#for x in c.query(wql):
#    print(x)

if False:
    for my_process in c.query("select Caption, Handle from CIM_Process"):
        print("my_process=", type(my_process))
        print("my_process=", dir(my_process))
        print("my_process=", my_process.path())
        print("my_process=", my_process.properties)
        print("my_process=", my_process)


for my_process in c.query("select * from CIM_Process"):
    print("my_process.path()=", my_process.path())
    qry = "associators of {%s} where AssocClass = CIM_ProcessExecutable ResultClass=CIM_DataFile ResultRole=Antecedent Role=Precedent" % my_process.path()
    print("qry=", qry)
    try:
        for my_file in c.query("associators of {%s} where AssocClass = CIM_ProcessExecutable ResultClass=CIM_DataFile ResultRole=Antecedent Role=Precedent" % my_process.path()):
            process_handle = my_process.properties['Handle']
            file_name = my_file['Name']
            print("process_handle=", process_handle, "file_name=", file_name)
    except:
        pass

# En tout cas sous WMI ...
if False:
    for antecedent, precedent in c.query("select Antecedent, Precedent from CIM_ProcessExecutable"):
        process_handle = c.query('select Handle from CIM_Process where __PATH="%s"' % precedent)
        file_name = c.query('select Name from CIM_DataFile where __PATH="%s"' % antecedent)
