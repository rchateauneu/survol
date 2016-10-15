import lib_common

# A map file is associated to a file.
def AddInfo(grph,node,entity_ids_arr):
	nameMappedFile = entity_ids_arr[0]
	# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
	exec_node = lib_common.gUriGen.FileUri( nameMappedFile )
	grph.add( ( node, lib_common.MakeProp("Mapped file"), exec_node ) )

