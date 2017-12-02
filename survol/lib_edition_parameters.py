import sys
import lib_util

# Should simplify this by storing the input URL in a hidden value
# So that the mode=edit trick would not be necessary anymore.

def FormEditionParameters(formActionNoMode,theCgi):
	"""
	This creates a HTML form for editing parameters of a script.
	"""

	formAction = formActionNoMode
	sys.stderr.write("FormEditionParameters formActionNoMode=%s formAction=%s\n"%(formAction,formActionNoMode))
	print('<form name="myform" action="' + formAction + '" method="GET">')

	# argKeys are the names of arguments passed as CGI parameters.
	argKeys = theCgi.m_arguments.keys()

	print('<table class="table_script_parameters">')

	# This is the list of parameters displayed and edited, which should not be
	# input as hidden arguments.
	lstEdimodArgs = []

	if theCgi.m_entity_type != "":
		print('<tr><td colspan=2>' + theCgi.m_entity_type + '</td>')
		for kvKey in theCgi.m_entity_id_dict:
			# TODO: Encode the value.
			kvVal = theCgi.m_entity_id_dict[kvKey]
			print("<tr>")
			print('<td>' + kvKey + '</td>')
			ediNam = "edimodargs_" + kvKey
			lstEdimodArgs.append(ediNam)
			sys.stderr.write("FormEditionParameters ediNam=%s\n"%ediNam)
			print('<td><input type="text" name="%s" value="%s"></td>' % (ediNam,kvVal) )
			print("</tr>")

	check_boxes_parameters = []

	# Now the parameters specific to the script, if they are not passed also as CGI params.
	# param_key is the display string of the variable, and also a HTML form variable name.
	for param_key in theCgi.m_parameters:
		sys.stderr.write("FormEditionParameters param_key=%s\n"%param_key)
		print("<tr>")
		print('<td>' + param_key + '</td>')
		param_val = theCgi.GetParameters( param_key )
		# TODO: Encode the value.
		if isinstance( param_val, bool ):
			# Beware that unchecked checkboxes are not posted, i.e. boolean variables set to False.
			# http://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
			check_boxes_parameters.append( param_key )
			if param_val:
				# Will be converted to boolean True.
				print('<td><input type="checkbox" name="' + param_key + '" value="True" checked></td>')
			else:
				# Python converts empty string to False, everything else to True.
				print('<td><input type="checkbox" name="' + param_key + '" value="True"></td>')
		# TODO: Check validity if int, float etc...
		else:
			print('<td><input type="text" name="' + param_key + '" value="' + str(param_val) + '"></td>')
		print("</tr>")

	print("<tr><td colspan=2>")
	# Beware that unchecked checkboxes are not posted, so it says that we come from edition mode.
	# http://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked

	# Now the hidden arguments. Although entity_type can be deduced from the CGI script location.
	# TODO: MAYBE THIS IS NEVER NECESSARY ... ?
	if not "edimodtype" in argKeys:
		print('<input type="hidden" name="edimodtype" value="' + theCgi.m_entity_type + '">')

	for key in argKeys:
		sys.stderr.write("FormEditionParameters key=%s\n"%key)
		# These keys are processed differently.
		if key in theCgi.m_parameters:
			continue

		# It is explicitely input by the user, so no need of a hidden parameter.
		if key in lstEdimodArgs:
			continue

		# BEWARE: The arguments which are editable, are not "hidden".
		# Hoiw could we edit an argument list ? And how to know that it is a list ?
		# Maybe we could proceed like CGI variables: If the parameter name ends with "[]".
		argList = theCgi.m_arguments.getlist(key)

		# Of course, the mode must not be "edit".
		# Otherwise, it must be stored as a hidden input.
		if key in ["mode"]:
			if argList[0] == "edit":
				continue

		# TODO: Values should be encoded.
		# BEWARE ... if the values contains simgle quotes !
		# Or remove enclosing quotes.
		if len(argList) == 1:
			print('<input type="hidden" name="' + key + '" value=\''+argList[0] + '\'>')
		else:
			for val in argList:
				# Note the "[]" to pass several values.
				print('<input type="hidden" name="' + key + '[]" value=\''+val + '\'>')

	print('<input type="submit" value="Submit">')
	print("</form>")

	print("</td></tr>")
	print("</table>")

	return