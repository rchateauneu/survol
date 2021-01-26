import sys
import logging
import lib_util


# Should simplify this by storing the input URL in a hidden value
# So that the mode=edit trick would not be necessary anymore.

def FormEditionParameters(form_action_no_mode, theCgi):
    """
    This creates a HTML form for editing parameters of a script.
    """

    form_action = form_action_no_mode
    logging.info("FormEditionParameters formActionNoMode=%s form_action=%s", form_action, form_action_no_mode)
    yield('<form name="myform" action="' + form_action + '" method="GET">')

    # arg_keys are the names of arguments passed as CGI parameters.
    arg_keys = theCgi.m_arguments.keys()

    yield('<table class="table_script_parameters">')

    # This is the list of parameters displayed and edited, which should not be input as hidden arguments.
    # The key-value pairs of the object are displayed and can be updated:
    # So it is possible to display another object.
    # These values are returned by prefixing the keys with "edimodargs_" so there is no confusion.
    # When displaying a CGI script, these edited arguments, passed on the command line on top of moniker,
    # are used to updated the key-value pairs of the object.
    # TODO: This implementation is not very clean.
    # FIXME: ... and it does not work anymore.
    #
    # TODO: Next implementation:
    # TODO: Some CGI parameters are prefixed with: "__updated__.", for example:
    # TODO: "__updated__.__class__=CIM_Process&__updated__.Handle=1234"
    # TODO: Parameters are passed like "__parameter__.show_all_scripts=True"
    lst_edimod_args = []

    if theCgi.m_entity_type != "":
        yield('<tr><td colspan=2>' + theCgi.m_entity_type + '</td>')
        for kv_key in theCgi.m_entity_id_dict:
            # TODO: Encode the value.
            kv_val = theCgi.m_entity_id_dict[kv_key]
            yield("<tr>")
            yield('<td>' + kv_key + '</td>')
            edi_nam = "edimodargs_" + kv_key
            lst_edimod_args.append(edi_nam)
            logging.debug("FormEditionParameters edi_nam=%s",edi_nam)
            yield('<td><input type="text" name="%s" value="%s"></td>' % (edi_nam,kv_val) )
            yield("</tr>")

    check_boxes_parameters = []

    # Now the parameters specific to the script, if they are not passed also as CGI params.
    # param_key is the display string of the variable, and also a HTML form variable name.
    for param_key in theCgi.m_parameters:
        logging.debug("FormEditionParameters param_key=%s",param_key)
        yield("<tr>")
        yield('<td>' + param_key + '</td>')
        param_val = theCgi.get_parameters( param_key )
        # TODO: Encode the value.
        if isinstance(param_val, bool):
            # Beware that unchecked checkboxes are not posted, i.e. boolean variables set to False.
            # http://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
            check_boxes_parameters.append(param_key)
            if param_val:
                # Will be converted to boolean True.
                yield('<td><input type="checkbox" name="' + param_key + '" value="True" checked></td>')
            else:
                # Python converts empty string to False, everything else to True.
                yield('<td><input type="checkbox" name="' + param_key + '" value="True"></td>')
        # TODO: Check validity if int, float etc...
        else:
            yield('<td><input type="text" name="' + param_key + '" value="' + str(param_val) + '"></td>')
        yield("</tr>")

    yield("<tr><td colspan=2>")

    # Beware that unchecked checkboxes are not posted, so it says that we come from edition mode.
    # http://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
    # FIXME: The consequence is that it is not possible to have bnoolean parameters with a True default value.
    # FIXME: It is always True.

    # Now the hidden arguments. Although entity_type can be deduced from the CGI script location.
    # TODO: MAYBE THIS IS NEVER NECESSARY ... ?
    if not "edimodtype" in arg_keys:
        yield('<input type="hidden" name="edimodtype" value="' + theCgi.m_entity_type + '">')

    for key in arg_keys:
        logging.debug("FormEditionParameters key=%s",key)
        # These keys are processed differently.
        if key in theCgi.m_parameters:
            continue

        # It is explicitely input by the user, so no need of a hidden parameter.
        if key in lst_edimod_args:
            continue

        # BEWARE: The arguments which are editable, are not "hidden".
        # How could we edit an argument list ? And how to know that it is a list ?
        # Maybe we could proceed like CGI variables: If the parameter name ends with "[]".
        arg_list = theCgi.m_arguments.getlist(key)

        # Of course, the mode must not be "edit".
        # Otherwise, it must be stored as a hidden input.
        if key in ["mode"]:
            if arg_list[0] == "edit":
                continue

        # TODO: Values should be encoded.
        # BEWARE ... if the values contains simgle quotes !
        # Or remove enclosing quotes.
        if len(arg_list) == 1:
            yield('<input type="hidden" name="' + key + '" value=\''+arg_list[0] + '\'>')
        else:
            for val in arg_list:
                # Note the "[]" to pass several values.
                yield('<input type="hidden" name="' + key + '[]" value=\''+val + '\'>')

    yield('<input type="submit" value="Submit">')
    yield("</form>")

    yield("</td></tr>")
    yield("</table>")

    return
