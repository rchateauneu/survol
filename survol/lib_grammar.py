# Consider using the Pythonpackage inflect.


# Win32_ReliabilityRecordses
# Win32_LogicalFileAccesses
def ToPlural(elt_nam, num_nod_lst):
    if num_nod_lst == 1:
        return elt_nam

    if not elt_nam[-1].isalpha():
        return elt_nam

    if elt_nam[-1] == "s":
        if (len(elt_nam) > 1) and (elt_nam[-2] != "s"):
            # Maybe it is already plural.
            return elt_nam
        else:
            return elt_nam + "es"

    if elt_nam[-1] == "y":
        return elt_nam[:-1] + "ies"

    return elt_nam + "s"


# https://www.theenglishspace.com/grammar/determiners/articles-introduction.html
def IndefiniteArticle(the_word):
    if the_word[0].upper() in "AEIOUY":
        return "an"
    else:
        return "a"
