# Analyses a git repository,
# extract the changes in commits,
# and in each commit, extract the C++ classes which are impacted.
# This can be done by parsing files with DOxygen (which is fast and tolerant to errors).
# DOxygen gives the line ranges where classes are defined (not sure, but other parsers can probably 
# do that: This is a simple task because it does not imply code generation).
# Given this and the Git dataset, deduce which classes were changed.
# Added with the users, it gives information about who changes what etc...
# And which classes are potentially dangerous because people left.