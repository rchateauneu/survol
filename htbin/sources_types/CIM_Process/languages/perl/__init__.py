# On l implemente en Perl appele par du Python car de toute facon Perl est necessaire.
#
# (1) http://metacpan.org/pod/App::Stacktrace
# "perl-stacktrace prints Perl stack traces of Perl threads for a given Perl process.
# For each Perl frame, the full file name and line number are printed."
#
# $ perl-stacktrace 24077
# 0x00d73416 in __kernel_vsyscall ()
# /usr/local/bin/cpan:11
# /usr/local/lib/perl5/5.12.2/App/Cpan.pm:364
# /usr/local/lib/perl5/5.12.2/App/Cpan.pm:295
# /usr/local/lib/perl5/5.12.2/CPAN.pm:339
# /usr/local/lib/perl5/5.12.2/Term/ReadLine.pm:198
#
# Tout en haut, comme les packages Python, on pourrait lister les modules Perl (Style CPAN).
# Et donc creer un directory "Langages".
