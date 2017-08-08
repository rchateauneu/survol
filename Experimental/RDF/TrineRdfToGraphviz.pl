use RDF::Trine::Exporter::GraphViz;


sub to_file2 {
    my ($toto, $file, $rdf, %options) = @_;

    print "missing file parameter" unless defined $file;

    if (!ref $file) {
        $options{as} = $1 if $file =~ /\.([^.]+)$/ and $FORMATS{$1};
        open (my $fh, '>', $file);
        $file = $fh;
    }

    print {$file} $toto->to_string( $rdf, %options );
}





print "rdf1=" . $rdf . "\n";
my $rdf_file = "result.rdf";

my $ser = RDF::Trine::Exporter::GraphViz->new( as => 'dot' );
print "rdf2=" . $rdf . " ser=$ser\n";
%opt = ( "a","A", "b", "B" );
# my $dot = $ser->to_string( $rdf, %opt );
my $dot = $ser->to_string( $rdf );
print "rdf3=" . $rdf . "\n";

my $finam = 'graph.svg';
# print {$fi} $ser->to_string( $rdf, %opt );
print {$finam} $ser->to_string( $rdf );
# $ser->to_file( 'graph.svg', $rdf, %opt );
# $ser->to_file( 'graph.svg', $rdf );
$fiptr = \$finam;

local *DESC;
open (DESC, '>', $finam);
$fiptr = \*DESC;

local *RDF;
open (RDF, '<', rdf_file );
$rdf = \*RDF;

to_file2( $ser, $fiptr, $rdf );
print "After to_file2\n";
$ser->to_file( $fiptr, $rdf );

print "After to_file\n";

# highly configurable
my $g = RDF::Trine::Exporter::GraphViz->new(
    namespaces => {
        foaf => 'http://xmlns.com/foaf/0.1/'
    },
    alias => {
        'http://www.w3.org/2002/07/owl#sameAs' => '=',
    },
    prevar => '$',  # variables as '$x' instead of '?x'
    url    => 1,    # hyperlink all URIs

    # see below for more configuration options
);
$g->to_file( 'test.svg', $model );

