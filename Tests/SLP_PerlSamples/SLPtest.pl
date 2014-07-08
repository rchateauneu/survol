use Net::SLP;

my $handle;

Net::SLP::SLPOpen('', 0, $handle);

Net::SLP::SLPReg(
	$handle,
	'service:mytestservice.x://zulu.open.com.au:9048', # URL
	Net::SLP::SLP_LIFETIME_MAXIMUM, # lifetime
	'',# srvtype (ignored)
	'(attr1=val1),(attr2=val2),(attr3=val3)', # attrs
	1, # Register. SLP does not support reregister.
	\&regcallback);

Net::SLP::SLPFindSrvs(
	$handle,
	'mytestservice.x',
	'',
	'',
	\&urlcallback);

Net::SLP::SLPFindSrvs(
	$handle,
	'http',
	'',
	'',
	\&urlcallback);

Net::SLP::SLPClose($handle);

# Called when a service is registered or deregisted with
# SLPReg(), SLPDeReg() and SLPDelAttrs() functions.

sub regcallback
{
	print "regcallback\n";
	print "    errcode=" . $errcode . "\n";
	my ($errcode) = @_;
}

# Called when a service URL is available from SLPFindSrvs
# This callback returns SLP_TRUE if it wishes to be called again if there is more
# data, else SLP_FALSE
# If $errcode == SLP_LAST_CALL, then there is no more data

sub urlcallback
{
	my ($srvurl, $lifetime, $errcode) = @_;

	if( $errcode == Net::SLP::SLP_LAST_CALL )
	{
		print "\n";
		return Net::SLP::SLP_FALSE;
	}
	else
	{
		print "urlcallback\n";
		print "    srvurl=" . $srvurl . "\n";
		print "    lifetime=" . $lifetime . "\n";
		return Net::SLP::SLP_TRUE;
	}
}

