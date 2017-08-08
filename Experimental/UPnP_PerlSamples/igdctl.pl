#!/usr/bin/perl
#########################################################################################
#
#    igdctl -:- Internet gateway device administration tool written in perl
#
#    VERSION:   0.1
#    AUTHOR:    Vincent Wochnik
#    EMAIL:     v.wochnik@yahoo.com
#    WWW:       ubuntu.blogetery.com
#    COPYRIGHT: (c) by Vincent Wochnik 2009
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy
#    of this software and associated documentation files (the "Software"), to
#    deal in the Software without restriction, including without limitation the
#    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#    sell copies of the Software, and to permit persons to whom the Software is
#    furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in
#    all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
#    IN THE SOFTWARE.
#
#    http://www.howtoforge.com/administrating-your-gateway-device-via-upnp
#
#########################################################################################
use strict;
use Getopt::Long;
use Net::UPnP::Device;
use Net::UPnP::ControlPoint;
## allow bundling of command line options
Getopt::Long::Configure('bundling');
##
## PARSE COMMAND LINE OPTIONS
##
my $help               = 0;
my $verbose            = 0;
my $action_print       = 0;
my $action_enable      = 0;
my $action_disable     = 0;
my $action_reconnect   = 0;
my $action_add_port    = 0;
my $action_get_port    = 0;
my $action_remove_port = 0;
my $action_list_ports  = 0;
my $action_clear_ports = 0;
my $devnum             = -1;
my $external_ip        = '';
my $external_port      = '';
my $internal_ip        = '';
my $internal_port      = '';
my $protocol           = '';
my $duration           = '';
my $active             = 1;        ## flag is set by default
if (!GetOptions('h|help',           => \$help,
                'v|verbose',        => \$verbose,
                'p|print'           => \$action_print,            ## print statistics
                'r|reconnect'       => \$action_reconnect,        ## reconnect
                'enable'            => \$action_enable,            ## enable internet access
                'disable'           => \$action_disable,        ## disable internet access
                'a|add-port'        => \$action_add_port,        ## add port mapping
                'g|get-port'        => \$action_get_port,        ## get a port by external host, ip and protocol
                'R|remove-port'     => \$action_remove_port,    ## remove port mapping
                'c|clear-ports'     => \$action_clear_ports,    ## clear port mapping list
                'l|list-ports'      => \$action_list_ports,        ## list port mappings
                'd|device=i'        => \$devnum,                ## device number
                'E|external-ip=s'   => \$external_ip,            ## external ip address
                'e|external-port=i' => \$external_port,            ## external port
                'I|internal-ip=s'   => \$internal_ip,            ## client ip address
                'i|internal-port=i' => \$internal_port,            ## internal port
                'P|protocol=s'        => \$protocol,                ## protocol (TCP/UDP
                'D|duration=i'      => \$duration,                ## expiration time
                'A|active=i'        => \$active)) {                ## active flag
    $help = 1;
}
if ($action_print+$action_enable+$action_disable+$action_reconnect+$action_add_port+$action_get_port+$action_remove_port+$action_clear_ports+$action_list_ports > 1) {
    ## No multiple action parameters!!!
    $help = 1;
} elsif ($action_print+$action_enable+$action_disable+$action_reconnect+$action_add_port+$action_get_port+$action_remove_port+$action_clear_ports+$action_list_ports == 0) {
    ## No action parameter found!!!
    $help = 1;
} elsif ($action_print+$action_enable+$action_disable+$action_reconnect == 1) {
    ## Some action parameters don't require additional parameters
    if (($external_ip) || ($external_port) || ($internal_ip) || ($internal_port) || ($duration)) {
        $help = 1;
    }
} elsif ($action_add_port+$action_get_port+$action_remove_port+$action_clear_ports+$action_list_ports == 1) {
    ## Check if all parameters are valid
    if (
        ((($action_add_port) || ((($action_clear_ports) || ($action_list_ports)) && ($internal_ip))) && ($internal_ip !~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) ||
        ((($action_add_port) || ($action_remove_port) || ($action_get_port)) && ($external_ip) && ($external_ip !~ m/^[0-9*]{1,3}\.[0-9*]{1,3}\.[0-9*]{1,3}\.[0-9*]{1,3}$/)) ||
        (($action_add_port) && (($internal_port < 0) || ($internal_port > 65535))) ||
        ((($action_add_port) || ($action_remove_port) || ($action_get_port)) && (($external_port < 0) || ($external_port > 65535))) ||
        (($action_add_port) && (($duration) && ($duration < 0))) ||
        ((($action_add_port) || ($action_remove_port) || ($action_get_port)) && ($protocol !~ m/(TCP|UDP)/)) ||
        (($action_add_port) && ($duration) && ($duration !~ m/^\d$/)) ||
        (($action_add_port) && ($active) && ($active !~ m/^(0|1)$/))
       ) {
        $help = 1;
    }
}
## Display help content and exit
if ($help) {
    ## Help content is located at the bottom after the __DATA__ statement
    print STDOUT <data> and exit 2;
}
## scanning for devices
print STDOUT "Scanning for devices ...\n" if $verbose;
my @devices = get_igd_devices();
my $devcount = length(@devices);
## error handling
print STDERR "No device found.\n\n" and exit 1 if (!@devices);
## if there is only one device, auto-choose
$devnum = 0 if ($devcount == 1);
## if verbose or device number invalid
if (($verbose) || ($devnum < 0) || ($devnum >= $devcount)) {
    printf STDOUT 'Found %d ', $devcount;
    print STDOUT "device.\n\n" if ($devcount == 1);
    print STDOUT "devices.\n\n" if ($devcount != 1);
}
## print list and ask the user if no device number is given per command argument
if (($devnum < 0) || ($devnum >= $devcount)) {
    ## print device list
    list_devices(@devices);
    ## user choice
    while (($devnum !~ m/^[0-9]+$/) || ($devnum >= $devcount)) {
        print("Please select a device.\nDevice: ");
	##########################" chomp($devnum = );
	$devnum=<STDIN>;
        chomp($devnum);
        print STDOUT "Invalid choice. Try again!\n" if (($devnum < 0) || ($devnum >= $devcount));
        print STDOUT "\n";
    }
}
## Get chosen device
my $device = @devices[$devnum];
my $service;
## get service handler
if ($action_enable+$action_disable+$action_print) {
    ## Get WANIPCommonInterfaceConfig service
    $service = $device->getservicebyname("urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1");
    print STDERR "WANCommonInterfaceConfig service not avaleble.\n\n" and exit 1 if (!$service);
} else {##if ($action_reconnect+$action_add_port+$action_get_port+$action_remove_port+$action_clear_ports+$action_list_ports)
    ## Get WANIPConnection service
    $service = $device->getservicebyname("urn:schemas-upnp-org:service:WANIPConnection:1");
    print STDERR "WANCommonInterfaceConfig service not avaleble.\n\n" and exit 1 if (!$service);
}
if ($action_print) {
    my $res, my $out_args, my $out="";
    ## Get internet enabled
    print STDOUT "Trying to get internet access state ...\n" if $verbose;
    $res = $service->postaction("GetEnabledForInternet");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        if ($out_args->{'NewEnabledForInternet'}) {
            $out .= sprintf('Internet access                   : enabled'."\n");
        } else {
            $out .= sprintf('Internet access                   : disabled'."\n");
        }
    }
    ## Get connection properties ...
    print STDOUT "Trying to get connection properties ...\n" if $verbose;
    $res = $service->postaction("GetCommonLinkProperties");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('WAN access type                   : %s'."\n", $out_args->{'NewWANAccessType'});
        $out .= sprintf('Maximum upstream rate             : %s bps'."\n", $out_args->{'NewLayer1UpstreamMaxBitRate'});
        $out .= sprintf('Maximum downstream rate           : %s bps'."\n", $out_args->{'NewLayer1DownstreamMaxBitRate'});
        $out .= sprintf('Physical link state               : %s'."\n", $out_args->{'NewPhysicalLinkStatus'});
    }
    ## Get wan access provider
    print STDOUT "Trying to get WAN access provider ...\n" if $verbose;
    $res = $service->postaction("GetWANAccessProvider");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('WAN access provider               : %s'."\n", $out_args->{'NewWANAccessProvider'});
    }
    ## Get maximum number of active connections
    print STDOUT "Trying to get maximum number of active connections ...\n" if $verbose;
    $res = $service->postaction("GetMaximumActiveConnections");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('Max. number of active connections : %d'."\n", $out_args->{'MaximumActiveConnections'});
    }
    ## Get total bytes sent
    print STDOUT "Trying to get total number of bytes sent ...\n" if $verbose;
    $res = $service->postaction("GetTotalBytesSent");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('Total bytes sent                  : %s'."\n", readable_size($out_args->{'NewTotalBytesSent'}));
    }
    ## Get total packets sent
    print STDOUT "Trying to get total number of packets sent ...\n" if $verbose;
    $res = $service->postaction("GetTotalPacketsSent");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('Total packets sent                : %d'."\n", $out_args->{'NewTotalPacketsReceived'});
    }
    ## Get total bytes received
    print STDOUT "Trying to get total number of bytes received ...\n" if $verbose;
    $res = $service->postaction("GetTotalBytesReceived");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('Total bytes received              : %s'."\n", readable_size($out_args->{'NewTotalBytesReceived'}));
    }
    ## Get total packets received
    print STDOUT "Trying to get total number of packets received ...\n" if $verbose;
    $res = $service->postaction("GetTotalPacketsReceived");
    if ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out .= sprintf('Total packets received            : %d'."\n", $out_args->{'NewTotalPacketsReceived'});
    }
    print STDOUT $out."\n" and exit 0 if $out;                ## print information
    print STDERR "Nothing to print out.\n" and exit 1;        ## otherwise print an error
} elsif ($action_enable) {        ## OK <-- based on Documentation
    my $res, my %in_args, my $success=1;
    %in_args = ('NewEnabledForInternet' => '1');
    ## Enable internet access ...
    print STDOUT "Trying to enable internet access ...\n" if $verbose;
    $res = $service->postaction("SetEnabledForInternet", \%in_args);
    ## error handling
    if ($res->getstatuscode() == 401) {
        print STDERR "Operation not supported. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
    }
    print STDOUT "Command successful.\n" and exit 0 if $success;
    print STDERR "Command failed.\n" and exit 1;
} elsif ($action_disable) {        ## OK <-- based on Documentation
    my $res, my %in_args, my $success=1;
    %in_args = ('NewEnabledForInternet' => '0');
    ## Disable internet access ...
    print STDOUT "Trying to disable internet access ...\n" if $verbose;
    $res = $service->postaction("SetEnabledForInternet", \%in_args);
    ## error handling
    if ($res->getstatuscode() == 401) {
        print STDERR "Operation not supported. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
    }
    print STDOUT "Command successful.\n" and exit 0 if $success;
    print STDERR "Command failed.\n" and exit 1;
} elsif ($action_reconnect) {        ## OK <-- based on Documentation
    my $res, my $success=1;
    ## Force termination ...
    print STDOUT "Trying to terminate WANIPConnection ...\n" if $verbose;
    $res = $service->postaction("ForceTermination");
    ## error handling
    if ($res->getstatuscode() == 501) {
        print STDERR "Action failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 710) {
        print STDERR "Invalid connection type. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 702) {
        print STDERR "Disconnect in progress. (WARNING ".$res->getstatuscode().")\n\n" if $verbose;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
    }
    print STDERR "Command failed.\n" and exit 1 if (!$success);
    ## Requesting new connection ...
    print STDOUT "Requesting new connection ...\n" if $verbose;
    $res = $service->postaction("RequestConnection");
    ## error handling
    if ($res->getstatuscode() == 704) {
        print STDERR "Connection setup failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 708) {
        print STDERR "Invalid Layer2 address. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 709) {
        print STDERR "Internet access disabled. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 710) {
        print STDERR "Invalid connection type. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 705) {
        print STDERR "Connection setup in progress. (WARNING ".$res->getstatuscode().")\n\n" if $verbose;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
    }
    print STDOUT "Command successful.\n" and exit 0 if $success;
    print STDERR "Command failed.\n" and exit 1;
} elsif ($action_add_port) {
    my $res, my %in_args, my $success=1;
    %in_args = ('NewRemoteHost' => $external_ip,
                'NewExternalPort' => $external_port,
                'NewProtocol' => $protocol,
                'NewInternalPort' => $internal_port,
                'NewInternalClient' => $internal_ip,
                'NewEnabled' => $active,
                'NewPortMappingDescription' => 'mapped by '.__FILE__,
                'NewLeaseDuration' => $duration);
    ## trying to add port mapping entry
    print STDOUT "Trying to add a port mapping entry ...\n" if $verbose;
    $res = $service->postaction("AddPortMapping", \%in_args);
    ## error handling
    if ($res->getstatuscode() == 402) {
        print STDERR "Invalid args. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 715) {
        print STDERR "Wildcard not allowed in remote host address. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 716) {
        print STDERR "Wildcard not allowed in external port. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() == 718) {
        print STDERR "Conflicting with another mapping entry. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
    }
    print STDOUT "Command successful.\n" and exit 0 if $success;
    print STDERR "Command failed.\n" and exit 1;
} elsif ($action_remove_port) {
    my $res, my %in_args, my $success=1;
    %in_args = ('NewRemoteHost' => $external_ip,
                'NewExternalPort' => $external_port,
                'NewProtocol' => $protocol);
    ## remove port mapping entry
    print STDOUT "Trying to remove a port mapping entry matching specified criteria ...\n" if $verbose;
    $res = $service->postaction("DeletePortMapping", \%in_args);
    ## error handling
    if ($res->getstatuscode() == 714) {
        print STDERR "Entry not found. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
        $success = 0;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
    }
    print STDOUT "Command successful.\n" and exit 0 if $success;
    print STDERR "Command failed.\n" and exit 1;
} elsif ($action_get_port) {
    my $res, my %in_args, my $out_args, my $out;
    %in_args = ('NewRemoteHost' => $external_ip,
                'NewExternalPort' => $external_port,
                'NewProtocol' => $protocol);
    ## print port mapping entry
    print STDOUT "Trying to print a port mapping entry matching specified criteria ...\n" if $verbose;
    $res = $service->postaction("GetSpecificPortMappingEntry", \%in_args);
    ## error handling
    if ($res->getstatuscode() == 714) {
        print STDERR "Entry not found. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } elsif ($res->getstatuscode() != 200) {
        print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
    } else {
        print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
        $out_args = $res->getargumentlist();
        $out = sprintf('%6s %15s %13s %15s %13s %10s'."\n", 'ACTIVE', 'REMOTE HOST', 'EXTERNAL PORT', 'CLIENT HOST', 'INTERNAL PORT', 'LEASE TIME') if (!$out);
        if ($external_ip) {
            $out .= sprintf('%6s %15s %13s %15s %13s %10s'."\n", $out_args->{'NewEnabled'}, $external_ip, $external_port, $out_args->{'NewInternalClient'}, $out_args->{'NewInternalPort'}, $out_args->{'NewLeaseDuration'});
        } else {
            $out .= sprintf('%6s %15s %13s %15s %13s %10s'."\n", $out_args->{'NewEnabled'}, '*', $external_port, $out_args->{'NewInternalClient'}, $out_args->{'NewInternalPort'}, $out_args->{'NewLeaseDuration'});
        }
    }
    print STDOUT $out."\n" and exit 0 if $out;                ## print information
    print STDERR "Nothing to print out.\n" and exit 1;        ## otherwise print an error
} elsif ($action_list_ports) {
    my $res, my %in_args, my $out_args, my $i=0, my $out="";
    while ($i >= 0) {
        %in_args = ('NewPortMappingIndex' => $i);
        ## search port mapping entry
        print STDOUT "Trying to search port mapping entry ...\n" if $verbose;
        $res = $service->postaction("GetGenericPortMappingEntry", \%in_args);
        ## error handling
        if ($res->getstatuscode() != 200) {
            print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
            $i = -1;    ## stop loop - there are no more entries
        } else {
            print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
            $out_args = $res->getargumentlist();
            if ((!$internal_ip) || ($out_args->{'NewInternalClient'} =~ m/^($internal_ip)$/)) {
                $out = sprintf('%6s %15s %13s %15s %13s %10s'."\n", 'ACTIVE', 'REMOTE HOST', 'EXTERNAL PORT', 'CLIENT HOST', 'INTERNAL PORT', 'LEASE TIME') if (!$out);
                if ($out_args->{'NewRemoteHost'}) {
                    $out .= sprintf('%6s %15s %13s %15s %13s %10s'."\n", $out_args->{'NewEnabled'}, $out_args->{'NewRemoteHost'}, $out_args->{'NewExternalPort'}, $out_args->{'NewInternalClient'}, $out_args->{'NewInternalPort'}, $out_args->{'NewLeaseDuration'});
                } else {
                    $out .= sprintf('%6s %15s %13s %15s %13s %10s'."\n", $out_args->{'NewEnabled'}, '*', $out_args->{'NewExternalPort'}, $out_args->{'NewInternalClient'}, $out_args->{'NewInternalPort'}, $out_args->{'NewLeaseDuration'});
                }
            }
            $i++;
        }
    }
    print STDOUT $out."\n" and exit 0 if $out;                ## print information
    print STDERR "Nothing to print out.\n" and exit 1;        ## otherwise print an error
} elsif ($action_clear_ports) {
    my $res, my %in_args, my $out_args, my $i=0, my $success=1;
    while ($i >= 0) {
        %in_args = ('NewPortMappingIndex' => $i);
        ## search port mapping entry
        print STDOUT "Trying to search port mapping entry ...\n" if $verbose;
        $res = $service->postaction("GetGenericPortMappingEntry", \%in_args);
        ## error handling
        if ($res->getstatuscode() != 200) {
            print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
            $i = -1;    ## stop loop - there are no more entries
        } else {
            print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
            $out_args = $res->getargumentlist();
            if ((!$internal_ip) || ($out_args->{'NewInternalClient'} =~ m/^($internal_ip)$/)) {
                %in_args = ('NewRemoteHost' => $out_args->{'NewRemoteHost'},
                            'NewExternalPort' => $out_args->{'NewExternalPort'},
                            'NewProtocol' => $out_args->{'NewProtocol'});
                ## remove port mapping entry
                printf STDOUT 'Trying to remove port mapping entry number %d...'."\n", $i+1 if $verbose;
                $res = $service->postaction("DeletePortMapping", \%in_args);
                ## error handling
                if ($res->getstatuscode() == 714) {
                    print STDERR "Entry not found. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
                    $success=0;
                    $i = -1;    ## stop loop - there is an error
                } elsif ($res->getstatuscode() != 200) {
                    print STDERR "Operation failed. (ERR ".$res->getstatuscode().")\n\n" if $verbose;
                    $success=0;
                    $i = -1;    ## stop loop - there is an error
                } else {
                    print STDOUT "Done (OK ".$res->getstatuscode().")\n\n" if $verbose;
                }
            } else {
                $i++;
            }
        }
    }
    print STDOUT "Command successful.\n" and exit 0 if $success;
    print STDERR "Command failed.\n" and exit 1;
}
sub get_igd_devices() {
    my $cp, my @devices, my $device, my @filtereddevs;
    $cp = Net::UPnP::ControlPoint->new();
    ## scan for devices
    @devices = $cp->search(st => 'upnp:rootdevice', mx => '1');
    ## and another time if none found
    @devices = $cp->search(st => 'upnp:rootdevice', mx => '3') if (!@devices);
    if (@devices) {
        foreach $device (@devices) {
            my $devtype = $device->getdevicetype();
            if ($devtype =~ m/^urn:schemas-upnp-org:device:InternetGatewayDevice:1$/) {
                push(@filtereddevs, $device);
            }
        }
    }
    @filtereddevs;
}
sub list_devices() {
    my @devices, $devcount;
    my $devnum, my $devmanuf, my $devmodel, my $devsn, my $devudn, my $devupc;
    @devices = $_[0];
    $devcount = length(@devices);
    for ($devnum = 0; $devnum < $devcount; $devnum++) {
        $devmanuf = $devices[$devnum]->getmanufacturer();
        $devmodel = $devices[$devnum]->getmodelname();
        $devsn = $devices[$devnum]->getserialnumber();
        $devudn = $devices[$devnum]->getudn();
        $devupc = $devices[$devnum]->getupc();
        $devsn = "n/a" if (!$devsn);
        $devudn = "n/a" if (!$devudn);
        $devupc = "n/a" if (!$devupc);
        printf STDOUT 'Device:       : %d'."\n", $devnum;
        printf STDOUT 'Manufacturer  : %s'."\n", $devmanuf;
        printf STDOUT 'Model         : %s'."\n", $devmodel;
        printf STDOUT 'Serial number : %s'."\n", $devsn;
        printf STDOUT 'UDN           : %s'."\n", $devudn;
        printf STDOUT 'UPC           : %s'."\n\n", $devupc;
    }
}
sub readable_size() {
    my $size = $_[0];
    my $readable;
    if ($size >= 1024*1024*1024*1024) {
        $readable = sprintf('%.2f TB', $size/1024/1024/1024/1024);
    } elsif ($size >= 1024*1024*1024) {
        $readable = sprintf('%.2f GB', $size/1024/1024/1024);
    } elsif ($size >= 1024*1024) {
        $readable = sprintf('%.2f MB', $size/1024/1024);
    } elsif ($size >= 1024*1024*1024*1024) {
        $readable = sprintf('%.2f KB', $size/1024);
    } else {
        $readable = sprintf('%.2f Bytes', $size);
    }
    $readable;
}
__DATA__
igdctl -:- IGD administration tool written in perl
Version 0.1
USAGE
  ./igdctl.pl [-h|-p|-r|-a|-g|-R|-l|-c|--enable|--disable]
  [-d DEVICE] [-E IP] [-e PORT] [-I IP] [-i PORT]
  [-P PROTOCOL] [-D DURATION] [-A ACTIVE]
Example:
  ./igdctl.pl -r
Actions:
  -h, --help                : Displays this help text.
  -v, --verbose             : Verbose mode.
  -p, --print               : Prints connection information avaleble.
      --enable              : Enable internet access if supported.
      --disable             : Disable internet access if supported.
  -r, --reconnect           : Triggers a reconnect.
  -a, --add-port            : Adds or overwrites a port mapping entry with the
                              same internal client address.
                              -e, -I, -i, -P are needed, -E, -D, -A are
                              optional.
  -g, --get-port            : Gets a port mapping entry by remote host,
                              port and protocol. -e, -P are needed, -E is
                              optional.
  -R, --remove-port         : Removes a port mapping entry.
                              -e, -P are needed, -E is optional.
  -l, --list-ports          : Lists all port mapping entries. If -I was
                              specified, only entries by a given IP are shown.
  -c, --clear-ports         : Removes all port mapping entries. If -I was
                              specified, only entries by a given IP are
                              removed.
Options:
  -d, --device=DEV          : specifies the device number when more then one
                              devices are avaleble.
  -E, --external-ip=IP      : specifies a remote host. Wildcards are supported.
  -e, --external-port=PORT  : specifies an external port number.
  -I, --internal-ip=IP      : specifies a client ip address.
  -i, --internal-port=PORT  : specifies a client port number.
  -P, --protocol=PROTOCOL   : specifies a protocol. TCP and UDP are allowed.
  -D, --duration=DURATION   : specifies a number of seconds until a port mapping
                              entry expires.
  -A, --active=ACTIVE       : Specifies whether a port mapping entry is enabled.
                              Values 0 and 1 are allowed.

