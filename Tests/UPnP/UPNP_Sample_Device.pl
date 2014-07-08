use Net::UPnP;

my $dm = Net::UPnP::DeviceManager->new;
my $device = $dm->registerDevice(DescriptionFile => 'description.xml',
                                   ResourceDirectory => '.');
my $service = $device->getService('urn:schemas-upnp-org:service:TestService:1');
$service->dispatchTo('MyPackage::MyClass');
$service->setValue('TestVariable', 'foo');
$dm->handle;

