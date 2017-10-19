import subprocess


# IndentationError: expected an indented block
# >>> for n in w.Win32_NetworkAdapter():
# ...     print(n)
# ...
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000000] WAN Miniport (SSTP)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (SSTP)";
#         DeviceID = "0";
#         Index = 0;
#         Installed = TRUE;
#         InterfaceIndex = 2;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (SSTP)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_SSTPMINIPORT\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (SSTP)";
#         ServiceName = "RasSstp";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000001] WAN Miniport (IKEv2)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (IKEv2)";
#         DeviceID = "1";
#         Index = 1;
#         Installed = TRUE;
#         InterfaceIndex = 10;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (IKEv2)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_AGILEVPNMINIPORT\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (IKEv2)";
#         ServiceName = "RasAgileVpn";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000002] WAN Miniport (L2TP)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (L2TP)";
#         DeviceID = "2";
#         Index = 2;
#         Installed = TRUE;
#         InterfaceIndex = 3;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (L2TP)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_L2TPMINIPORT\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (L2TP)";
#         ServiceName = "Rasl2tp";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000003] WAN Miniport (PPTP)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (PPTP)";
#         DeviceID = "3";
#         Index = 3;
#         Installed = TRUE;
#         InterfaceIndex = 4;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (PPTP)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_PPTPMINIPORT\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (PPTP)";
#         ServiceName = "PptpMiniport";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000004] WAN Miniport (PPPOE)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (PPPOE)";
#         DeviceID = "4";
#         Index = 4;
#         Installed = TRUE;
#         InterfaceIndex = 5;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (PPPOE)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_PPPOEMINIPORT\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (PPPOE)";
#         ServiceName = "RasPppoe";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000005] WAN Miniport (IPv6)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (IPv6)";
#         DeviceID = "5";
#         Index = 5;
#         Installed = TRUE;
#         InterfaceIndex = 6;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (IPv6)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_NDISWANIPV6\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (IPv6)";
#         ServiceName = "NdisWan";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000006] WAN Miniport (Network Monitor)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (Network Monitor)";
#         DeviceID = "6";
#         Index = 6;
#         Installed = TRUE;
#         InterfaceIndex = 7;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (Network Monitor)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_NDISWANBH\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (Network Monitor)";
#         ServiceName = "NdisWan";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Ethernet 802.3";
#         AdapterTypeId = 0;
#         Availability = 3;
#         Caption = "[00000007] Realtek PCIe GBE Family Controller";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "Realtek PCIe GBE Family Controller";
#         DeviceID = "7";
#         GUID = "{372DB82B-FE28-489B-B744-FC1C0F726791}";
#         Index = 7;
#         Installed = TRUE;
#         InterfaceIndex = 11;
#         MACAddress = "8C:DC:D4:34:D4:38";
#         Manufacturer = "Realtek";
#         MaxNumberControlled = 0;
#         Name = "Realtek PCIe GBE Family Controller";
#         NetConnectionID = "Local Area Connection";
#         NetConnectionStatus = 2;
#         NetEnabled = TRUE;
#         PhysicalAdapter = TRUE;
#         PNPDeviceID = "PCI\\VEN_10EC&DEV_8168&SUBSYS_18E9103C&REV_0C\\4&11DD9C9B&0&00E2";
#         PowerManagementSupported = FALSE;
#         ProductName = "Realtek PCIe GBE Family Controller";
#         ServiceName = "RTL8167";
#         Speed = "100000000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000008] WAN Miniport (IP)";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "WAN Miniport (IP)";
#         DeviceID = "8";
#         Index = 8;
#         Installed = TRUE;
#         InterfaceIndex = 8;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "WAN Miniport (IP)";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\MS_NDISWANIP\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "WAN Miniport (IP)";
#         ServiceName = "NdisWan";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Tunnel";
#         AdapterTypeId = 15;
#         Availability = 3;
#         Caption = "[00000009] Microsoft ISATAP Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "Microsoft ISATAP Adapter";
#         DeviceID = "9";
#         Index = 9;
#         Installed = TRUE;
#         InterfaceIndex = 12;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "Microsoft ISATAP Adapter";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\*ISATAP\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "Microsoft ISATAP Adapter";
#         ServiceName = "tunnel";
#         Speed = "100000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Wide Area Network (WAN)";
#         AdapterTypeId = 3;
#         Availability = 3;
#         Caption = "[00000010] RAS Async Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "RAS Async Adapter";
#         DeviceID = "10";
#         Index = 10;
#         Installed = TRUE;
#         InterfaceIndex = 9;
#         MACAddress = "20:41:53:59:4E:FF";
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "RAS Async Adapter";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "SW\\{EEAB7790-C514-11D1-B42B-00805FC1270E}\\ASYNCMAC";
#         PowerManagementSupported = FALSE;
#         ProductName = "RAS Async Adapter";
#         ServiceName = "AsyncMac";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Tunnel";
#         AdapterTypeId = 15;
#         Availability = 3;
#         Caption = "[00000011] Microsoft ISATAP Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "Microsoft ISATAP Adapter";
#         DeviceID = "11";
#         Index = 11;
#         Installed = TRUE;
#         InterfaceIndex = 13;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "Microsoft ISATAP Adapter #2";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\*ISATAP\\0001";
#         PowerManagementSupported = FALSE;
#         ProductName = "Microsoft ISATAP Adapter";
#         ServiceName = "tunnel";
#         Speed = "100000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Tunnel";
#         AdapterTypeId = 15;
#         Availability = 3;
#         Caption = "[00000012] Microsoft Teredo Tunneling Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "Microsoft Teredo Tunneling Adapter";
#         DeviceID = "12";
#         Index = 12;
#         Installed = TRUE;
#         InterfaceIndex = 14;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "Teredo Tunneling Pseudo-Interface";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\*TEREDO\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "Microsoft Teredo Tunneling Adapter";
#         ServiceName = "tunnel";
#         Speed = "100000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Ethernet 802.3";
#         AdapterTypeId = 0;
#         Availability = 3;
#         Caption = "[00000013] VirtualBox Host-Only Ethernet Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "VirtualBox Host-Only Ethernet Adapter";
#         DeviceID = "13";
#         GUID = "{BCAE0703-FC45-4644-92D4-031350F78C6E}";
#         Index = 13;
#         Installed = TRUE;
#         InterfaceIndex = 15;
#         MACAddress = "08:00:27:00:98:C2";
#         Manufacturer = "Oracle Corporation";
#         MaxNumberControlled = 0;
#         Name = "VirtualBox Host-Only Ethernet Adapter";
#         NetConnectionID = "VirtualBox Host-Only Network";
#         NetConnectionStatus = 2;
#         NetEnabled = TRUE;
#         PhysicalAdapter = TRUE;
#         PNPDeviceID = "ROOT\\NET\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "VirtualBox Host-Only Ethernet Adapter";
#         ServiceName = "VBoxNetAdp";
#         Speed = "100000000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Ethernet 802.3";
#         AdapterTypeId = 0;
#         Availability = 3;
#         Caption = "[00000014] VirtualBox Bridged Networking Driver Miniport";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "VirtualBox Bridged Networking Driver Miniport";
#         DeviceID = "14";
#         Index = 14;
#         Installed = TRUE;
#         InterfaceIndex = 16;
#         MACAddress = "8C:DC:D4:34:D4:38";
#         Manufacturer = "Oracle Corporation";
#         MaxNumberControlled = 0;
#         Name = "VirtualBox Bridged Networking Driver Miniport";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\SUN_VBOXNETFLTMP\\0000";
#         PowerManagementSupported = FALSE;
#         ProductName = "VirtualBox Bridged Networking Driver Miniport";
#         ServiceName = "VBoxNetFlt";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000015] TomTom";
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "TomTom";
#         DeviceID = "15";
#         Index = 15;
#         Installed = TRUE;
#         InterfaceIndex = 17;
#         MaxNumberControlled = 0;
#         Name = "TomTom";
#         PhysicalAdapter = FALSE;
#         PowerManagementSupported = FALSE;
#         ProductName = "TomTom";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         Availability = 3;
#         Caption = "[00000016] VirtualBox Bridged Networking Driver Miniport";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "VirtualBox Bridged Networking Driver Miniport";
#         DeviceID = "16";
#         Index = 16;
#         Installed = TRUE;
#         InterfaceIndex = 18;
#         Manufacturer = "Oracle Corporation";
#         MaxNumberControlled = 0;
#         Name = "VirtualBox Bridged Networking Driver Miniport";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\SUN_VBOXNETFLTMP\\0001";
#         PowerManagementSupported = FALSE;
#         ProductName = "VirtualBox Bridged Networking Driver Miniport";
#         ServiceName = "VBoxNetFlt";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Tunnel";
#         AdapterTypeId = 15;
#         Availability = 3;
#         Caption = "[00000017] Microsoft ISATAP Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "Microsoft ISATAP Adapter";
#         DeviceID = "17";
#         Index = 17;
#         Installed = TRUE;
#         InterfaceIndex = 19;
#         Manufacturer = "Microsoft";
#         MaxNumberControlled = 0;
#         Name = "Microsoft ISATAP Adapter #3";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\*ISATAP\\0002";
#         PowerManagementSupported = FALSE;
#         ProductName = "Microsoft ISATAP Adapter";
#         ServiceName = "tunnel";
#         Speed = "100000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Ethernet 802.3";
#         AdapterTypeId = 0;
#         Availability = 3;
#         Caption = "[00000018] NETGEAR WNDA3100v3 N600 Wireless Dual Band USB Adapter";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "NETGEAR WNDA3100v3 N600 Wireless Dual Band USB Adapter";
#         DeviceID = "18";
#         GUID = "{CF185B35-1F88-46CF-A6CE-BDECFBB59B4F}";
#         Index = 18;
#         Installed = TRUE;
#         InterfaceIndex = 20;
#         MACAddress = "B0:7F:B9:FF:3A:70";
#         Manufacturer = "NETGEAR Inc.";
#         MaxNumberControlled = 0;
#         Name = "NETGEAR WNDA3100v3 N600 Wireless Dual Band USB Adapter";
#         NetConnectionID = "Wireless Network Connection";
#         NetConnectionStatus = 2;
#         NetEnabled = TRUE;
#         PhysicalAdapter = TRUE;
#         PNPDeviceID = "USB\\VID_0846&PID_9014\\000000000";
#         PowerManagementSupported = FALSE;
#         ProductName = "NETGEAR WNDA3100v3 N600 Wireless Dual Band USB Adapter";
#         ServiceName = "WNDA3100v3";
#         Speed = "108000000";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };
#
#
# instance of Win32_NetworkAdapter
# {
#         AdapterType = "Ethernet 802.3";
#         AdapterTypeId = 0;
#         Availability = 3;
#         Caption = "[00000019] VirtualBox Bridged Networking Driver Miniport";
#         ConfigManagerErrorCode = 0;
#         ConfigManagerUserConfig = FALSE;
#         CreationClassName = "Win32_NetworkAdapter";
#         Description = "VirtualBox Bridged Networking Driver Miniport";
#         DeviceID = "19";
#         Index = 19;
#         Installed = TRUE;
#         InterfaceIndex = 21;
#         MACAddress = "B0:7F:B9:FF:3A:70";
#         Manufacturer = "Oracle Corporation";
#         MaxNumberControlled = 0;
#         Name = "VirtualBox Bridged Networking Driver Miniport";
#         PhysicalAdapter = FALSE;
#         PNPDeviceID = "ROOT\\SUN_VBOXNETFLTMP\\0002";
#         PowerManagementSupported = FALSE;
#         ProductName = "VirtualBox Bridged Networking Driver Miniport";
#         ServiceName = "VBoxNetFlt";
#         SystemCreationClassName = "Win32_ComputerSystem";
#         SystemName = "RCHATEAU-HP";
#         TimeOfLastReset = "20171014214032.375199+060";
# };


# C:\Python27\python.exe C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/Experimental/Test_ip_config.py
# Windows IP Configuration
#     Host Name : rchateau-HP
#     Primary Dns Suffix :
#     Node Type : Hybrid
#     IP Routing Enabled : No
#     WINS Proxy Enabled : No
# Tunnel adapter isatap.{BCAE0703-FC45-4644-92D4-031350F78C6E}
#     Media State : Media disconnected
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:Microsoft ISATAP Adapter #2
#     Physical Address : 00-00-00-00-00-00-00-E0
#     DHCP Enabled : No
#     Autoconfiguration Enabled : Yes
# Tunnel adapter Teredo Tunneling Pseudo-Interface
#     Media State : Media disconnected
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:Teredo Tunneling Pseudo-Interface
#     Physical Address : 00-00-00-00-00-00-00-E0
#     DHCP Enabled : No
#     Autoconfiguration Enabled : Yes
# Tunnel adapter isatap.{CF185B35-1F88-46CF-A6CE-BDECFBB59B4F}
#     Media State : Media disconnected
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:Microsoft ISATAP Adapter #3
#     Physical Address : 00-00-00-00-00-00-00-E0
#     DHCP Enabled : No
#     Autoconfiguration Enabled : Yes
# Ethernet adapter VirtualBox Host-Only Network
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:VirtualBox Host-Only Ethernet Adapter
#     Physical Address : 08-00-27-00-98-C2
#     DHCP Enabled : No
#     Autoconfiguration Enabled : Yes
#     Link-local IPv6 Address : fe80::c9af:fa02:c433:5ebf%15(Preferred)
#   = ADDRESS:192.168.56.1()
#     Subnet Mask : 255.255.255.0
#   = GATEWAY:
#     DHCPv6 IAID : 336068647
#     DHCPv6 Client DUID : 00-01-00-01-1C-9B-61-ED-8C-DC-D4-34-D4-38
#   = DNS:fec0:0:0:ffff::1%1
#     fec0 : 0:0:ffff::2%1
#     fec0 : 0:0:ffff::3%1
#     NetBIOS over Tcpip : Enabled
# Wireless LAN adapter Wireless Network Connection
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:NETGEAR WNDA3100v3 N600 Wireless Dual Band USB Adapter
#     Physical Address : B0-7F-B9-FF-3A-70
#     DHCP Enabled : Yes
#     Autoconfiguration Enabled : Yes
#     Link-local IPv6 Address : fe80::e884:fb9a:c1b3:5fbc%20(Preferred)
#   = ADDRESS:192.168.0.20()
#     Subnet Mask : 255.255.255.0
#     Lease Obtained : 14 October 2017 21:41:07
#     Lease Expires : 24 October 2017 21:41:09
#   = GATEWAY:192.168.0.1
#   = DHCP:192.168.0.1
#     DHCPv6 IAID : 464551865
#     DHCPv6 Client DUID : 00-01-00-01-1C-9B-61-ED-8C-DC-D4-34-D4-38
#   = DNS:194.168.4.100
#   = DNS:194.168.8.100
#     NetBIOS over Tcpip : Enabled
# Tunnel adapter isatap.{372DB82B-FE28-489B-B744-FC1C0F726791}
#     Media State : Media disconnected
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:Microsoft ISATAP Adapter
#     Physical Address : 00-00-00-00-00-00-00-E0
#     DHCP Enabled : No
#     Autoconfiguration Enabled : Yes
# Ethernet adapter Local Area Connection
#     Connection-specific DNS Suffix :
#   = DESCRIPTION:Realtek PCIe GBE Family Controller
#     Physical Address : 8C-DC-D4-34-D4-38
#     DHCP Enabled : Yes
#     Autoconfiguration Enabled : Yes
#     Link-local IPv6 Address : fe80::3c7a:339:64f0:2161%11(Preferred)
#   = ADDRESS:192.168.0.14()
#     Subnet Mask : 255.255.255.0
#     Lease Obtained : 14 October 2017 21:40:58
#     Lease Expires : 24 October 2017 21:40:58
#   = GATEWAY:192.168.0.1
#   = DHCP:192.168.0.1
#     DHCPv6 IAID : 244112596
#     DHCPv6 Client DUID : 00-01-00-01-1C-9B-61-ED-8C-DC-D4-34-D4-38
#   = DNS:194.168.4.100
#   = DNS:194.168.8.100
#     NetBIOS over Tcpip : Enabled



mapIpconfigs = dict()
currItf = ""
proc = subprocess.Popen(['ipconfig','/all'],stdout=subprocess.PIPE)
for currLine in proc.stdout.readlines():
	currLine = currLine.decode("utf-8").rstrip()
	if currLine:
		if currLine[0] != " ":
			currItf = currLine.strip()
			if currItf[-1] == ":":
				currItf = currItf[:-1]
			mapIpconfigs[currItf] = []
		else:
			idxColon = currLine.find(":")
			if idxColon >= 0:
				currKey = currLine[:idxColon].replace(". ","").strip()
				currVal = currLine[idxColon+1:].strip()
			else:
				currVal = currLine.strip()
			mapIpconfigs[currItf].append( (currKey, currVal))

# print(mapIpconfigs)
for key in mapIpconfigs:
	print(key)
	subMap = mapIpconfigs[key]
	# if key.startswith("Ethernet adapter") or key.startswith("Wireless LAN adapter"):
	for pr in subMap:
		if pr[0] == "IPv4 Address":
			print("  = ADDRESS:"+pr[1].replace("Preferred",""))
		elif pr[0] == "DHCP Server":
			print("  = DHCP:"+pr[1])
		elif pr[0] == "DNS Servers":
			print("  = DNS:"+pr[1])
		elif pr[0] == "Default Gateway":
			print("  = GATEWAY:"+pr[1])
		elif pr[0] == "Description":
			print("  = DESCRIPTION:"+pr[1])
		else:
			print("    %s : %s"%(pr[0],pr[1]))

La description est egale a Win32_NetworkAdapter.Name
Donc on sait quel objet creer
Faut-il prendre la surclasse CIM_NetworkAdapter ????
C est peut-etre bien d avoir le meme concept vis a vis dres adresses IP et des host ?

# Tunnel adapter isatap.{BCAE0703-FC45-4644-92D4-031350F78C6E}
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\{BCAE0703-FC45-4644-92D4-031350F78C6E}\Connection
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\{BCAE0703-FC45-4644-92D4-031350F78C6E}\Parameters\Tcpip
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\Isatap\{490D3975-90E9-43D5-9F58-CB95D81CFDB4}
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBIOS\Linkage
