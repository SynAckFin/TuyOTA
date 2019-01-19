#!/usr/bin/perl
use strict;

$| = 1;
use IO::Socket;
use IO::Select;
use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;

my $LocalSSID = "";                 # The SSID of your network
my $LocalPassword = "";             # The password for your network

# Change if you want but there is no need to
my $SSID     = "ZAGDU-789";
my $Password = "un49fqxc";

my $Timeout = 30;                   # Seconds of inactivity before moving on
my $DeviceIP;                       # IP address of target device
my $WiFiDevice = "";                # Usually wlan0 - automatically detected
my $WiFiIPAddr = "10.44.57.1";      # IP assigned to wlan
my $WiFiSubnet = "";                # An approximation of APs subnet (calculated)
my $WiFiAPDevice = "wlan0";         # Device created for Access Point
my $WiFiSCDevice = "wlan0";         # Device created for Scanning and Connecting
my $WiFiAPPresent = 0;              # Device may already be there from previous run
my $WiFiSCPresent = 0;              # Device may already be there from previous run
my $APConfigFile = "hostapd.conf";  # Will be created if doesn't exist
my $DNSQsocket;                     # DNS Query socket
my $DNSRsocket;                     # DNS Response socket
my $SonoffSilence = 0;              # Only send SSID/key message once
my $Google;                         # So I know where to send DNS replies
my $GoogleAddress = sockaddr_in(53,inet_aton("8.8.8.8"));
my $DeviceList;
my $Status;                         # So I know whats happening
my $AP_IP;                          # IP address of Access Point/WiFi Connection
my $AP_SN;                          # An approximation of the Access Point's subnet
my $StageOneFirmware = "image_user2-0x81000.bin";
my $BeginStage = 1;                 # Starting stage of the script
my $StageTwoFirmware = "sonoff.bin";
my $SonoffIP = "192.168.4.1:80";    # Address for configuring device
my $FinalStageIP = "192.168.4.2";   # Address for configuring device
my $MQHost = "";                    # Host for mq. Set when receive DNS request
my $Monitor = { IOset => IO::Select->new };
my $FirmHeader = pack("H*","55aa55aa312e312e3000000000000200" .
                           "000002000000330003a674013a113d00" .
                           "03a6a70003a674013a113d000007bfaa" .
                           "55aa5500000000000000000000000000");
#
# Upgrade response dont bother editing
#
my $UpgradeResponse = '{' .
      '"result":{' .
        '"url":"http://fakewebsite/ota/tuya-sonoff.bin",' .
        '"type":0,' .
        '"size":"478491",' .
        '"md5":"79e9748319d7ad888f2deff16a87a296",' .
        '"version" :"1.1.0"' .
      '},' .
      '"e":false,' .
      '"success":true' .
    '}';

sub SetupInterface {
    my $if = shift;

    print("Getting interface into stable state\n");
    system("ip a del $FinalStageIP/24 dev $if");
    system("ip a del $WiFiIPAddr/24 dev $if");
    system("ip link set $if down");
    system("ip link set $if up");
    print("Done\n");
}
sub SetupDeviceMonitor {
    my $mon = shift;
    my $socket = IO::Socket::INET->new(
      Proto => 'udp',
      Broadcast => 1,
      LocalPort => 6666,
      ReuseAddr => 1,
    ) or die "Unable to create Device Listener socket! $!";
    my $fileno = $socket->fileno;
    $mon->{IOset}->add($socket);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_DeviceMonitorRead ];
    return $socket;
}
sub ScanForWlan {
    my $fh;

    # Scan for WiFi devices even if one has been
    # specified on the command line.
    print("Looking for WiFi device\n");
    unless( open($fh,"iwconfig 2>/dev/null |") ) {
      print("Error: $!\n");
      print("There is a problem with iwconfig\n");
      print("Make sure 'wireless tools' package is installed\n");
      exit(-1);
    };
    my $wifi;
    while(<$fh>) {
      chomp($_);
      if( my($dev,$type) = /^([^\s]+)\s+(.*)/ ) {
        if( $dev eq $WiFiAPDevice ) {
          print("Found AP device $WiFiAPDevice, marking it as present\n");
          $WiFiAPPresent = 1;
          next;
        }
        if( $dev eq $WiFiSCDevice ) {
          print("Found Scan/Connect device $WiFiSCDevice, marking it as present\n");
          $WiFiSCPresent = 1;
          next;
        }
        if( $type =~ /IEEE\s*802/ ) {
          if(length($WiFiDevice)) {
            if($WiFiDevice eq $dev) {
              $wifi = $dev;
            }
          }
          else {
            $WiFiDevice = $wifi = $dev;
          }
        }
      }
    }
    unless(close($fh)) {
      print("There is a problem with iwconfig\n");
      print("Perhaps you are not running the script as root?\n");
      exit(0);
    }
    unless(defined($wifi)) {
      print("Unable to find WiFi device\n");
      if(length($WiFiDevice)) {
        print("You specified $WiFiDevice as your device but I could not find it\n");
        print("If any devices are listed above try one of them.\n");
      }
      exit(-1);
    }
    print("Wifi device is $WiFiDevice\n");
}
sub SetupAccessPoint {
    my $mon = shift;
    my $fh;

    print("Using WiFi device $WiFiAPDevice for Access Point\n");
    unless( -r $APConfigFile ) {
      print("Creating Access Point config file $APConfigFile\n");
      open($fh,"> $APConfigFile") or die "Unable to create $APConfigFile: $!";
      print $fh "interface=$WiFiAPDevice\n";
      print $fh "wpa=2\n";
      print $fh "ssid=$SSID\n";
      print $fh "wpa_passphrase=$Password\n";
      print $fh "hw_mode=g\n";
      print $fh "channel=1\n";
      close($fh);
    }
    print("Starting Access Point with SSID $SSID\n");
    my $pid = open($fh,"hostapd hostapd.conf |");
    unless(defined($pid) && $pid > 0) {
      print("Failed to run hostapd: $!\n");
      print("Please ensure it is installed\n");
      print("Continuing in case other devices are partway through upgrade\n");
      return;
    }
    print("Giving Access Point IP address $WiFiIPAddr, pid is $pid\n");
    system("ip a add $WiFiIPAddr/24 dev $WiFiAPDevice");
    my $fileno = $fh->fileno;
    $mon->{IOset}->add($fh);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_AccessPointRead, $pid ];
    $mon->{Callbacks}{$fileno}{Close} = [ \&CB_AccessPointClose, $pid ];
}
sub SetupWiFiScan {
    my $mon = shift;
    my $fh;

    print("Setting up wifi scan\n");
    system("ip link set dev $WiFiSCDevice up");
    my $pid = (open($fh,"while true; do iwlist $WiFiSCDevice scan; sleep 5; done |"));
    unless ($pid > 0) {
      print("FAILURE\n");
    }
    my $fileno = $fh->fileno;
    $mon->{IOset}->add($fh);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_WiFiScanRead, {} ];
    $mon->{Callbacks}{$fileno}{Close} = [ \&CB_WiFiScanClose, $pid ];
}
sub SetupDHCP {
    my $mon = shift;
    # The DHCP listener
    my $sockin = IO::Socket::INET->new(
      Proto => 'udp',
#      LocalAddr => $WiFiIPAddr,
      LocalPort => 67,
      ReuseAddr => 1,
      Broadcast => 1,
    ) or die "Unable to create DHCP Listener socket! $!";
    # The DHCP sender

    # Setup an IP address table for leases
    ($WiFiSubnet) = $WiFiIPAddr =~ /(.*)[.]\d+/;
    my $Leases;
    for (2..254) {
      my $ip = "$WiFiSubnet.$_";
      $Leases->{IP}{$ip} = { IP => $ip } unless( $ip eq $WiFiIPAddr );
    }
    my $fileno = $sockin->fileno;
    $mon->{IOset}->add($sockin);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_DHCPRead, $Leases ];
}
sub SetupDNS {
    my $mon = shift;
    # The DNS listener
    my $socket = IO::Socket::INET->new(
      Proto => 'udp',
      LocalAddr => $WiFiIPAddr,
      LocalPort => 53,
      ReuseAddr => 1,
    ) or die "Unable to create DNS Listener socket! $!";
    # The DNS Sender
    my $fileno = $socket->fileno;
    $mon->{IOset}->add($socket);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_DNSRead ];
}
sub SetupMQTTListener {
    my $mon = shift;
    my $socket;

    $socket = IO::Socket::INET->new(
      Type => SOCK_STREAM,
      LocalAddr => $WiFiIPAddr,
      LocalPort => 1883,
      Listen => 1,
      ReuseAddr => 1,
    ) or die "Unable to create MQTT Listener socket! $!";
    my $fileno = $socket->fileno;
    $mon->{IOset}->add($socket);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_MQTTAccept ];
    return $socket;
}
sub SetupWebListener {
    my $mon = shift;
    my $socket;

    $socket = IO::Socket::INET->new(
      Type => SOCK_STREAM,
      LocalAddr => $WiFiIPAddr,
      LocalPort => 80,
      Listen => 1,
      ReuseAddr => 1,
    ) or die "Unable to create Web Listener socket! $!";
    my $fileno = $socket->fileno;
    $mon->{IOset}->add($socket);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_WebAccept ];
    return $socket;
}
sub SetupFinalStageListener {
    my $mon = shift;
    my $socket;

    print("Setting up listener for FinalStage\n");
    $socket = IO::Socket::INET->new(
      Type => SOCK_STREAM,
      LocalAddr => $FinalStageIP,
      LocalPort => 8080,
      Listen => 1,
      ReuseAddr => 1,
    ) or die "Unable to create FinalStage Listener on port 8080! $!";
    my $fileno = $socket->fileno;
    $mon->{IOset}->add($socket);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_FSAccept ];
    $mon->{Callbacks}{$fileno}{Timeout}  = [ \&CB_FSTimeout ];
    return $socket;
}
sub RedirectDevice {
    my $ip = shift;
    print("Redirecting device $ip to use Access Point $SSID\n");

    # Construct the packet...
    my $payload = sprintf('{"passwd":"%s","ssid":"%s","token":"EUb6IPWXYTn455"}',$Password,$SSID);
    my $pkt = pack("NNNN",0x55aa,0,1,length($payload)+8) . $payload;
    $pkt .= pack("NN",0,0xaa55);
    # Connect to the device
    my $socket;

    unless($socket = IO::Socket::INET->new(
                              PeerAddr => $ip,
                              PeerPort => 6668,
                              Proto    => "tcp",
                              Type     => SOCK_STREAM) ) {
      print("Unable to open socket to $ip: $!\n");
      print("The device might be at the next stage, ignoring for now\n");
      return;
    }

    sleep(5);
    my $n;
    eval { $n = $socket->send($pkt); };
    if($n == length($pkt)) {
      print("**** Redirect appears successful\n");
    }
    sleep(1);
    close($socket);
}
sub CheckBinaries {

    unless(-r $StageOneFirmware) {
      print("Stage One firmware not found, downloading it\n");
      system("wget","https://github.com/SynAckFin/TuyOTA/raw/master/static/image_user2-0x81000.bin");
    }
    unless(-r $StageTwoFirmware) {
      print("Stage Two firmware not found, downloading it\n");
      system("wget","https://github.com/SynAckFin/TuyOTA/raw/master/static/sonoff.bin");
    }
    unless( -s $StageOneFirmware == 239220 ) {
      printf("Error %s is wrong size, should be 239220 bytes but is actually %i\n",
                      $StageOneFirmware, -s $StageOneFirmware);
      exit(0);
    }
    unless( -s $StageTwoFirmware ==  482512 ) {
      printf("Error %s is wrong size, should be 482512 bytes but is actually %i\n",
                      $StageTwoFirmware, -s $StageTwoFirmware);
      exit(0);
    }
}
sub HandleSonoff {
    my $ap = shift;
    return if($SonoffSilence);
    if( length($LocalSSID) == 0 ) {
      print("**** You haven't configured an SSID to connect the device to\n");
      print("**** If you run again using -s and -p flags this\n");
      print("**** will attempt to configure any device that needs it\n");
      $SonoffSilence = 1;
      return 0;
    }
    print("***** Found Sonoff AP $1 ******\n");
    system("iwconfig $WiFiSCDevice mode Managed");
    system("iwconfig $WiFiSCDevice essid off");
    if(system("iwconfig $WiFiSCDevice essid $ap")) {
      print("Failed to connect to $ap\n");
      return 0;
    }
    print("***** Connected to $ap ******\n");
    sleep(2);
    if( my $sock = IO::Socket::INET->new(PeerAddr => $SonoffIP,Proto => 'tcp') ) {
      print("Sending config to $ap\n");
      $sock->send( "GET /sv?w=1%2C1&s1=$LocalSSID&p1=$LocalPassword&s2=&p2=&h=%25s-%2504d HTTP/1.1\r\n" .
                   "Host: $ap\r\n" .
                   "Connection: close\r\n" .
                   "\r\n" );
      my $rbuff;
      1 while( $sock->recv($rbuff,4096,0) );
      close($sock);
      print("***** Config sent *****\n");
    }
    else {
      print("Failed to connect to device $ap: $!\n");
      system("iwconfig $WiFiSCDevice essid off");
      return 0;
    }
    system("iwconfig $WiFiSCDevice essid off");
    return 1;
}
sub usage {
    print("usage: $0 [-t Timeout] [-b BeginStage] [-ip DeviceIP] [-s SSID] [-p password]\n");
    print("    Timeout    - Default 30. Seconds of inactivity before moving on\n");
    print("    BeginStage - Default 1. Stage to start at. Can be 1,2, or 3\n");
    print("    DeviceIP   - Default none. IP address of the target device\n");
    print("    SSID       - Your home networks SSID\n");
    print("    Password   - Your home networks Password\n");
    print("\n");
    print("Stages:\n");
    print("    Stage 1:\n");
    print("       Asks DeviceIP to move to custom Access Point (AP)\n");
    print("       Asks any device on custom AP to recheck for firmware update\n");
    print("       Hands out 1st stage firmware to any device that asks for it\n");
    print("\n");
    print("    Stage 2:\n");
    print("       Looks for a device running 1st stage firmware and installs sonoff.bin.\n");
    print("       Configures devices with SSID and Password if specified on commandline\n"); 
    exit(1);
}
sub CB_WiFiScanRead {
    my ($fh, $mon, $data) = @_;
    my $fileno = $fh->fileno;

    $_ = <$fh>;

    # This can interfer with itself so need
    # a mechanism to prevent it attaching twice
    # to the same interface
    return 0 if( exists($data->{When}) && $data->{When} > time() );
    return unless($_ =~ s/^\s*ESSID(.*)/$1/);
    if( $_ =~ /FinalStage/) {
      print("***** FinalStage Detected ******\n");
      system("ip link set $WiFiSCDevice down");
      system("iwconfig $WiFiSCDevice mode Managed");
      system("iwconfig $WiFiSCDevice essid off");
      system("ip link set $WiFiSCDevice up");
      if(system("iwconfig $WiFiSCDevice essid FinalStage")) {
        print("Failed to connect to FinalStage\n");
        return 0;
      }
      print("***** Connected to FinalStage ******\n");
      $data->{When} = time() + 20;
      return 1;
    }
    elsif( $_ =~ /"(sonoff-[\dA-F]+)"/i ) {
      return 0 if(exists($data->{Sonoff}{$1}) && $data->{Sonoff}{$1}{Retry} > time());
      $data->{When} = time() + 20;
      $data->{Sonoff}{$1}{Retry} = time() + 25;
      return HandleSonoff($1);
    }
#    print("$_\n");
    return 0;
}
sub CB_WiFiScanClose {
    my ($fh, $mon, $pid) = @_;
    kill(9, $pid) if( $pid > 0 );
    $mon->{IOset}->remove($fh);
    close($fh);
}
sub CB_AccessPointRead {
    my ($fh, $mon) = @_;
    my $rbuff;
    my $fileno = $fh->fileno;

    $_ = <$fh>;
    if(length($_)) {
#      print "AP: $_";
      return 0;
    }
    print("***** Access Point has Shutdown *****\n");
    $mon->{IOset}->remove($fileno);
    delete($mon->{Callbacks}{$fileno});
    close($fh);
    return 0;
}
sub CB_AccessPointClose {
    my ($fh, $mon, $pid) = @_;
    kill(9, $pid) if( $pid > 0 );
    $mon->{IOset}->remove($fh);
    delete($mon->{Callbacks}{$fh->fileno});
    close($fh);
}
sub CB_DeviceMonitorRead {
    my $socket = shift;
    my $pkt;

    $socket->recv($pkt,512,0);
    my $ip;
    my $gwID;
    return 0 unless( $pkt =~ /"ip":"(.*?)"/i );
    $ip = $1;
    return 0 unless( $pkt =~ /"gwId":"(.*?)"/i );
    $gwID = $1;
    if( exists($DeviceList->{$gwID}) ) {
      if( $DeviceList->{$gwID} != $ip ) {
        print("**** Device $gwID has changed IP from $DeviceList->{$gwID} to $ip\n");
        $DeviceList->{$gwID} = $ip;
        return 1;
      }
    }
    else {
      print("**** New device detected. ID: $gwID IP:$ip\n");
      $DeviceList->{$gwID} = $ip;
      if( defined($DeviceIP) && $ip eq $DeviceIP ) {
        print("Asking device to move networks and upgrade...\n");
        RedirectDevice($ip);
        return 1;
      }
      my ($devsn) = $ip =~ /(.*)[.]/;
      if( $devsn eq $WiFiSubnet ) {
        print("**** New device looks to be part way through upgrading\n");
        print("**** Forcing it to retry the upgrade\n");
        RedirectDevice($ip);
        return 1;
      }
      
    }
    return 0;
}
sub CB_DHCPRead {
    my ($socket, $mon, $leases) = @_;
    my $pkt;
    my $out;
    my $rv = $socket->recv($pkt,512,0);
    if( length($pkt) < 243 ) {
      print("Bad DHCP request - ignoring\n");
      return 0;
    }
    # Decode the packet
    my ($op,$htype,$hlen,$hops,$xid,$secs,$flags,$pkt) = unpack("CCCCNnna*",$pkt);
    # Might not be for me.
    return if( $op != 1 || $htype != 1 || $hlen != 6 || $hops != 0 );
    my ($cip,$yip,$sip,$gip,$hwaddr,$pad,$sname,$file,$cookie,$options) = unpack("NNNNa6a10Z64Z128Na*",$pkt);
    my $mac = sprintf("%02x:%02x:%02x:%02x:%02x:%02x",unpack("C*",$hwaddr));
    # Have we come accross this before?
    my $ip;
    if( exists($leases->{MAC}{$mac}) ) {
      $ip = $leases->{MAC}{$mac}{IP};
    }
    else {
      for ( values %{$leases->{IP}} ) {
        next if( exists( $_->{MAC} ) );
        $ip = $_;
        $ip->{MAC} = $mac;
        $leases->{MAC}{$mac}{IP} = $ip;
        last;
      }
    }
    # Start building reply packet
    $pkt = pack("CCCCNnnN",2,$htype,$hlen,$hops,$xid,$secs,$flags,$cip);
    # Give it its IP
    $pkt .= pack("CCCC",split(/[.]/,$ip->{IP}));
    # Next server and relay are 0.0.0.0
    $pkt .= pack("NN",0,0);
    # Add Hardware and padding
    $pkt .= $hwaddr . $pad;
    # Add server name
    $pkt .= pack("Z64","MyDHCP");
    # Add a boot file
    $pkt .= pack("Z128","SomeFile");
    # Add magic cookie
    $pkt .= pack("N",$cookie);
    # Go through the options to find packet type
    while(length($options) > 0) {
      # Get type and length
      my ($opt,$len);
      ($opt,$len,$options) = unpack("CCa*",$options);
      if( $opt == 53 ) {
        my ($t) = unpack("C",$options);
        printf("%s %s %s\n",$t == 1 ? "DHCP Discover" : "DHCP Request",$mac,$ip->{IP});
        $pkt .= pack("CCC",$opt,1,$t == 1 ? 2 : 5);
      }
      last if( $opt == 255 );
      (undef,$options) = unpack("a$len",$options);
    }
    # DHCP Server
    $pkt .= pack("CCCCCC",54,4,split(/[.]/,$WiFiIPAddr));
    # Lease time
    $pkt .= pack("CCN",51,4,3600);
    # Subnet
    $pkt .= pack("CCCCCC",1,4,255,255,255,0);
    # Router
    $pkt .= pack("CCCCCC",3,4,split(/[.]/,$WiFiIPAddr));
    # DNS server
    $pkt .= pack("CCCCCC",6,4,split(/[.]/,$WiFiIPAddr));
    # Domain Name
    $pkt .= pack("CCa*",15,length("nowhere.com"),"nowhere.com");
    # End
    $pkt .= pack("CC",255,0);
    $pkt .= pack("Z","");
    system("arp -s $ip->{IP} $mac");
    $rv = sockaddr_in(68,inet_aton($ip->{IP}));
    $socket->send($pkt,0,$rv);
    return 0;
}
sub CB_DNSRead {
    my $socket = shift;

    my $pkt;
    my $sender = $socket->recv($pkt,512,0);

    my $pktcpy = $pkt;
    my ( $ident, $flags, $qdc, $anc, $nsc, $arc, $pkt ) = unpack("nnnnnna*",$pkt);

    # Only going to handle standard queries with one question
    # Just drop it if outside parameters
    if( $flags != 0x0100 || $qdc != 1 ) {
      return 0;
    }
#    printf("%s\n", $flags & 0x8000 ? "Response" : "Query");
#    printf("Ident: %04x\n", $ident );
    
#    printf("%04x %04x %04x %04x %04x %04x\n",$ident, $flags, $qdc, $anc, $nsc, $arc);
    my $query = "";
    my $question = $pkt;
    for( ( my $l, $pkt ) = unpack("Ca*",$pkt); $l ; ( $l, $pkt ) = unpack("Ca*",$pkt) ) {
      (my $part, $pkt) = unpack("a${l}a*",$pkt);
      $query .= $part . ".";
    }
    $query = lc($query);
    print("Received DNS query for $query\n");
    $MQHost = $query if( $query =~ /^mq/ );
    print("Sending $WiFiIPAddr as response\n");
    my $response = pack("nnnnnn",$ident, 0x8180, 1, 1, 0, 0);
    # Append the question;
    $response .= $question;
    # Add pointer to domain name, type, class , ttl
    $response .= pack("nnnN",0xc00c,1,1,60);
    # Append the answer
    $response .= pack("nCCCC",4,split(/[.]/,$WiFiIPAddr));
    # Send it to the device
    $socket->send($response,0,$sender);
    return 0;
}
sub CB_MQTTAccept {
    my ($socket,$mon) = @_;

    print("Accepting MQTT connection, forwarding to $MQHost\n");
    my $client = $socket->accept or return print "Error accepting MQTT request: $!\n";
    # This should happen until DNS has been queried
    # If it does then just should it down
    if( length($MQHost) <= 0 ) {
      print("$MQHost not set\n");
      close($client);
      return 0;
    }
    my $remote;
    unless( $remote = IO::Socket::INET->new(
                                Type => SOCK_STREAM,
                                PeerHost => "$MQHost",
                                PeerPort => 1883,
                                Proto => 'tcp', ) ) {
      print "Unable to reach $MQHost: $!";
      close($client);
      return 0;
    }
    my $fileno = $client->fileno;
    $mon->{IOset}->add($client);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_Proxy, $remote ];
    $fileno = $remote->fileno;
    $mon->{IOset}->add($remote);
    $mon->{Callbacks}{$fileno}{Read}  = [ \&CB_Proxy, $client ];
    return 0;
}
sub CB_WebAccept {
    my $sock = shift;

    print("Receiving www request\n");
    my $client = $sock->accept or return print "Error accepting WWW request: $!\n";

    my $io = IO::Select->new;
    $io->add($client);

    # Get the request and use a 10 second timeout
    # so dont wait forever for client
    my $request = "";
    while( $request !~ /\r\n\r\n/s ) {
      my $rbuff;
      $io->can_read(10) or return print("Timed out waiting for request\n");
      $client->recv($rbuff,4096,0);
      if( length($rbuff) <= 0 ) {
        print("REQ: $request");
        print("Client closed connection while receiving request: $!\n");
        return;
      }
      $request .= $rbuff;
    }
    # Handle firmware request directly 
    if ( $request =~ /tuya-sonoff.bin/ ) {
      # Does it want the header of the firmware?
      print("Sending firmware $StageOneFirmware\n");
#      print($request);
      unless( $request =~ /Range: bytes=(\d+)-(\d+)/ ) {
        $client->send("HTTP/1.1 500 Server error\r\n");
      }
      else {
        my $start = $1;
        my $end   = $2;
        my $length = $end - $start + 1;
        my $firmsize = -s $StageOneFirmware;
        my $size = $firmsize * 2 + 51;
        $client->send("HTTP/1.1 206 Partial Content\r\n" .
                      "Content-Length: $length\r\n" . 
                      "Content-Range: bytes $start-$end/$size\r\n" . 
                      "Connection: close\r\n" .
                      "Content-Type: application/octet-stream\r\n" .
                      "\r\n");
        if( $1 == 0 ) {
          $client->send($FirmHeader);
        }
        else {
          my $fh;
          open($fh,"< $StageOneFirmware");
          # Need to calculate the offset into the file
          # based upon start position
          my $offset = $start;
          # Remove header bytes from offset
          $offset -= 51;
          # Remove first firmware length if it want second
          $offset -= $firmsize if $offset >= $firmsize;
          seek($fh, $offset, 0);
          print("Sending bytes $start-$end from offset $offset\n");
          my $rbuff;
          while( read($fh,$rbuff,$length > 4096 ? 4096 : $length) && $length > 0 ) {
            $client->send($rbuff);
          }
        }
      }
      return;
    }

    # Request might have some content so make sure
    # that we actually have it
    if( $request =~ /^Content-Length:\s+(\d+).*\r\n\r\n(.*)/ms ) {
      my $cl = $1 - length($2);
      while( $cl > 0 ) {
        print("Fetching Request Content\n");
        $io->can_read(10) or return print("Timed out waiting for content\n");
        my $rbuff;
        $client->recv($rbuff,$cl,0);
        if( length($rbuff) <= 0 ) {
          print("Client closed connection while receiving content: $!\n");
          return;
        }
        $cl -= length($rbuff);
        $request .= $rbuff;
      }
    }
    # Extract the url for logging
    if( $request =~ /^\w+\s(.*?)&/ ) {
      print("URL: $1\n");
    }
    # Extract the host from the request
    unless( $request =~ /^Host:\s+(.*?)\s*(\n|\r)/mi ) {
      print("Unable to interpret request, abandoning\n");
      return;
    }
    my $host = $1;
    # Change connection type to close
    $request =~ s/^Connection:\s+(.*?)(\n|\r)$/Connection: close/m;
    # Connect to remote host
    my $remote = IO::Socket::INET->new(
      Type => SOCK_STREAM,
      PeerHost => $host,
      PeerPort => 80,
      Proto => 'tcp',
    ) or die "Unable to reach $host: $!";
    # Send the request;
    $remote->send($request);
    # Set up for reply
    $io->remove($client);
    $io->add($remote);
    #
    # Should I intercept or let it pass through?
    #
    if ( $request =~ /tuya.device.upgrade.silent.get/ ) {
      # Fake it
      my $response = "HTTP/1.1 200 OK\r\n" .
                     "Content-Type: application/json\r\n" .
                     "Content-Length: " . length($UpgradeResponse) . "\r\n" .
                     "Connection: close\r\n" .
#                     "Content-Language: zh-CN\r\n" .
#                     "Server: Apache-Coyote/1.1\r\n" .
                     "\r\n" .
                     $UpgradeResponse;
      $client->send($response);
      print("Sent upgrade response\n");
      return 1;
    }
    else {
      while($io->can_read(30)) {
        my $rbuff;
        $remote->recv($rbuff,4096,0);
        last if(length($rbuff) <= 0);
        $client->send($rbuff);
        if( $rbuff =~ m{(HTTP/1.1 \d+ .*)} ) {
          print("Response: $1\n");
        }
        if( $rbuff =~ /\r\n\r\n({.+})/s ) {
          print("$1\n");
        }
      }
    }
    return 0;
}
sub CB_FSAccept {
    my $sock = shift;

    print("***** Receiving FinalStage Request ****\n");
    my $client = $sock->accept or return print "Error accepting WWW request: $!\n";

    my $io = IO::Select->new;
    $io->add($client);

    # Get the request and use a 3 second timeout
    # so dont wait forever for client
    my $request = "";
    while( $request !~ /\r\n\r\n/s ) {
      my $rbuff;
      $io->can_read(3) or return print("Timed out waiting for request\n");
      $client->recv($rbuff,4096,0);
      if( length($rbuff) <= 0 ) {
        print("REQ: $request");
        print("Client closed connection while receiving request: $!\n");
        return;
      }
      $request .= $rbuff;
    }
    return 0 unless( $request =~ /image_arduino.bin/ );
    print("Sending firmware $StageTwoFirmware\n");
    my $length = -s $StageTwoFirmware;
    $client->send("HTTP/1.1 200 OK\r\n" .
                  "Content-Length: $length\r\n" . 
                  "Connection: close\r\n" .
                  "Content-Type: application/octet-stream\r\n" .
                  "\r\n");
    my $fh;
    open($fh,"<$StageTwoFirmware");
    my $rbuff;
    my $sent;
    while(read($fh,$rbuff,4096)) {
      $client->send($rbuff);
      $sent += length($rbuff);
    }
    if($sent == $length) {
      print("***** Tasmota Firmware sent to device ******\n");
      return 1;
    }
    return 0;
}
sub CB_Proxy {
    my ($src,$mon,$dst) = @_;
    my $rbuff;
    $src->recv($rbuff,4096,0);
    if(length($rbuff) <= 0) {
      delete($mon->{Callbacks}{$src->fileno});
      delete($mon->{Callbacks}{$dst->fileno});
      $mon->{IOset}->remove($src);
      $mon->{IOset}->remove($dst);
      close($src);
      close($dst);
    }
    else {
      $dst->send($rbuff,0);
    }
    return 0;
}
sub MonitorActivity {
    my $mon = shift;
    my $LastActivity = time();
    while( my @handles = $mon->{IOset}->can_read($Timeout)) {
      for ( @handles ) {
        my $fileno = $_->fileno;
        my ( $exec, @args ) = @{$mon->{Callbacks}{$fileno}{Read}};
        $LastActivity = time() if &$exec($_, $mon,@args);
      }
      last if( (time() - $LastActivity) > $Timeout);
    }
}
sub MonitorShutdown {
    my $mon = shift;
    print("Shutting down...\n");
    for ( $mon->{IOset}->handles ) {
      my $fileno = $_->fileno;
      if( exists( $mon->{Callbacks}{$fileno}{Close} ) ) {
        my ( $exec, @args ) = @{$mon->{Callbacks}{$fileno}{Close}};
        &$exec($_, $mon,@args);
      }
      else {
        $mon->{IOset}->remove($_);
        close($_);
      }
    }
}
sub END {
    print("Exiting....\n");
    MonitorShutdown($Monitor);
}
#######################################################
#  ____  _             _         _   _                #
# / ___|| |_ __ _ _ __| |_ ___  | | | | ___ _ __ ___  #
# \___ \| __/ _` | '__| __/ __| | |_| |/ _ | '__/ _ \ #
#  ___) | || (_| | |  | |_\__ \ |  _  |  __| | |  __/ #
# |____/ \__\__,_|_|   \__|___/ |_| |_|\___|_|  \___| #
#                                                     #
#######################################################
while(@ARGV) {
  my $arg = shift @ARGV;
  if( $arg eq "-s" ) {
    $LocalSSID = shift @ARGV || "";
    $LocalSSID =~ s/([^\w])/sprintf("%%%02x",ord($1))/egi;
  }
  elsif( $arg eq "-p" ) {
    $LocalPassword = shift @ARGV || "";
    $LocalPassword =~ s/([^\w])/sprintf("%%%02x",ord($1))/egi;
  }
  elsif( $arg eq "-b" ) {
    $BeginStage = shift @ARGV || 1;
    $BeginStage = 1 unless $BeginStage =~ /^\d+$/;
  }
  elsif( $arg eq "-t" ) {
    $Timeout = shift @ARGV || 30;
    $Timeout = 1 unless $Timeout =~ /^\d+$/;
  }
  elsif( $arg eq "-ip" ) {
    $DeviceIP = shift @ARGV || "";
  }
  else {
    print("Unknown option $arg\n");
    usage();
  }
}
SetupDeviceMonitor($Monitor);
CheckBinaries();
if( $BeginStage <= 1 ) {
  SetupInterface($WiFiAPDevice);
  SetupAccessPoint($Monitor);
  SetupDHCP($Monitor);
  SetupDNS($Monitor);
  SetupMQTTListener($Monitor);
  SetupWebListener($Monitor);
  RedirectDevice($DeviceIP) if(length($DeviceIP));
  MonitorActivity($Monitor);
  MonitorShutdown($Monitor);
}
print("Setting up IP Address $FinalStageIP for Final Stages\n");
SetupInterface($WiFiSCDevice);
system("ip a add $FinalStageIP/24 dev $WiFiSCDevice");

SetupWiFiScan($Monitor);
SetupFinalStageListener($Monitor);
MonitorActivity($Monitor);
MonitorShutdown($Monitor);
SetupInterface($WiFiSCDevice);

print("Finished\n");
1;
