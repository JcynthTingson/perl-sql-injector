#!/usr/bin/perl

use strict;
use IO::Socket;

my $usage = "./bg<host> <port>\n";
my $host = shift or die $usage;
my $port = shift or die $usage;
my $buf;
my $sock = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto => "tcp"
) || die "Cannot connect to " . $host;
$sock->send("HEAD / HTTP/1.1\r\n");
$sock->send("\r\n");
$sock->send("\r\n");
$sock->recv($buf, 2048);
my @buf = split("\n", $buf);
foreach(@buf){
    if(m/^Server:(.*)/){
        print "Web server found: ", $1, "\n";
    }
}

END {
    $sock->close();
}