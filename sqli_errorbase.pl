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