#!/usr/bin/perl
use strict;
use warnings;
use Net::DNS::RR;

my $ZONE = shift || die;

my $owner = '';
foreach my $i (0..12) {
	$owner .= chr(65+rand(26));
}

my $rr1 = Net::DNS::RR->new("$owner.$ZONE 72800 IN NS ns1.$owner.$ZONE.");
print "add " . $rr1->string . "\n";
my $rr2 = Net::DNS::RR->new("$owner.$ZONE 72800 IN NS ns2.$owner.$ZONE.");
print "add " . $rr2->string . "\n";
my $rr3 = Net::DNS::RR->new("ns1.$owner.$ZONE 72800 IN A 1.2.3.4");
print "add " . $rr3->string . "\n";
my $rr4 = Net::DNS::RR->new("ns2.$owner.$ZONE 72800 IN AAAA dead:beef::6");
print "add " . $rr4->string . "\n";
