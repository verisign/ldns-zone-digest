#!/usr/bin/perl
use strict;
use warnings;

my @dat;
my $max_a = 0;
my $max_b = 0;
my $max_c = 0;

while (<>) {
	chomp;
	next unless /./;
	my ($a,$b,$c) = split;
	$dat[$a][$b] = $c;
	$max_a = $a if $a > $max_a;
	$max_b = $b if $b > $max_b;
	$max_c = $c if $c > $max_c;
}

$max_c = $dat[0][1];

printf STDERR "max = $max_c\n";

foreach my $i (0..$max_a) {
	foreach my $j (1..$max_b) {
		printf "%d %d %f\n", $i, $j, $dat[$i][$j] / $max_c;
	}
	print "\n";
}
