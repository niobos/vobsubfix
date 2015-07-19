#!/usr/bin/env perl

use strict;
use warnings;

if( @ARGV != 1 ) {
	print STDERR "Usage: $0 vobsub.idx\n";
	exit 64;
}


if( $ARGV[0] !~ m/(.*)\.(idx|sub)$/ ) {
	printf STDERR "`%s`: not an idx or sub extension, skipping\n", $ARGV[0];
	next;
}
my $idxfilename = "$1.idx";
my $subfilename = "$1.sub";

open my $idx, "+<:encoding(utf8)", $idxfilename
	or die "Couldn't read $idxfilename: $!\n";
open my $sub, "+<:raw", $subfilename
	or die "Couldn't read $subfilename: $!\n";

my $idxpos = tell $idx;
while(my $idxline = <$idx>) {
	if( $idxline =~ m/^\s*#/ ) { # comment line
		next;
	} elsif( $idxline !~ m/^timestamp: ([^,]+), filepos: (.*)$/ ) {
		# none interesting lines
		next;
	}
	my ($timestamp, $subpos) = ($1, hex($2));

	printf "timestamp: %s, filepos: %08x: ", $timestamp, $subpos;

	seek $sub, $subpos, 0; # Go to this subtitle in the sub file
	# Expect a Pack header
	my $buf;
	read $sub, $buf, 4;
	if( $buf ne "\x00\x00\x01\xba" ) {
		die(sprintf("sub @ 0x%08x : Expected PES header of PACK\n", $subpos));
	}
	seek $sub, 10, 1; # seek over the data
	read $sub, $buf, 4;
	if( $buf ne "\x00\x00\x01\xbd" ) {
		die(sprintf("sub @ 0x%08x : Expected PES header of private\n", $subpos+14));
	}

	read $sub, my $peslength, 2; $peslength = unpack "n", $peslength;
	seek $sub, 2, 1; # seek first 2 bytes of extensions
	read $sub, my $pes_header_extra_len, 1; $pes_header_extra_len = unpack "C", $pes_header_extra_len;
	seek $sub, $pes_header_extra_len, 1; # Seek to end of header

	read $sub, my $substreamid, 1; $substreamid = unpack "C", $substreamid;
	if( $substreamid != 0x20 ) {
		die(sprintf("sub @ 0x%08x : Expected substreamID 0x20\n", tell($sub)-1));
	}

	read $sub, my $spulen, 2; $spulen = unpack "n", $spulen;
	printf "SPU length %d", $spulen;

	if( $spulen == 0 ) {
		printf " removing";

		# Change streamID to padding (0xbe) in the .sub
		seek $sub, $subpos+14+3, 0;
		print $sub "\xbe";

		# Comment out this line in the .idx
		my $curpos = tell $idx; # remember where we are
		seek $idx, $idxpos, 0; # go to the beginning of this line
		print $idx "#"; # overwrite the first char with a '#'
		seek $idx, $curpos, 0; # return to where we were
	}

	printf "\n";

} continue {
	# update $idxpos to be the beginning of line
	$idxpos = tell $idx;
}

close $idx;
close $sub;
