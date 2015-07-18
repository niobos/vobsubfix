#!/usr/bin/env perl

use strict;
use warnings;

my $fh = *STDIN;

sub try_read {
	my ($fh, $count, $incompleteok) = @_;
	my $buf;
	my $n = read $fh, $buf, $count;
	if( $n < $count ) {
		return undef if $incompleteok;
		die(sprintf "\@0x%08x : Unexpected EOF", tell($fh));
	}
	return $buf;
}

sub hexdump ($) {
	return join(' ', map { sprintf "%02x", ord($_) } split //, $_[0]);
}


my $spu_data_remaining = 0;
while(1) {
	my $sync = try_read($fh, 3, 1);
	last if ! defined $sync;
	if( $sync ne "\x00\x00\x01" ) {
		die(sprintf "\@0x%08x : Expected PES header, but got %s", tell($fh)-3, hexdump($sync));
	}

	my $streamid = try_read($fh, 1);
	$streamid = unpack "C", $streamid;

	if( $streamid == 0xba ) {
		# Pack header, copy over
		my $data = try_read($fh, 10);
		print pack "a*Ca*", $sync, $streamid, $data;
		printf STDERR "\@0x%08x : Pack, copy\n", tell($fh);

	} elsif( $streamid == 0xbe ) {
		# padding, copy over
		my $length = try_read($fh, 2);
		$length = unpack("n", $length);
		my $data = try_read($fh, $length);
		print pack "a*Cna*", $sync, $streamid, $length, $data;
		printf STDERR "\@0x%08x : padding, copy\n", tell($fh);

	} elsif( $streamid == 0xbd ) {
		# private data, inspect
		my $length = try_read($fh, 2);
		$length = unpack("n", $length);
		my $length_remaining = $length;

		my $extensions = try_read($fh, 3); $length_remaining -= 3;
		my $ext_h_len = unpack "xxC", $extensions;
		$extensions .= try_read($fh, $ext_h_len); $length_remaining -= $ext_h_len;

		my $substreamid = unpack "C", try_read($fh, 1); $length_remaining -= 1;
		warn(sprintf "\@0x%08x : substream 0x%02x instead of expected 0x20", tell($fh)-1, $substreamid) if $substreamid != 0x20;

		if( $spu_data_remaining > 0 ) {
			# We are already inside a SPU, copy over
			my $toread = $spu_data_remaining;
			$toread = $length_remaining if $length_remaining < $toread;
			my $data = try_read($fh, $toread);
			print pack "a*Cna*Ca*", $sync, $streamid, $length, $extensions, $substreamid, $data;
			printf STDERR "\@0x%08x : SPU-cont, copy 0x%04x (%d) bytes\n", tell($fh), $toread, $toread;
			$spu_data_remaining -= $toread;

		} else {
			# Start of an SPU, inspect
			my $spu_len = unpack "n", try_read($fh, 2); $length_remaining -= 2;
			my $remaining_pes_data = try_read($fh, $length_remaining);

			if( $spu_len == 0 && $length_remaining == 0 ) {
				# empty SPU, switch streamid to padding
				$substreamid = 0xbe;
				print pack "a*Cna*Cn", $sync, $streamid, $length, $extensions, $substreamid, $spu_len; # $remaining_pes_data is empty
				printf STDERR "\@0x%08x : 0-length SPU, change to padding\n", tell($fh);
			} else {
				warn(sprintf "\@0x%08x : 0-length SPU with %d bytes trailing data", tell($fh), $length_remaining) if $spu_len == 0;
				print pack "a*Cna*Cna*", $sync, $streamid, $length, $extensions, $substreamid, $spu_len, $remaining_pes_data;
				printf STDERR "\@0x%08x : 0x%04x (%d) length SPU, copy 0x%04x (%d) bytes\n", tell($fh), $spu_len, $spu_len, $length_remaining, $length_remaining;
				$spu_data_remaining = $spu_len - 2 - $length_remaining;
			}
		}

	} else {
		die(sprintf "\@0x%08x : Unknown stream id 0x%02x", tell($fh)-1, $streamid);
	}
}
