#!/usr/bin/env perl

use strict;
use warnings;

use Data::ParseBinary;
use Data::Dumper;

sub hexdump ($) {
	return join(' ', map { sprintf "%02x", ord($_) } split //, $_[0]);
}


open my $fh, "<:raw", $ARGV[0] or die("Couldn't open: $!");
my $stream = CreateStreamReader(File => $fh);
my $pos = $stream->tell;

my %spu_buf;
while(1) {
	$pos = $stream->tell;
	my $header = Bytes("sync", 3)->parse($stream);
	if( $header ne "\x00\x00\x01" ) {
		printf STDERR "\@0x%04x Expected PES header, but got: %s\n",
			$pos, hexdump($header);
		exit 1;
	}
	$pos = $stream->tell;
	my $streamid = Byte("stream id")->parse($stream);

	if( $streamid == 0xba ) {
		my $ph = BitStruct("Pack header",
				Const( BitField("marker", 2), 1 ),
				BitField("SCR[32..30]", 3),
				Bit("mbs_1"),
				BitField("SCR[29..15]", 15),
				Bit("mbs_2"),
				BitField("SCR[14..0]", 15),
				Bit("mbs_3"),
				BitField("SCR ext", 9),
				#Value("SCR", sub { ((($_->ctx->{"SCR[32..30]"} << 30) |
				#                     ($_->ctx->{"SCR[29..15]"} << 15) |
				#                     ($_->ctx->{"SCR[14..0]"}  <<  0)
				#                    ) * 300 + $_->ctx->{"SCR ext"}
				#                   ) / 27000000.} ), # seconds
				Bit("mbs_4"),
				BitField("bitrate", 22),
				BitField("mbs_5", 2),
				BitField("reserved", 5),
				BitField("stuffing length", 3),
				Bytes("padding", sub { $_->ctx->{"stuffing length"} } ),
			)->parse($stream);

	} elsif( $streamid == 0xbd ) {
		my $length = UBInt16("length")->parse($stream);
		my $startpos = $stream->tell;
		my $extensions = BitStruct("extensions",
				Const( BitField("magic", 2), 2),
				BitField("PES scrambling code", 2),
				Bit("PES priority"),
				Bit("data alignment indicator"),
				Bit("copyright"),
				Bit("original"),

				Bit("PTS present"),
				Bit("DTS present"),
				Const( Bit("ESCR present"), 0 ),
				Const( Bit("ES rate present"), 0 ),
				Const( Bit("DSM trick mode"), 0 ),
				Const( Bit("additional copy info present"), 0 ),
				Const( Bit("PES CRC present"), 0 ),
				Const( Bit("PES extension present"), 0 ),

				Byte("PES header data length"),
				If( sub { $_->ctx->{"PTS present"} }, BitStruct("PTS",
					# 5 bytes
					Const( BitField("magic", 4), 0x2 ),
					BitField("PTS[32..30]", 3),
					Bit("mbs_1"),
					BitField("PTS[29..15]", 15),
					Bit("mbs_2"),
					BitField("PTS[14..0]", 15),
					Bit("mbs_3"),
				)),
				If( sub { $_->ctx->{"DTS present"} }, BitStruct("DTS",
					# 5 bytes
					Const( BitField("magic", 4), 0x2 ),
					BitField("DTS[32..30]", 3),
					Bit("mbs_1"),
					BitField("DTS[29..15]", 15),
					Bit("mbs_2"),
					BitField("DTS[14..0]", 15),
					Bit("mbs_3"),
				)),
			)->parse($stream);
		$length -= $stream->tell - $startpos;
		my $substreamid = Byte("substream ID")->parse($stream);
		$pos = $stream->tell;
		my $spu_data = Bytes("PES data", $length - 1 )->parse($stream);
		$spu_buf{$substreamid} .= $spu_data;

		while( length($spu_buf{$substreamid}) >= 2 ) {
			my $spulen = unpack "n", $spu_buf{$substreamid};
			if( $spulen == 0 ) {
				substr($spu_buf{$substreamid}, 0, 2, '');

			} elsif( length($spu_buf{$substreamid}) >= $spulen ) {
				parse_spu( substr($spu_buf{$substreamid}, 0, $spulen, ''), $pos );
				printf "%d remaining\n", length($spu_buf{$substreamid});

			} else {
				last;
			}
		}

	} elsif( $streamid == 0xbe ) {
		my $length = UBInt16("length")->parse($stream);
		Bytes("data", $length)->parse($stream); # padding

	} else {
		printf STDERR "\@0x%04x Unknown stream ID 0x%02x\n", $pos, $streamid;
		exit 1;
	}
}


sub parse_spu {
	my $stream = CreateStreamReader(StringRef => \$_[0]);

	my $length = UBInt16("")->parse($stream);
	my $data_end = UBInt16("")->parse($stream);

	if( $data_end > $length ) {
		printf STDERR "\@0x%04x SPU: data_end (0x%04x) larger than total length (0x%04x)\n", $_[1], $data_end, $length;
		exit 1;
	}

	printf "\@0x%04x +0x%x SPU\n", $_[1], $length;
}
