#!/usr/bin/env perl

use strict;
use warnings;

use Data::ParseBinary;
use Data::Dumper;

my $parser_pes = Struct("MPEG-PES",
	Magic("\x00\x00\x01"),
	OneOf( Byte("stream ID"), [0xba, 0xbd, 0xbe] ),
	Switch("data", sub { $_->ctx->{"stream ID"} }, {
		0xba => BitStruct("Pack header",
				BitField("marker", 2),
				BitField("SC[32..30]", 3),
				Bit("mbs_1"),
				BitField("SC[29..15]", 15),
				Bit("mbs_2"),
				BitField("SC[14..0]", 15),
				Bit("mbs_3"),
				BitField("SCR ext", 9),
				Bit("mbs_4"),
				BitField("bitrate", 22),
				BitField("mbs_5", 2),
				BitField("reserved", 5),
				BitField("stuffing length", 3),
				Bytes("padding", sub { $_->ctx->{"stuffing length"} } ),
			),
		0xbd => Struct("private PES",
				UBInt16("length"),
				Anchor("PES start"),
				BitStruct("extensions",
					Const( BitField("magic", 2), 2),
					BitField("PES scrambling code", 2),
					Bit("PES priority"),
					Bit("data alignment indicator"),
					Bit("copyright"),
					Bit("original"),

					Bit("PTS present"),
					Bit("DTS present"),
					OneOf( Bit("ESCR present"), [0] ),
					OneOf( Bit("ES rate present"), [0] ),
					OneOf( Bit("DSM trick mode"), [0] ),
					OneOf( Bit("additional copy info present"), [0] ),
					OneOf( Bit("PES CRC present"), [0] ),
					OneOf( Bit("PES extension present"), [0] ),

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
				),
				Byte("substream ID"),
				Bytes("PES data", sub { $_->ctx->{"length"} - ($_->stream->tell-$_->ctx->{"PES start"}) } ),
			),
		0xbe => Struct("padding PES",
				UBInt16("length"),
				Anchor("PES start"),
				Bytes("PES data", sub { $_->ctx->{"length"} - ($_->stream->tell-$_->ctx->{"PES start"}) } ),
			),
	}),
);

my $parser_spu = Struct("SPU",
	UBInt16("length"),
	If( sub { $_->ctx->{"length"} }, Struct("SPU data",
		UBInt16("data end"),
		Bytes("data", sub { $_->ctx->{"data end"}-2 } ),
		UBInt16("control end"),
		Anchor("control start"),
		Bytes("control", sub { $_->ctx->{"control end"}-$_->ctx->{"control start"} } ),
		UBInt16("duration", 2),
		UBInt16("control end2"),
		Byte("0x02"),
		Byte("0xff"),
		If( sub { $_->stream->tell % 2 }, Byte("0xff_") ),
	)),
);

open my $fh, "<", $ARGV[0] or die("Couldn't open: $!");
my $stream = CreateStreamReader(File => $fh);

my $buf;
while(1) {
	#printf "\@0x%04x ", $stream->tell;
	my $pes = $parser_pes->parse($stream);
	#printf "-0x%04x PES id: 0x%02x\n", $stream->tell, $pes->{"stream ID"};
	#print Dumper($pes);

	next unless $pes->{"stream ID"} == 0xbd;

	$buf .= $pes->{"data"}->{"PES data"};
	my $spu;
	eval { $spu = $parser_spu->parse($buf); };
	next unless defined $spu;
	$buf = '';
	if( $spu->{"length"} > 0 ) {
		$spu->{"SPU data"}->{"data"} = length $spu->{"SPU data"}->{"data"};
		$spu->{"SPU data"}->{"control"} = length $spu->{"SPU data"}->{"control"};
		print Dumper($spu);
		if( $spu->{"SPU data"}->{"control end"} != $spu->{"SPU data"}->{"control end2"} ) {
			die("Invalid SPU, file pos " . sprintf("0x%x = %d", $stream->tell, $stream->tell));
		}
	}
}

