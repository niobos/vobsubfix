#!/usr/bin/env perl

use strict;
use warnings;

use Carp;
use Data::ParseBinary;

use Data::Dumper;

sub hexdump ($) {
	return join(' ', map { sprintf "%02x", ord($_) } split //, $_[0]);
}

{
	package DS::PES;
	our @ISA = qw{Data::ParseBinary::Stream::Reader};

	sub isBitStream { return 0 };

	sub new {
		my ($class, $source) = @_;
		my $self = {
			debug => 0,
			state => 'init',
			source => $source,
			pos => 0,
			datalen => undef,
		};
		return bless $self, $class;
	}

	sub ReadBytes {
		my ($self, $count) = @_;

		my $buf = '';

		while( length $buf < $count ) {
			if( $self->{state} eq 'init' ) {
				# read new packet from underlying stream
				my $sync = ::Bytes("sync", 3)->parse($self->{source});
				if( $sync ne "\x00\x00\x01" ) {
					::croak $self->vtell . " Expected PES sync, but got: " . ::hexdump($sync);
				}

				my $streamid = ::Byte("")->parse($self->{source});
				printf STDERR "\@0x%x PES header streamID 0x%02x\n", $self->{source}->tell-4, $streamid if $self->{debug};

				if( $streamid == 0xba ) {
					::Bytes("", 10)->parse($self->{source});

				} elsif( $streamid == 0xbe ) {
					my $length = ::UBInt16("")->parse($self->{source});
					::Bytes("", $length)->parse($self->{source});

				} elsif( $streamid == 0xbd ) {
					my $length = ::UBInt16("")->parse($self->{source});
					my $pos = $self->{source}->tell;
					$self->{pos} = 0;
					my $extensions = ::BitStruct("extensions",
							::Const( ::BitField("magic", 2), 2),
							::BitField("PES scrambling code", 2),
							::Bit("PES priority"),
							::Bit("data alignment indicator"),
							::Bit("copyright"),
							::Bit("original"),

							::Bit("PTS present"),
							::Bit("DTS present"),
							::Const( ::Bit("ESCR present"), 0 ),
							::Const( ::Bit("ES rate present"), 0 ),
							::Const( ::Bit("DSM trick mode"), 0 ),
							::Const( ::Bit("additional copy info present"), 0 ),
							::Const( ::Bit("PES CRC present"), 0 ),
							::Const( ::Bit("PES extension present"), 0 ),

							::Byte("PES header data length"),
							::If( sub { $_->ctx->{"PTS present"} }, ::BitStruct("PTS",
								# 5 bytes
								::Const( ::BitField("magic", 4), 0x2 ),
								::BitField("PTS[32..30]", 3),
								::Bit("mbs_1"),
								::BitField("PTS[29..15]", 15),
								::Bit("mbs_2"),
								::BitField("PTS[14..0]", 15),
								::Bit("mbs_3"),
							)),
							::If( sub { $_->ctx->{"DTS present"} }, ::BitStruct("DTS",
								# 5 bytes
								::Const( ::BitField("magic", 4), 0x2 ),
								::BitField("DTS[32..30]", 3),
								::Bit("mbs_1"),
								::BitField("DTS[29..15]", 15),
								::Bit("mbs_2"),
								::BitField("DTS[14..0]", 15),
								::Bit("mbs_3"),
							)),
							::Bytes("padding", sub { $_->ctx->{"PES header data length"}
							                         - ($_->ctx->{"PTS present"} ? 5 : 0)
							                         - ($_->ctx->{"DTS present"} ? 5 : 0)
							                       } ),
						)->parse($self->{source});

					my $substreamid = ::Byte("substream ID")->parse($self->{source});
					$length -= $self->{source}->tell - $pos; # Remove extensions & substreamid

					if( $substreamid != 0x20 ) {
						::carp $self->vtell . " Substream ID not 0x20 but $substreamid";
						::Bytes("pes data", $length )->parse( $self->{source} );

					} else {
						printf STDERR "\@0x%x %d = 0x%x bytes of data\n", $self->{source}->tell, $length, $length if $self->{debug};
						$self->{datalen} = $length;
						$self->{state} = 'data';
					}

				} else {
					::croak $self->vtell . " Unknown stream ID $streamid";
				}

			} elsif( $self->{state} eq 'data' ) {
				# Read the requested amounts of bytes, up to the amount available
				# in this PES
				my $avail = $self->{datalen} - $self->{pos};
				my $toread = $count - length($buf);
				if( $avail < $toread ) { $toread = $avail; }
				printf STDERR "\@0x%x reading %d = 0x%x bytes\n", $self->{source}->tell, $toread, $toread if $self->{debug};
				$buf .= ::Bytes("pes data", $toread )->parse( $self->{source} );
				printf STDERR "\@0x%x read %d = 0x%x / %d = 0x%x bytes\n", $self->{source}->tell, length($buf), length($buf), $count, $count if $self->{debug};
				$self->{pos} += $toread;

				if( $self->{pos} == $self->{datalen} ) {
					$self->{state} = 'init';
				}

			} else {
				::confess "Invalid state " . $self->{state} . "\n";
			}
		}

		return $buf;
	}

	sub next_pes {
		my ($self) = @_;
		my $newpos = $self->{source}->tell + ($self->{datalen} - $self->{pos});
		$self->{source}->seek($newpos);
		$self->{state} = 'init';
	}

	sub ReadBits {
		my ($self, $bitcount) = @_;
		return $self->_readBitsForByteStream($bitcount);
	}

	sub tell {
		my $self = shift;
		return $self->{pos};
	}

	sub vtell {
		my $self = shift;
		return sprintf("PES\@0x%x parent\@0x%x", scalar($self->tell), $self->{source}->tell );
	}

	#sub seek {
	#	my ($self, $newpos) = @_;
	#}
}

open my $fh, "<:raw", $ARGV[0] or die("Couldn't open: $!");
my $s_file = CreateStreamReader(File => $fh);
my $s_pesdata = DS::PES->new($s_file);

while(1) {
	my $length = UBInt16("length")->parse($s_pesdata);
	next if $length == 0;

	my $data_end = UBInt16("data end")->parse($s_pesdata) + 2;
	if( $data_end > $length ) {
		printf STDERR "%s SPU: data_end (0x%04x) larger than total length (0x%04x)\n", $s_pesdata->vtell, $data_end, $length;
	}

	my $data = Bytes("data", $data_end - 4)->parse($s_pesdata);

	my $control_end = UBInt16("control end")->parse($s_pesdata);
	if( $control_end <= $data_end ) {
		printf STDERR "%s SPU: control_end (0x%04x) smaller than data_end (0x%04x)\n", $s_pesdata->vtell, $control_end, $data_end;
	} elsif( $control_end > $length ) {
		printf STDERR "%s SPU: control_end (0x%04x) larger than total length (0x%04x)\n", $s_pesdata->vtell, $control_end, $length;
	}

	my $control = Bytes("control", $control_end - $data_end - 2)->parse($s_pesdata);

	my $duration = UBInt16("duration")->parse($s_pesdata);
	my $control_end2 = UBInt16("control end")->parse($s_pesdata);
	if( $control_end != $control_end2 ) {
		printf STDERR "%s SPU: control_end (0x%04x) != control_end2 (0x%04x)\n", $s_pesdata->vtell, $control_end, $control_end2;
	}

	{
		my $two = Byte("0x02")->parse($s_pesdata);
		if( $two != 0x02 ) {
			printf STDERR "%s SPU: end sequence (0x%02x) != 0x02\n", $s_pesdata->vtell, $two;
		}
		my $ff = Byte("0x02")->parse($s_pesdata);
		if( $ff != 0xff ) {
			printf STDERR "%s SPU: end sequence (0x%02x) != 0xff\n", $s_pesdata->vtell, $ff;
		}
		if( $control_end % 2 ) {
			$ff = Byte("0x02")->parse($s_pesdata);
			if( $ff != 0xff ) {
				printf STDERR "%s SPU: end sequence (0x%02x) != 0xff\n", $s_pesdata->vtell, $ff;
			}
		}
	}

	printf "%s +0x%x SPU\n", $s_pesdata->vtell, $length;
}
