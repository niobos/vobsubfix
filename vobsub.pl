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

			last_pts => undef,
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
								::Value("PTS", sub { ($_->ctx->{"PTS[32..30]"} << 30 |
								                      $_->ctx->{"PTS[29..15]"} << 15 |
								                      $_->ctx->{"PTS[14..0]"}  <<  0
								                     ) / 90000. } ),
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
								::Value("DTS", sub { ($_->ctx->{"DTS[32..30]"} << 30 |
								                      $_->ctx->{"DTS[29..15]"} << 15 |
								                      $_->ctx->{"DTS[14..0]"}  <<  0
								                     ) / 90000. } ),
							)),
							::Bytes("padding", sub { $_->ctx->{"PES header data length"}
							                         - ($_->ctx->{"PTS present"} ? 5 : 0)
							                         - ($_->ctx->{"DTS present"} ? 5 : 0)
							                       } ),
						)->parse($self->{source});

					if( $extensions->{"PTS present"} ) {
						$self->{"last PTS"} = $extensions->{"PTS"}->{"PTS"};
						printf STDERR "\@0x%x PES header PTS: %f\n", $self->{source}->tell, $extensions->{"PTS"}->{"PTS"} if $self->{debug};
					}

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
				my $toread = $count - length($buf);
				if( $self->{datalen} < $toread ) { $toread = $self->{datalen}; }
				printf STDERR "\@0x%x reading %d = 0x%x bytes\n", $self->{source}->tell, $toread, $toread if $self->{debug};
				$buf .= ::Bytes("pes data", $toread )->parse( $self->{source} );
				$self->{datalen} -= $toread;
				$self->{pos} += $toread;
				printf STDERR "\@0x%x read %d = 0x%x / %d = 0x%x bytes\n", $self->{source}->tell, length($buf), length($buf), $count, $count if $self->{debug};

				if( $self->{datalen} == 0 ) {
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
		my $newpos = $self->{source}->tell + $self->{datalen};
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
		return sprintf("\@0x%x", $self->{source}->tell );
	}

	#sub seek {
	#	my ($self, $newpos) = @_;
	#}
}

open my $fh, "<:raw", $ARGV[0] or die("Couldn't open: $!");
my $s_file = CreateStreamReader(File => $fh);
my $s_pesdata = DS::PES->new($s_file);

while(1) {
	my $startpos = $s_pesdata->tell;
	my $length = UBInt16("length")->parse($s_pesdata);
	if( $length == 0 ) {
		printf "%s (%f) : empty SPU\n", $s_pesdata->vtell, $s_pesdata->{"last PTS"};
		next;
	}

	my $next_control_start = UBInt16("control start")->parse($s_pesdata);
	if( $next_control_start > $length ) {
		printf STDERR "%s SPU: next_control_start (0x%04x) larger than total length (0x%04x)\n", $s_pesdata->vtell, $next_control_start, $length;
	}

	my $data = Bytes("data", $next_control_start - 4)->parse($s_pesdata);

	my $control_start;
	do {
		$control_start = $next_control_start;
		my $delay = UBInt16("delay")->parse($s_pesdata);
		$next_control_start = UBInt16("control start")->parse($s_pesdata);
		if( $next_control_start > $length ) {
			printf STDERR "%s SPU: next_control_start (0x%04x) larger than total length (0x%04x)\n", $s_pesdata->vtell, $next_control_start, $length;
		}

		printf "%s %f : ", $s_pesdata->vtell, $s_pesdata->{"last PTS"} + ($delay<<10)/90000.;

		while(1) {
			my $cmd = Byte("command")->parse($s_pesdata);
			if( $cmd == 0x00 ) {
				printf "<force> ";

			} elsif( $cmd == 0x01 ) {
				printf "<start> ";

			} elsif( $cmd == 0x02 ) {
				printf "<stop> ";

			} elsif( $cmd == 0x03 ) {
				my $palette = Bytes("palette", 2)->parse($s_pesdata);
				my @palette = map { hex($_) } split //, unpack "H4", $palette;
				printf "<palette %s> ", join(' ', @palette);

			} elsif( $cmd == 0x04 ) {
				my $palette = Bytes("palette", 2)->parse($s_pesdata);
				my @palette = map { hex($_) } split //, unpack "H4", $palette;
				printf "<alpha %s> ", join(' ', @palette);

			} elsif( $cmd == 0x05 ) {
				my $coords = Bytes("coords", 6)->parse($s_pesdata);
				$coords = BitStruct("coords",
						BitField("c1", 12),
						BitField("cl", 12),
						BitField("r1", 12),
						BitField("rl", 12),
					)->parse($coords);
				printf "<coords c[%d;%d] r[%d;%d]> ", $coords->{c1}, $coords->{cl},
													  $coords->{r1}, $coords->{rl};

			} elsif( $cmd == 0x06 ) {
				my $coords = Bytes("coords", 4)->parse($s_pesdata);
				$coords = Struct("coords",
						UBInt16("1st"),
						UBInt16("2nd"),
					)->parse($coords);
				printf "<pos %d %d> ", $coords->{"1st"}, $coords->{"2nd"};

			} elsif( $cmd == 0xff ) {
				printf "<end> ";
				last;

			} else {
				printf "<0x%02x ?", $cmd;
				last;
			}
		}

		print "\n";

	} while( $next_control_start != $control_start );

	my $pad_len = $startpos+$length - $s_pesdata->tell;
	Bytes("padding", $pad_len)->parse($s_pesdata);
}
