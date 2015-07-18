Introduction
============

[SubRip] is a subtitle OCR program for Windows. It can take a (set of)
VOB-files, and OCR from there, but it can also read in a pair of .idx/.sub
files.

This last format comes in handy when you want to include the (bitmap) subs in
an MP4 file, and OCR them later: [MP4Box] can extract a VobSub track from an
MP4 file in to a idx/sub pair.

Unfortunately, I had problems with this workflow: after each subtitle image,
SubRip added a ghost image. The ghost image contained half of the lines of the
previous image, and thus looked interlaced.

This project is my quest to figure out what caused it, and to fix it. But since
I don't have any Delphi experience, I can't fix SubRip itself, so I made a
patch-script to fix it externally.

[SubRip]: http://subrip.sourceforge.net/
[MP4Box]: https://gpac.wp.mines-telecom.fr/mp4box/


Details
=======

The problem seems to be that the MP4Box output contains 0-length SPU's, which
SubRip tries to parse. My guess is that SubRip doesn't clean up his memory
before parsing a new SPU, and hence the ghost of the previous image.

This script just goes through the sub-file, and replace the 0-length SPU
packets with padding packets.
