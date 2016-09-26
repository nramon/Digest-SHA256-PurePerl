# Copyright (C) 2016 Ramon Novoa <ramonnovoa@gmail.com>
# 
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# 
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.
package Digest::SHA256::PurePerl;

use strict;
use warnings;
use vars qw($VERSION @ISA %EXPORT_TAGS @EXPORT_OK @EXPORT);

$VERSION = '1.0.0';

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration use Digest::SHA256::PurePerl ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
require Exporter;
@ISA = qw(Exporter AutoLoader);
%EXPORT_TAGS = ('all' => [ qw() ]);
@EXPORT_OK = (@{$EXPORT_TAGS{'all'}});
@EXPORT = qw(sha256);

###############################################################################
###############################################################################
## Implementation of the SHA256 message-digest algorithm.
###############################################################################
###############################################################################

# 2 to the power of 32.
use constant POW232 => 2**32;

# Fixed constants. See: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
# First 32 bits of the fractional parts of the cube roots of the first 64
# primes.
my @K = (
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

###############################################################################
# Return the SHA256 checksum of the given string as a hex string.
# Pseudocode from: http://en.wikipedia.org/wiki/SHA-2#Pseudocode
###############################################################################
sub sha256 {
	my $str = shift;

	# No input!
	if (!defined($str)) {
		return "";
	}

	# Note: All variables are unsigned 32 bits and wrap modulo 2^32 when
	# calculating.

	# First 32 bits of the fractional parts of the square roots of the first 8
	# primes.
	my $h0 = 0x6a09e667;
	my $h1 = 0xbb67ae85;
	my $h2 = 0x3c6ef372;
	my $h3 = 0xa54ff53a;
	my $h4 = 0x510e527f;
	my $h5 = 0x9b05688c;
	my $h6 = 0x1f83d9ab;
	my $h7 = 0x5be0cd19;

	# Pre-processing.
	my $msg = unpack ("B*", pack ("A*", $str));
	my $bit_len = length ($msg);

	# Append "1" bit to message.
	$msg .= '1';

	# Append "0" bits until message length in bits = 448 (mod 512).
	$msg .= '0' while ((length ($msg) % 512) != 448);

	# Append bit /* bit, not byte */ length of unpadded message as 64-bit
	# big-endian integer to message.
	$msg .= unpack ("B32", pack ("N", $bit_len >> 32));
	$msg .= unpack ("B32", pack ("N", $bit_len));

	# Process the message in successive 512-bit chunks.
	for (my $i = 0; $i < length ($msg); $i += 512) {

		my @w;
		my $chunk = substr ($msg, $i, 512);

		# Break chunk into sixteen 32-bit big-endian words.
		for (my $j = 0; $j < length ($chunk); $j += 32) {
			push (@w, unpack ("N", pack ("B32", substr ($chunk, $j, 32))));
		}

		# Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
		for (my $i = 16; $i < 64; $i++) {
			my $s0 = rightrotate($w[$i - 15], 7) ^ rightrotate($w[$i - 15], 18) ^ ($w[$i - 15] >> 3);
			my $s1 = rightrotate($w[$i - 2], 17) ^ rightrotate($w[$i - 2], 19) ^ ($w[$i - 2] >> 10);
			$w[$i] = ($w[$i - 16] + $s0 + $w[$i - 7] + $s1) % POW232;
		}

		# Initialize working variables to current hash value.
		my $a = $h0;
		my $b = $h1;
		my $c = $h2;
		my $d = $h3;
		my $e = $h4;
		my $f = $h5;
		my $g = $h6;
		my $h = $h7;

		# Compression function main loop.
		for (my $i = 0; $i < 64; $i++) {
			my $S1 = rightrotate($e, 6) ^ rightrotate($e, 11) ^ rightrotate($e, 25);
			my $ch = ($e & $f) ^ ((0xFFFFFFFF & (~ $e)) & $g);
			my $temp1 = ($h + $S1 + $ch + $K[$i] + $w[$i]) % POW232;
			my $S0 = rightrotate($a, 2) ^ rightrotate($a, 13) ^ rightrotate($a, 22);
			my $maj = ($a & $b) ^ ($a & $c) ^ ($b & $c);
			my $temp2 = ($S0 + $maj) % POW232;

			$h = $g;
			$g = $f;
			$f = $e;
			$e = ($d + $temp1) % POW232;
			$d = $c;
			$c = $b;
			$b = $a;
			$a = ($temp1 + $temp2) % POW232;
		}

		# Add the compressed chunk to the current hash value.
		$h0 = ($h0 + $a) % POW232;
		$h1 = ($h1 + $b) % POW232;
		$h2 = ($h2 + $c) % POW232;
		$h3 = ($h3 + $d) % POW232;
		$h4 = ($h4 + $e) % POW232;
		$h5 = ($h5 + $f) % POW232;
		$h6 = ($h6 + $g) % POW232;
		$h7 = ($h7 + $h) % POW232;
	}

	# Produce the final hash value (big-endian).
	return unpack ("H*", pack ("N", $h0)) .
	       unpack ("H*", pack ("N", $h1)) .
	       unpack ("H*", pack ("N", $h2)) .
	       unpack ("H*", pack ("N", $h3)) .
	       unpack ("H*", pack ("N", $h4)) .
	       unpack ("H*", pack ("N", $h5)) .
	       unpack ("H*", pack ("N", $h6)) .
	       unpack ("H*", pack ("N", $h7));
}

###############################################################################
# Rotate a 32-bit number a number of bits to the right.
###############################################################################
sub rightrotate {
	my ($x, $c) = @_;

	return (0xFFFFFFFF & ($x << (32 - $c))) | ($x >> $c);
}

1;
__END__

=head1 NAME

Digest::SHA256 - Pure Perl implementation of the SHA-256 algorithm.

=head1 SYNOPSIS

  use Digest::SHA256::PurePerl;
  my $hash = sha256("input string");

=head1 DESCRIPTION

This is a Pure Perl implementation of the SHA-256 message-digest algorithm (see:
http://en.wikipedia.org/wiki/SHA-2) that does not depend on any other modules.

=head2 Methods

=over 4

=item * sha256()

Returns the SHA-256 hash of the given string as a hex string.

=back

=head1 AUTHOR

Ramon Novoa <ramonnovoa@gmail.com>

=head1 COPYRIGHT

Copyright (C) 2016 Ramon Novoa <ramonnovoa@gmail.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.

=cut
