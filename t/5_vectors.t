use strict;
use warnings;
use Test::More;

use Digest::SHA256::PurePerl;

# NIST / FIPS 180-4 example vectors.
my @vectors = (
	['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
	['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
	 '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
	['a' x 1_000_000, 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'],
);

plan tests => scalar(@vectors);

for my $v (@vectors) {
	my $name = length($v->[0]) > 60 ? length($v->[0]) . ' bytes' : $v->[0];
	is(sha256($v->[0]), $v->[1], "NIST vector: $name");
}
