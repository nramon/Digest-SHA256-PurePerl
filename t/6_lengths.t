use strict;
use warnings;
use Test::More;

use Digest::SHA256::PurePerl;

# Digest::SHA is a core module; use it as a reference implementation.
BEGIN {
	eval { require Digest::SHA; 1 }
		or plan skip_all => 'Digest::SHA not available';
}

# Cover every length around the padding and block boundaries (55/56 and 63/64
# bytes, and the same for later blocks), plus a range of small lengths.
my @lengths = (0 .. 130, 183, 184, 191, 192, 255, 256, 1023, 1024, 1025);

plan tests => scalar(@lengths) + 2;

for my $len (@lengths) {
	my $data = join('', map { chr(($_ * 7 + $len) % 256) } 0 .. $len - 1);
	is(sha256($data), Digest::SHA::sha256_hex($data), "matches Digest::SHA for $len bytes");
}

# All 256 byte values in one string.
my $all = join('', map { chr } 0 .. 255);
is(sha256($all), Digest::SHA::sha256_hex($all), 'all byte values');

# Exported by default.
ok(defined(&main::sha256), 'sha256 is exported by default');
