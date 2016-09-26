use strict;
use Test;

BEGIN {
	plan tests => 1
}

use Digest::SHA256::PurePerl;

# Undefined input.
ok(sha256(undef), "")

