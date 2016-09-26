use strict;
use Test;

BEGIN {
	plan tests => 1
}

use Digest::SHA256::PurePerl;

# Empty input.
ok(sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

