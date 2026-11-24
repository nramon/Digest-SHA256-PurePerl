use strict;
use warnings;
use Test::More tests => 5;

use Digest::SHA256::PurePerl;

# Internal helper: 32-bit right rotation.
is(Digest::SHA256::PurePerl::rightrotate(0x00000001, 1), 0x80000000, 'bit wraps around');
is(Digest::SHA256::PurePerl::rightrotate(0x80000000, 31), 0x00000001, 'rotate by 31');
is(Digest::SHA256::PurePerl::rightrotate(0x12345678, 8), 0x78123456, 'rotate by 8');
is(Digest::SHA256::PurePerl::rightrotate(0xFFFFFFFF, 13), 0xFFFFFFFF, 'all ones');
is(Digest::SHA256::PurePerl::rightrotate(0, 7), 0, 'zero');
