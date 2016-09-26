use strict;
use Test;

BEGIN {
	plan tests => 3
}

use Digest::SHA256::PurePerl;

# Short string.
ok(sha256("Homer J. Simpson"), "2b61791e68465555d324925b662a0970c280ecd31201ddd918ef9e7366ca5cbf");

# 1025 byte string.
ok(sha256("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque laoreet ligula a dui ultrices lacinia. Aliquam erat volutpat. Integer fringilla nunc vitae dapibus euismod. Vestibulum nec neque sit amet urna volutpat aliquet eget in odio. Morbi vitae neque tincidunt, hendrerit ligula venenatis, consequat ipsum. Nulla ultricies, sem et consectetur sagittis, mauris lacus dapibus arcu, eu porttitor nunc risus nec neque. Nulla eu varius lorem, quis finibus nibh. Maecenas laoreet tempus eros, non suscipit augue placerat eu. Maecenas dignissim feugiat magna, vitae lobortis nunc pharetra sit amet. Praesent sed erat sed metus aliquam viverra. Ut ut elementum nunc. Etiam viverra quis nibh sit amet ultricies. Ut egestas ligula a molestie semper. Etiam lobortis mi ac diam ornare vestibulum. Aenean posuere nisl eget augue bibendum, nec mollis ligula imperdiet. Suspendisse varius sodales sem non scelerisque. Ut felis nunc, egestas a semper id, tempor non diam. Sed faucibus elementum orci nec aliquet. Nulla ac orci aliquam."), "6f36dcc19f2e3c14134bd45fe8c69726af554be2ad1a1f74b9ef797c64c7eef5");

# Binary data.
ok(sha256(pack("c4", 0x01, 0x02, 0x03, 0x04)), "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a");
