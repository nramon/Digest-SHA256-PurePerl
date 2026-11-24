use strict;
use warnings;
use Test::More;

eval { require Test::Perl::Critic; Test::Perl::Critic->import(); 1 }
	or plan skip_all => 'Test::Perl::Critic required for this test';

all_critic_ok();
