use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence                                                                                                     
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME' => 'Digest::SHA256',
	'AUTHOR' => 'Ramon Novoa <ramonnovoa@gmail.com>',
	'VERSION_FROM'=>'lib/Digest/SHA256/PurePerl.pm', # finds $VERSION
);
