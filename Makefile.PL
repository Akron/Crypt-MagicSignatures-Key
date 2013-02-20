#!/usr/bin/env perl
use 5.010001;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    VERSION_FROM => 'lib/Crypt/MagicSignatures/Key.pm',
    NAME         => 'Crypt::MagicSignatures::Key',
    AUTHOR       => 'Nils Diewald',
    PREREQ_PM => {
      'Math::Prime::Util' => '0.17',
      'Math::Random::Secure' => '0.05',
      'Carp' => 0,
      'Digest::SHA' => 0,
      'MIME::Base64' => 0,
      'Math::BigInt' => 0,
      'Exporter' => 0,
      'Test::More' => 0
    },
    LICENSE => 'perl',
    META_MERGE   => {
      requires  => {perl => '5.010001'},
      resources => {
	license     => 'http://www.opensource.org/licenses/artistic-license-2.0',
	repository  => 'https://github.com/Akron/Crypt-MagicSignatures-Key'
      }
    },
    test => {TESTS => 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t'}
);

