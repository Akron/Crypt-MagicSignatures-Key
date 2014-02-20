#!/usr/bin/env perl
use 5.010001;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Crypt::MagicSignatures::Key',
  AUTHOR       => 'Nils Diewald',
  ABSTRACT     => 'MagicKeys for the Salmon Protocol',
  VERSION_FROM => 'lib/Crypt/MagicSignatures/Key.pm',
  BUILD_REQUIRES => {
    'Test::More' => 0
  },
  PREREQ_PM => {
    'Math::Prime::Util' => '0.21',
    'Carp'         => 0,
    'Digest::SHA'  => 0,
    'MIME::Base64' => 0,
    'Math::BigInt' => 0,
    'Exporter'     => 0,
  },
  LICENSE => 'perl',
  META_MERGE   => {
    requires  => { perl => '5.010001' },
    resources => {
      license     => 'http://www.opensource.org/licenses/artistic-license-2.0',
      repository  => 'https://github.com/Akron/Crypt-MagicSignatures-Key'
    },
    recommends => {
      'Math::Prime::Util::GMP'  => 0.06,
      'Math::BigInt::GMP'       => 1.37,
      'Math::Random::ISAAC::XS' => 1.004,
    }
  },
  MIN_PERL_VERSION => '5.010001',
  test => {TESTS => 't/*.t'}
);

