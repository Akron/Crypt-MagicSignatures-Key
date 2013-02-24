#!/usr/bin/env perl
use Test::More tests => 22;
use Math::BigInt try => 'GMP,Pari';
use strict;
use warnings;
no strict 'refs';

use lib '../lib';

our $module;
BEGIN {
    our $module = 'Crypt::MagicSignatures::Key';
    use_ok($module);   # 1
};

sub _b {
  return Crypt::MagicSignatures::Key::_bitsize(@_);
};

SKIP: {
  skip 'No key generation available', 21 unless
    eval q{use Math::Prime::Util qw/random_nbit_prime/; 1;};

  local $SIG{__WARN__} = sub {};

  ok(my $key = Crypt::MagicSignatures::Key->new, 'Key Generation');
  ok($key->n, 'Modulus');
  ok($key->e, 'Public Exponet');
  ok($key->d, 'Private Exponet');

  # diag 'N: ' . $key->n;
  # diag 'E: ' . $key->e;
  # diag 'D: ' . $key->d;

  is($key->e, 65537, 'Public exponent is correct');

  is(_b($key->n), 512, 'Modulus-Size is correct');

  ok(my $sig = $key->sign('This is a message'), 'Signing');
  ok($key->verify('This is a message', $sig), 'Verification');

  ok($key = Crypt::MagicSignatures::Key->new(size => 1024, e => 3), 'Key Generation');
  ok($key->n, 'Modulus');
  ok($key->e, 'Public Exponet');
  ok($key->d, 'Private Exponet');

  is($key->e, 3, 'Public exponent is correct');
  is(_b($key->n), 1024, 'Modulus-Size is correct');

  ok($sig = $key->sign('This is a new message'), 'Signing');
  ok($key->verify('This is a new message', $sig), 'Verification');
  ok(!$key->verify('This is a new message', 'u' . $sig), 'Verification');
  ok(!$key->verify('This is a new message', $sig . 'u'), 'Verification');

  like($key->to_string, qr/^RSA(\.[-_a-zA-Z0-9]+=*){2}$/, 'Stringification');

  ok(!Crypt::MagicSignatures::Key->new(size => 48, e => 3), 'Key Generation');
  ok(!Crypt::MagicSignatures::Key->new(size => 513, e => 3), 'Key Generation');
};
