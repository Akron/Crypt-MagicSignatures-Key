#!/usr/bin/env perl
use Test::More;
use Math::BigInt try => 'GMP,Pari';
use strict;
use warnings;
no strict 'refs';

use lib '../lib';

my $m = 'Math::Prime::Util 0.21';
my $mpu = eval q{use } . $m . q{ qw/random_nbit_prime/; 1;};

plan skip_all => $m . ' is not available for key generation' unless $mpu;

$m = 'Math::Prime::Util::GMP';
my $mpug = eval q{use } . $m . q{; 1;};

plan skip_all => "Test would run too slow without $m" unless $mpug;

my $module = 'Crypt::MagicSignatures::Key';
use_ok($module);   # 1

sub _b {
  return Crypt::MagicSignatures::Key::_bitsize(@_);
};

local $SIG{__WARN__} = sub {};

ok(my $key = Crypt::MagicSignatures::Key->new, 'Key Generation');
ok($key->n, 'Modulus');
ok($key->e, 'Public Exponet');
ok($key->d, 'Private Exponet');

# diag 'N: ' . $key->N;
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

done_testing;
