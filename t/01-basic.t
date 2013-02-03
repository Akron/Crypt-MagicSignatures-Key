#!/usr/bin/env perl

use Test::More tests => 7;
use Math::BigInt try => 'GMP,Pari';
use strict;
use warnings;
no strict 'refs';

use lib '../lib';

our $module;
BEGIN {
  our $module = 'Crypt::MagicSignatures::Key';
  use_ok($module, qw/b64url_encode b64url_decode/);   # 1
};

my $test_msg = 'This is a small message test.';

# test os2ip
my $os2ip = *{"${module}::_os2ip"}->($test_msg);
ok($os2ip eq '22756313778701413365784'.
             '01782410999343477943894'.
             '174703601131715860591662', 'os2ip'); # 2

# test i2osp
my $i2osp = *{"${module}::_i2osp"}->($os2ip);
ok($i2osp eq $test_msg, 'i2osp');                  # 3

$os2ip = *{"${module}::_os2ip"}->($test_msg);

# test bitsize
my $bitsize = *{"${module}::_bitsize"}->($os2ip);
is(231, $bitsize, 'bitsize');                    # 4

# test octet_len
my $octet_len = *{"${module}::_octet_len"}->($os2ip);
is(29, $octet_len, 'octet_len');                 # 5

my $b64url_encode = b64url_encode($test_msg);
$b64url_encode =~ s/[\s=]+$//;
is($b64url_encode, 'VGhpcyBpcyBhIHNtYWxsIG1lc3NhZ2UgdGVzdC4',
   'b64url_encode');                               # 6

my $b64url_decode = b64url_decode($b64url_encode);
ok($b64url_decode eq $test_msg, 'b64url_decode');  # 7



