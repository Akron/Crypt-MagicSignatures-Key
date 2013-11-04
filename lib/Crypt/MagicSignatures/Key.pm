package Crypt::MagicSignatures::Key;
use strict;
use warnings;
use Carp 'carp';

use v5.10.1;

our @CARP_NOT;

our $VERSION = '0.10';

# Maximum number of tests for random prime generation = 100
# Range of valid key sizes = 512 - 2048
# Maximum number length for i2osp and os2ip = 30000

use Digest::SHA qw/sha256 sha256_hex/;
use MIME::Base64 qw(decode_base64 encode_base64);

# Implement with GMP or PARI if existent
use Math::BigInt try => 'GMP,Pari';

# Export functions on request
use Exporter 'import';
our @EXPORT_OK = qw(b64url_encode b64url_decode);

# Primitives for Math::Prime::Util
sub random_nbit_prime;

our $GENERATOR;

# Load Math::Prime::Util and Math::Random::Secure
BEGIN {
  if (eval "use Math::Prime::Util 0.21 qw/random_nbit_prime/; 1;") {
    our $GENERATOR = 1;
  };
};


# Construct a new object
sub new {
  my $class = shift;
  my $self;

  # Is already a MagicKey object
  return $_[0] if ref $_[0] && ref $_[0] eq __PACKAGE__;

  # MagicKey in string notation
  if (@_ == 1 && index($_[0], 'RSA') >= 0) {

    my $string = shift;
    return unless $string;

    # New object from parent class
    $self = bless {}, $class;

    # Delete whitespace
    $string =~ tr{\t-\x0d }{}d;

    # Ignore mime-type prolog if given
    $string =~ s{^data\:application\/magic(?:\-public|\-private)?\-key[,;:]}{}i;

    # Split MagicKey
    my ($type, $mod, $exp, $private_exp) = split(/\./, $string);

    # The key is incorrect
    if ($type ne 'RSA') {
      carp "MagicKey type '$type' is not supported";
      return;
    };

    # RSA.modulus(n).exponent(e).private_exponent(d)?
    for ($mod, $exp, $private_exp) {
      next unless $_;
      $_ = _b64url_to_hex($_);
    };

    # Set modulus
    $self->n( $mod );

    # Set exponent
    $self->e( $exp );

    # Set private key
    $self->d( $private_exp ) if $private_exp;
  }

  # MagicKey defined by parameters
  else {
    my %param = @_;

    # RSA complete description
    if (defined $param{n}) {

      $self = bless {}, $class;

      # Set attributes
      foreach (qw/n e d/) {
	$self->$_($param{$_}) if exists $param{$_};
      };

      # Modulus was not defined
      carp 'Key is not well defined' and return unless $self->n;
    }

    # Generate new key
    else {

      # Generator not installed
      unless ($GENERATOR) {
	carp 'No Math::Prime::Util installed' and return;
      };

      # Define key size
      my $size = $param{size};

      # Size is given
      if ($size) {

	# Key size is too short or impractical
	if ($size < 512 || $size > 2048 || $size % 2) {
	  carp "Key size $size is invalid" and return;
	};
      }

      # Default size
      else {
	$size = 512;
      };

      # Public exponent
      my $e = $param{e};

      # Partial size
      my $psize = int( $size / 2 );

      my $n;
      my $m = 100; # Maximum number of rounds

      my ($p, $q);

      # Start calculation of combining primes
    CALC_KEY:

      # Run as long as allowed
      while ($m > 0) {

	# Fetch random primes p and q
	# Uses Bytes::Random::Secure by default
	$p = random_nbit_prime($psize);
	$q = random_nbit_prime($psize);

	# Fetch a new prime if both are equal
	while ($p == $q) {
	  $q = random_nbit_prime($psize);
	  unless (--$m > 0) {
	    $p = $q = Math::BigInt->bzero;
	    last;
	  };
	};

	# Calculate modulus
	$n = $p * $q;

	# Bitsize is correct based on given size
	last if _bitsize($n) == $size;

	$m--;
      };

      unless ($m > 0) {
	carp 'Maximum rounds for key generation is reached' and return;
      };

      # Bless object
      $self = bless {}, $class;

      # Set e
      $self->e($e) if $e;

      # Calculate phi
      my $phi = ($p - 1) * ($q - 1);

      # Calculate multiplicative inverse of e modulo phi
      my $d = $self->e->copy->bmodinv($phi);

      # $d is too short
      goto CALC_KEY if _bitsize($d) < $size / 4;

      # Store d
      $self->d($d);

      # Store n
      $self->n($n);
    };
  };

  # Set size (bitsize length of modulus)
  $self->{size} = _bitsize( $self->n );

  # Size is to small
  if ($self->{size} < 512 || $self->{size} > 2048)  {
    carp 'Keysize is out of range' and return;
  };

  # Set emLen (octet length of modulus)
  $self->{emLen} = _octet_len( $self->n );

  return $self;
};


# Get or set modulus
sub n {
  my $self = shift;

  # Get value
  unless ($_[0]) {
    return ($self->{n} //= Math::BigInt->bzero);
  };

  # Set value
  my $n = Math::BigInt->new( shift );

  # n is not a number
  carp 'n is not a number' and return if $n->is_nan;

  # Delete precalculated emLen and size
  delete $self->{emLen};
  delete $self->{size};

  return $self->{n} = $n;
};


# Get or set public exponent
sub e {
  my $self = shift;

  # Get value
  unless ($_[0]) {
    return ($self->{e} //= Math::BigInt->new('65537'));
  };

  # Set value
  my $e = Math::BigInt->new( shift );

  # e is not a number
  carp 'e is not a number' and return if $e->is_nan;

  return $self->{e} = $e;
};


# Get or set private exponent
sub d {
  my $self = shift;

  # Get value
  unless ($_[0]) {
    return $self->{d} // undef;
  };

  # Set value
  my $d = Math::BigInt->new( shift );

  # d is not a number
  carp 'd is not a number' and return if $d->is_nan;

  return $self->{d} = $d;
};


# Get key size
sub size {
  my $self = shift;
  return unless $self->n;
  return $self->{size} // ($self->{size} = _bitsize($self->n));
};


# Sign a message
sub sign {
  my ($self, $message) = @_;

  unless ($self->d) {
    carp 'You can only sign with a private key' and return;
  };

  my $encoded_message = _sign_emsa_pkcs1_v1_5($self, $message);

  return b64url_encode($encoded_message);
};


# Verify a signature for a message (sig base)
sub verify {
  my ($self,
      $message,
      $encoded_message) =  @_;

  # Delete whitespace and padding
  $encoded_message =~ tr{=\t-\x0d }{}d;

  unless ($encoded_message && $message) {
    carp 'No signature or message given';
    return;
  };

  return unless $self->n;

  return _verify_emsa_pkcs1_v1_5(
    $self,
    $message,
    # _b64url_to_hex( $encoded_message )
    b64url_decode($encoded_message)
  );
};


# Return MagicKey-String (public only)
sub to_string {
  my $self = shift;

  my $n = $self->n;
  return '' unless $n;

  my $e = $self->e;

  # Convert modulus and exponent
  $_ = _hex_to_b64url($_) for ($n, $e);

  my @array = ('RSA', $n, $e);

  push(@array, _hex_to_b64url($self->d)) if $_[0] && $self->d;

  my $mkey = join('.', @array);

  # Specification is not clear about $mkey =~ s/=+//g;

  $mkey;
};


# Returns the b64 urlsafe encoding of a string
sub b64url_encode {
  return '' unless $_[0];

  my $v = $_[0];

  utf8::encode $v if utf8::is_utf8 $v;
  $v = encode_base64($v, '');
  $v =~ tr{+/\t-\x0d }{-_}d;

  # Trim padding or not
  $v =~ s/\=+$// unless (defined $_[1] ? $_[1] : 1);

  return $v;
};


# Returns the b64 urlsafe decoded string
sub b64url_decode {
  my $v = shift;
  return '' unless $v;

  $v =~ tr{-_}{+/};

  my $padding;

  # Add padding
  if ($padding = (length($v) % 4)) {
    $v .= chr(61) x (4 - $padding);
  };

  return decode_base64($v);
};


# Get octet length of n
sub _emLen {
  my $self = shift;
  return 0 unless $self->n;
  return $self->{emLen} // ($self->{emLen} = _octet_len( $self->n ));
};


# Sign with emsa padding
sub _sign_emsa_pkcs1_v1_5 {
  # http://www.ietf.org/rfc/rfc3447.txt [Ch. 8.1.1]

  # key, message
  my ($K, $M) = @_;

  # octet length of n
  my $k = $K->_emLen;

  # encode message (Hash digest is always 'sha-256')
  my $EM = _emsa_encode($M, $k) or return;

  my $m = _os2ip($EM);
  my $s = _rsasp1($K, $m);
  _i2osp($s, $k); # S
};


# Verify with emsa padding
sub _verify_emsa_pkcs1_v1_5 {
  # http://www.ietf.org/rfc/rfc3447.txt [Ch. 8.2.2]

  # key, message, signature
  my ($K, $M, $S) = @_;

  my $k = $K->_emLen;

  # The length of the signature is not
  # equivalent to the length of the RSA modulus
  carp 'Invalid signature' and return if length($S) != $k;

  my $s = _os2ip($S);
  my $m = _rsavp1($K, $s) or return;
  my $EM = _emsa_encode($M, $k) or return;

  return $EM eq _i2osp($m, $k);
};


# RSA signing
sub _rsasp1 {
  # http://www.ietf.org/rfc/rfc3447.txt [Ch. 5.2.1]

  # Key, message
  my ($K, $m) = @_;

  if ($m >= $K->n) {
    carp 'Message representative out of range' and return;
  };

  return $m->bmodpow($K->d, $K->n);
};


# RSA verification
sub _rsavp1 {
  # http://www.ietf.org/rfc/rfc3447.txt [Ch. 5.2.2]

  # Key, signature
  my ($K, $s) = @_;

  # Is signature in range?
  if ($s > $K->n || $s < 0) {
    carp 'Signature representative out of range' and return;
  };

  return $s->bmodpow($K->e, $K->n);
};


# Create code with emsa padding (only sha-256 support)
sub _emsa_encode {
  # http://www.ietf.org/rfc/rfc3447.txt [Ch. 9.2]

  my ($M, $emLen) = @_;

  # No message given
  return unless $M;

  # Hash digest is always 'sha-256'

  # Create Hash with DER padding
  my $H = sha256($M);
  my $T = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01" .
          "\x65\x03\x04\x02\x01\x05\x00\x04\x20" . $H;
  my $tLen = length( $T );

  if ($emLen < $tLen + 11) {
    carp 'Intended encoded message length too short' and return;
  };

  return "\x00\x01" . ("\xFF" x ($emLen - $tLen - 3)) . "\x00" . $T;
};


# Convert from octet string to bigint
sub _os2ip {
  # Based on Crypt::RSA::DataFormat
  # See also Convert::ASN1

  my $os = shift;

  my $l = length($os);
  return if $l > 30_000;

  my $base = Math::BigInt->new(256);
  my $result = Math::BigInt->bzero;
  for (0 .. $l - 1) {
    # Maybe optimizable
    $result->badd(
      int(ord(unpack "x$_ a", $os)) * ($base ** int($l - $_ - 1))
    );
  };
  $result;
};


# Convert from bigint to octet string
sub _i2osp {
  # Based on Crypt::RSA::DataFormat
  # See also Convert::ASN1

  my $num = Math::BigInt->new(shift);

  return if $num->is_nan;
  return if $num->length > 30_000;

  my $l = shift || 0;
  my $base = Math::BigInt->new(256);

  my $result = '';

  if ($l && $num > ( $base ** $l )) {
    carp 'i2osp error - Integer is to short' and return;
  };

  do {
    my $r = $num % 256;
    $num = ($num - $r) / 256;
    $result = chr($r) . $result;
  } until ($num < 256);

  $result = chr($num) . $result if $num != 0;

  if (length($result) < $l) {
    $result = chr(0) x ($l - length($result)) . $result;
  };

  $result;
};


# Returns the octet length of a given integer
sub _octet_len {
  return Math::BigInt->new( _bitsize( shift ))
    ->badd(7)
      ->bdiv(8)
	->bfloor;
};


# Returns the bitlength of the integer
sub _bitsize {
  my $int = Math::BigInt->new( shift );
  return 0 unless $int;
  # Trim leading '0b'
  length( $int->as_bin ) - 2;
};


# base64url to hex number
sub _b64url_to_hex {
  # Based on
  # https://github.com/sivy/Salmon/blob/master/lib/Salmon/
  #         MagicSignatures/SignatureAlgRsaSha256.pm

  # Decode and convert b64url encoded hex number
  return Math::BigInt->new(
    '0x' . unpack( 'H*', b64url_decode( shift ) )
  );
};


# hex number to base64url
sub _hex_to_b64url {
  # https://github.com/sivy/Salmon/blob/master/lib/Salmon/
  #         MagicSignatures/SignatureAlgRsaSha256.pm

  # Trim leading '0x'
  my $num = substr(Math::BigInt->new( shift )->as_hex, 2);

  # Add leading zero padding
  $num = ( ( ( length $num ) % 2 ) > 0 ) ? '0' . $num : $num;

  # Encode number using b64url
  return b64url_encode( pack( 'H*', $num ) );
};


1;


__END__

=pod

=head1 NAME

Crypt::MagicSignatures::Key - MagicKeys for the Salmon Protocol


=head1 SYNOPSIS

  use Crypt::MagicSignatures::Key;

  my $mkey = Crypt::MagicSignatures::Key->new('RSA.mVgY...');

  my $sig = $mkey->sign('This is a message');

  if ($mkey->verify('This is a message', $sig)) {
    print 'The signature is valid for ' . $mkey->to_string;
  };


=head1 DESCRIPTION

L<Crypt::MagicSignatures::Key> implements MagicKeys as described in the
L<MagicSignatures Specification|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html>
to sign messages of the L<Salmon Protocol|http://www.salmon-protocol.org/>.
MagicSignatures is a "robust mechanism for digitally signing nearly arbitrary messages".
See L<Crypt::MagicSignatures::Envelope> for using MagicKeys to sign MagicEnvelopes.


=head1 ATTRIBUTES


=head2 n

  print $mkey->n;
  $mkey->n('456789...');

The MagicKey modulus.


=head2 e

  print $mkey->e;
  $mkey->e(3);

The MagicKey public exponent.
Defaults to C<65537>.


=head2 d

  print $mkey->d;
  $mkey->d('234567...');

The MagicKey private exponent.


=head2 size

  print $mkey->size;

The MagicKey keysize in bits.


=head1 METHODS

=head2 new

  my $mkey = Crypt::MagicSignatures::Key->new(<<'MKEY');
    RSA.
    mVgY8RN6URBTstndvmUUPb4UZTdwvw
    mddSKE5z_jvKUEK6yk1u3rrC9yN8k6
    FilGj9K0eeUPe2hf4Pj-5CmHww==.
    AQAB.
    Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6
    yihYetQ8jy-jZXdsZXd8V5ub3kuBHH
    k4M39i3TduIkcrjcsiWQb77D8Q==
  MKEY

  $mkey = Crypt::MagicSignatures::Key->new(
    n => '13145688881420345...',
    d => '87637925876135637...',
    e => 3
  );

  $mkey = Crypt::MagicSignatures::Key->new(size => 1024);


The Constructor accepts MagicKeys in
L<compact notation|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html#anchor13>
or by attributes.

If no C<n> attribute is given and L<Math::Prime::Util>
is installed, a new key will be generated.
In case no C<size> attribute is given, the default key size
for generation is 512 bits, which is also the minimum size.
The maximum size is 2048 bits.


=head2 sign

  my $sig = $mkey->sign('This is a message');

Signs a message and returns the signature.
The key needs to be a private key.
The signature algorithm is based on
L<RFC3447|http://www.ietf.org/rfc/rfc3447.txt>.


=head2 verify

  my $sig = $priv_key->sign('This is a message');

  # Successfully verify signature
  if ($pub_key->verify('This is a message', $sig)) {
    print 'The signature is okay.';
  }

  # Fail to verify signature
  else {
    print 'The signature is wrong!';
  };

Verifies a signature of a message based on the public
component of the key.
Returns a C<true> value on success and C<false> otherwise.


=head2 to_string

  my $pub_key = $mkey->to_string;
  my $priv_key = $mkey->to_string(1);

Returns the public key as a string in
L<compact notation|http://salmon-protocol.googlecode.com/svn/trunk/draft-panzer-magicsig-01.html#anchor13>.
If a C<true> value is passed to the method,
the full key (including the private exponent if existing)
is returned.


=head1 FUNCTIONS

=head2 b64url_encode

  use Crypt::MagicSignatures::Key qw/b64url_encode/;

  print b64url_encode('This is a message');
  print b64url_encode('This is a message', 0);

Encodes a string as base-64 with URL safe characters.
A second parameter indicates, if trailing equal signs
are wanted. The default is C<true>.
This differs from
L<MIME::Base64::encode_base64|MIME::Base64/"encode_base64">.
The function can be exported.


=head2 b64url_decode

  use Crypt::MagicSignatures::Key qw/b64url_decode/;

  print b64url_decode('VGhpcyBpcyBhIG1lc3NhZ2U=');

Decodes a base-64 string with URL safe characters.
The function can be exported.


=head1 DEPENDENCIES

For signing and verification there are no dependencies
other than Perl v5.10.1 and core modules.
For key generation L<Math::Prime::Util> v0.21 is necessary.

Either L<Math::BigInt::GMP> (preferred) or L<Math::BigInt::Pari>
is strongly recommended for speed improvement
(signing and verification) as well as
L<Math::Prime::Util::GMP> and L<Math::Random::ISAAC::XS>
(key generation).


=head1 KNOWN BUGS AND LIMITATIONS

The signing and verification is not guaranteed to be
compatible with other implementations!


=head1 SEE ALSO

L<Crypt::MagicSignatures::Envelope>,
L<Crypt::RSA::DataFormat>,
L<Alt::Crypt::RSA::BigInt>,
L<https://github.com/sivy/Salmon>.


=head1 AVAILABILITY

  https://github.com/Akron/Crypt-MagicSignatures-Key


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012-2013, L<Nils Diewald|http://nils-diewald.de/>.

This program is free software, you can redistribute it
and/or modify it under the same terms as Perl.

=cut
