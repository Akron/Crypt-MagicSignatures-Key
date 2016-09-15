use strict;
use warnings;
use Test::More;
BEGIN {
  plan skip_all => 'these tests are for RELEASE_TESTING'
    unless $ENV{RELEASE_TESTING};
};
use Test::Kwalitee 'kwalitee_ok';
kwalitee_ok();
done_testing;
