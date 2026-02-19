#!/usr/bin/perl

# Batch-mode tests for afpcmd
# Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

use strict;
use warnings;

use Test::More;
use File::Temp qw(tempdir);

my $AFP_URL  = 'afp://test_usr:test_pwd@localhost/afpfs_test';
my $work_dir = tempdir(CLEANUP => 1);
my $test_file = "afpcmd_test_$$.txt";
my $test_path = "$work_dir/$test_file";

# -----------------------------------------------------------------------
# batch_upload
# -----------------------------------------------------------------------

open(my $fh, '>', $test_path) or BAIL_OUT("Cannot create test file: $!");
print $fh "Hello from afpcmd batch transfer test\nLine 2\nLine 3\n";
close $fh;

my $orig_cksum = `cksum "$test_path"`;
chomp $orig_cksum;
$orig_cksum =~ s/\s+\S+$//;    # strip filename, keep "CRC SIZE"

is(system('afpcmd', $test_path, $AFP_URL), 0, 'batch_upload: afpcmd exits 0');

# -----------------------------------------------------------------------
# batch_download
# -----------------------------------------------------------------------

unlink $test_path;
ok(!-e $test_path, 'batch_download: local copy removed before download');

is(system('afpcmd', "$AFP_URL/$test_file", $work_dir), 0,
    'batch_download: afpcmd exits 0');

ok(-e $test_path, 'batch_download: file exists after download');

my $new_cksum = `cksum "$test_path"`;
chomp $new_cksum;
$new_cksum =~ s/\s+\S+$//;

is($new_cksum, $orig_cksum, 'batch_download: checksum matches original');

done_testing;
