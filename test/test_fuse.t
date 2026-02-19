#!/usr/bin/perl

# afpfs-ng FUSE client tests
# Based on the original test/Makefile by Simon Vetter
# Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

use strict;
use warnings;

use Test::More;
use Cwd qw(getcwd);

my $mnt_dir       = getcwd() . '/afpfs_mnt';
my $AFP_URL       = 'afp://test_usr:test_pwd@localhost/afpfs_test';
my $AFP_GUEST_URL = 'afp://localhost/afpfs_test';

# Run a command via fork+exec, capture combined stdout+stderr.
# Returns (output_string, raw_$?_status).
sub run_capture {
    my @cmd = @_;
    pipe(my $out_r, my $out_w) or die "pipe: $!";
    my $pid = fork() // die "fork: $!";
    if ($pid == 0) {
        close $out_r;
        open(STDOUT, '>&', $out_w) or die "dup stdout: $!";
        open(STDERR, '>&', $out_w) or die "dup stderr: $!";
        close $out_w;
        exec(@cmd) or die "exec: $!";
        exit 1;
    }
    close $out_w;
    local $/;
    my $output = <$out_r>;
    close $out_r;
    waitpid($pid, 0);
    return ($output // '', $?);
}

# -----------------------------------------------------------------------
# prepare
# -----------------------------------------------------------------------

mkdir $mnt_dir unless -d $mnt_dir;
ok(-d $mnt_dir, 'prepare: mount directory exists');

is(system('afpfsd', '--manager'), 0, 'prepare: afpfsd daemon started');

# -----------------------------------------------------------------------
# fuse_auth: authenticated mount
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_URL, $mnt_dir), 0,
    'fuse_auth: authenticated mount succeeds');

open(my $wfh, '>', "$mnt_dir/sample.txt")
    or BAIL_OUT("Cannot write to mounted share: $!");
print $wfh "You should read this back\n";
close $wfh;

open(my $rfh, '<', "$mnt_dir/sample.txt")
    or BAIL_OUT("Cannot read from mounted share: $!");
my $content = do { local $/; <$rfh> };
close $rfh;
like($content, qr/^You should read this back$/m,
    'fuse_auth: file content readable after write');

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_auth: authenticated unmount succeeds');

# -----------------------------------------------------------------------
# fuse_auth: guest mount (verify file persists and is readable)
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_GUEST_URL, $mnt_dir), 0,
    'fuse_auth: guest mount succeeds');

ok(-f "$mnt_dir/sample.txt",
    'fuse_auth: guest mount shows previously written file');

open(my $gfh, '<', "$mnt_dir/sample.txt")
    or BAIL_OUT("Cannot read file on guest mount: $!");
my $guest_content = do { local $/; <$gfh> };
close $gfh;
like($guest_content, qr/^You should read this back$/m,
    'fuse_auth: guest mount file content matches');

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_auth: guest unmount succeeds');

# -----------------------------------------------------------------------
# fuse_auth: authenticated mount (cleanup)
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_URL, $mnt_dir), 0,
    'fuse_auth: cleanup mount succeeds');

open(my $cfh, '<', "$mnt_dir/sample.txt")
    or BAIL_OUT("Cannot read file on cleanup mount: $!");
my @lines = <$cfh>;
close $cfh;
like($lines[0], qr/^You should read this back$/,
    'fuse_auth: cleanup mount file content matches');
is(scalar @lines, 1, 'fuse_auth: file has exactly one line');

unlink "$mnt_dir/sample.txt";
ok(!-e "$mnt_dir/sample.txt", 'fuse_auth: sample.txt removed');

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_auth: cleanup unmount succeeds');

# -----------------------------------------------------------------------
# fuse_status: afp_client status (global and per-mountpoint)
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_URL, $mnt_dir), 0,
    'fuse_status: mount for status test');

# Global status goes to the manager daemon and lists all active mounts.
my ($status_out, $status_rc) = run_capture('afp_client', 'status');
is($status_rc, 0, 'fuse_status: afp_client status exits 0');
like($status_out, qr/AFPFS Version:/,
    'fuse_status: version header present');
like($status_out, qr/Manager daemon:.*active mount/,
    'fuse_status: active mount count shown');
like($status_out, qr/afpfs_test/,
    'fuse_status: volume name in status overview');

# Per-mountpoint status is forwarded from the manager to the child daemon.
my ($mnt_status_out, $mnt_status_rc) =
    run_capture('afp_client', 'status', $mnt_dir);
is($mnt_status_rc, 0, 'fuse_status: afp_client status <mountpoint> exits 0');
like($mnt_status_out, qr/Server "afpfs_testsrv"/,
    'fuse_status: server name in per-mount status');
like($mnt_status_out, qr/Volume "afpfs_test"/,
    'fuse_status: volume name in per-mount status');
like($mnt_status_out, qr/using AFP version:/,
    'fuse_status: AFP version in per-mount status');
like($mnt_status_out, qr/mounted:/,
    'fuse_status: mount state in per-mount status');

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_status: unmount after status test');

# After all mounts are gone the manager reports an idle state.
sleep 1;
my ($idle_out) = run_capture('afp_client', 'status');
like($idle_out, qr/Manager daemon: no active mounts/,
    'fuse_status: idle manager reports no active mounts');

# -----------------------------------------------------------------------
# fuse_client_mount: afp_client mount (non-URL server:volume syntax)
# -----------------------------------------------------------------------

sleep 1;
is(system('afp_client', 'mount',
          '-u', 'test_usr', '-p', 'test_pwd',
          'localhost:afpfs_test', $mnt_dir), 0,
    'fuse_client_mount: afp_client mount with credentials succeeds');

open(my $cmfh, '>', "$mnt_dir/client_mount_test.txt")
    or BAIL_OUT("Cannot write via afp_client mount: $!");
print $cmfh "client mount test content\n";
close $cmfh;

ok(-f "$mnt_dir/client_mount_test.txt",
    'fuse_client_mount: file written via afp_client mount is visible');

unlink "$mnt_dir/client_mount_test.txt";

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_client_mount: unmount after client mount test');

# -----------------------------------------------------------------------
# fuse_dir_ops: directory operations (mkdir, readdir, rmdir) via FUSE
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_URL, $mnt_dir), 0,
    'fuse_dir_ops: mount for directory operations');

ok(mkdir("$mnt_dir/testdir"), 'fuse_dir_ops: mkdir succeeds');
ok(-d "$mnt_dir/testdir",    'fuse_dir_ops: directory visible after mkdir');

open(my $dfh, '>', "$mnt_dir/testdir/nested.txt")
    or BAIL_OUT("Cannot write nested file: $!");
print $dfh "nested content\n";
close $dfh;
ok(-f "$mnt_dir/testdir/nested.txt", 'fuse_dir_ops: file created in subdirectory');

open(my $dnfh, '<', "$mnt_dir/testdir/nested.txt")
    or BAIL_OUT("Cannot read nested file: $!");
my $nested = do { local $/; <$dnfh> };
close $dnfh;
like($nested, qr/nested content/, 'fuse_dir_ops: subdirectory file content correct');

unlink "$mnt_dir/testdir/nested.txt";
ok(rmdir("$mnt_dir/testdir"), 'fuse_dir_ops: rmdir succeeds');
ok(!-e "$mnt_dir/testdir",   'fuse_dir_ops: directory gone after rmdir');

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_dir_ops: unmount after directory tests');

# -----------------------------------------------------------------------
# fuse_rename: file rename via FUSE
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_URL, $mnt_dir), 0,
    'fuse_rename: mount for rename test');

open(my $rnfh, '>', "$mnt_dir/rename_src.txt")
    or BAIL_OUT("Cannot create rename source: $!");
print $rnfh "rename test content\n";
close $rnfh;

ok(rename("$mnt_dir/rename_src.txt", "$mnt_dir/rename_dst.txt"),
    'fuse_rename: rename succeeds');
ok(-f  "$mnt_dir/rename_dst.txt", 'fuse_rename: destination exists after rename');
ok(!-e "$mnt_dir/rename_src.txt", 'fuse_rename: source gone after rename');

open(my $rnrfh, '<', "$mnt_dir/rename_dst.txt")
    or BAIL_OUT("Cannot read renamed file: $!");
my $rn_content = do { local $/; <$rnrfh> };
close $rnrfh;
like($rn_content, qr/rename test content/,
    'fuse_rename: content intact after rename');

unlink "$mnt_dir/rename_dst.txt";
is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_rename: unmount after rename test');

# -----------------------------------------------------------------------
# fuse_ro: read-only mount rejects write operations
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', '-o', 'ro', $AFP_URL, $mnt_dir), 0,
    'fuse_ro: read-only mount succeeds');

my $ro_write_ok = open(my $rowfh, '>', "$mnt_dir/ro_test.txt");
if ($ro_write_ok) {
    close $rowfh;
    fail('fuse_ro: write should fail on read-only mount');
    unlink "$mnt_dir/ro_test.txt";
} else {
    pass('fuse_ro: write correctly rejected on read-only mount');
}

is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_ro: unmount read-only mount');

# -----------------------------------------------------------------------
# fuse_suspend_resume: suspend disconnects; resume restores file access
# -----------------------------------------------------------------------

sleep 1;
is(system('mount_afpfs', $AFP_URL, $mnt_dir), 0,
    'fuse_suspend_resume: mount for suspend/resume test');

open(my $srfh, '>', "$mnt_dir/sr_test.txt")
    or BAIL_OUT("Cannot create file before suspend: $!");
print $srfh "suspend resume content\n";
close $srfh;

is(system('afp_client', 'suspend', $mnt_dir), 0,
    'fuse_suspend_resume: suspend succeeds');
is(system('afp_client', 'resume',  $mnt_dir), 0,
    'fuse_suspend_resume: resume succeeds');

open(my $srrfh, '<', "$mnt_dir/sr_test.txt")
    or BAIL_OUT("Cannot read file after resume: $!");
my $sr_content = do { local $/; <$srrfh> };
close $srrfh;
like($sr_content, qr/suspend resume content/,
    'fuse_suspend_resume: file readable after resume');

unlink "$mnt_dir/sr_test.txt";
is(system('afp_client', 'unmount', $mnt_dir), 0,
    'fuse_suspend_resume: unmount after suspend/resume test');

# -----------------------------------------------------------------------
# fuse_exit: afp_client exit shuts down the manager daemon cleanly
# -----------------------------------------------------------------------

sleep 1;
my ($exit_out, $exit_rc) = run_capture('afp_client', 'exit');
is($exit_rc, 0, 'fuse_exit: afp_client exit exits 0');

done_testing;
