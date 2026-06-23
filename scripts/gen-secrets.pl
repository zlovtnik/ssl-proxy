#!/usr/bin/env perl
use strict;
use warnings;
use Fcntl      qw(:DEFAULT S_IWUSR S_IRUSR S_IXUSR);
use File::Path qw(make_path);
use File::Find qw(find);

use vars qw($MODE $did_warn_token);
no warnings 'once';
my $SECRETS_DIR = './secrets';

# @SECRETS — only place to add/remove a secret
my @SECRETS = (
    [ 'postgres.key',                 32, 'b64' ],
    [ 'minio_access_key.key',         24, 'b64' ],
    [ 'minio_secret_key.key',         32, 'b64' ],
    [ 'wg_obfuscation_key',           32, 'b64' ],
    [ 'admin_api_key',                48, 'b64' ],
    [ 'grafana_admin_password.key',   32, 'b64' ],
    [ 'atheros_api_token_sha256.key', 48, 'sha256' ],
    [ 'waha/api_key.key',             32, 'b64' ],
    [ 'waha/dashboard_password.key',  32, 'b64' ],
    [ 'waha/swagger_password.key',    32, 'b64' ],
);

# @COPIES — only place to configure copies
my @COPIES = (
    [ 'admin_api_key', 'wg-rotation/candidate/secrets/admin_api_key' ],
    [ 'wg_obfuscation_key', 'wg-rotation/candidate/secrets/wg_obfuscation_key' ],
);

sub die_usage {
    my $me = $0; $me =~ s|.*/||;
    die "Usage: $me [--generate|--dry-run|--force|--check]\n";
}

sub rand_b64 {
    my ($n) = @_;
    require MIME::Base64;
    open my $fh, '<', '/dev/urandom' or die "open /dev/urandom: $!";
    sysread($fh, my $buf, $n) == $n or die "short read from /dev/urandom";
    my $e = MIME::Base64::encode_base64($buf, '');
    $e =~ s/=+$//; $e;
}

sub sha256_hex { require Digest::SHA; Digest::SHA::sha256_hex(shift) }

# write_secret($p, $d) — atomic, 0600, no-overwrite, no dir logic
sub write_secret {
    my ($path, $data) = @_;
    if ($MODE eq 'force' && -e $path) {
        unlink $path or die "unlink $path: $!";
    }
    die "$path already exists\n" if -e $path;
    my $tmp = "$path.tmp.$$";
    sysopen(my $fh, $tmp, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)
      or die "write $tmp: $!";
    print $fh $data or die "print $tmp: $!";
    close $fh or die "close $tmp: $!";
    chmod(S_IRUSR|S_IWUSR, $tmp) or die "chmod $tmp: $!";
    rename($tmp, $path) or die "rename $tmp -> $path: $!";
}

sub copy_secret {
    my ($src, $dst) = @_;
    open my $fh, '<', $src or die "read $src: $!";
    local $/; write_secret($dst, <$fh>);
}

sub mkdirs_for_secrets {
    my %seen;
    for my $p (@_) {
        (my $dir = $p) =~ s|/[^/]+$||;
        next if $seen{$dir}++;
        make_path($dir, { mode => 0700, error => \my $err });
        die "make_path $dir: @$err" if @$err;
    }
}

sub lock_tree {
    my ($root) = @_;
    find(sub {
        return if $_ eq '.' || $_ eq '..';
        chmod(-d $_ ? S_IRUSR|S_IWUSR|S_IXUSR : S_IRUSR|S_IWUSR,
              $File::Find::name) or die "chmod $File::Find::name: $!";
    }, $root);
}

sub warn_token {
    my ($label, $token) = @_;
    return if $did_warn_token;
    return if $ENV{SECRETS_QUIET} && $ENV{SECRETS_QUIET} ne '0';
    print "\n!!! ONE-TIME TOKEN -- $label\n   $token\n   This will not be stored. Save it now.\n\n"
      if -t STDOUT;
    $did_warn_token = 1;
}

sub main {
    $MODE = shift;
    $did_warn_token = 0;

    if ($MODE eq 'check') {
        my @paths = map "$SECRETS_DIR/$_->[0]", @SECRETS;
        push @paths, map "$SECRETS_DIR/$_->[1]", @COPIES;
        my $ok = 1;
        for my $p (@paths) {
            if (!-e $p) { print "MISSING $p\n"; $ok = 0; next }
            my $mode = (stat($p))[2] & 07777;
            if ($mode != 0600 && $mode != 0700) {
                printf "WRONG PERMS %s (got %04o)\n", $p, $mode;
                $ok = 0; next;
            }
            if ($p =~ /sha256/) {
                open my $fh, '<', $p or do { print "CANNOT_READ $p\n"; $ok = 0; next };
                my $c = <$fh>; close $fh; chomp $c;
                if ($c !~ /^[0-9a-f]{64}$/) {
                    print "INVALID_HASH $p\n"; $ok = 0;
                }
            }
            print "OK $p\n";
        }
        exit($ok ? 0 : 1);
    }
    elsif ($MODE eq 'dry-run') {
        print "Dry-run mode - no files will be written.\n\n";
        for my $s (@SECRETS) {
            printf "  CREATE %-45s %3d bytes  %s\n",
                   "$SECRETS_DIR/$s->[0]", $s->[1], $s->[2];
        }
        for my $c (@COPIES) {
            printf "  COPY  %-45s <- %s\n",
                   "$SECRETS_DIR/$c->[1]", "$SECRETS_DIR/$c->[0]";
        }
        print "\nNo files were created.\n";
        exit 0;
    }

    mkdirs_for_secrets(map "$SECRETS_DIR/$_->[0]", @SECRETS, @COPIES);

    for my $s (@SECRETS) {
        my ($rel, $bytes, $type) = @$s;
        my $raw = rand_b64($bytes);
        if ($type eq 'sha256') {
            write_secret("$SECRETS_DIR/$rel", sha256_hex($raw) . "\n");
            warn_token('Atheros API Token', $raw);
        } else {
            write_secret("$SECRETS_DIR/$rel", $raw . "\n");
        }
    }

    for my $c (@COPIES) {
        copy_secret("$SECRETS_DIR/$c->[0]", "$SECRETS_DIR/$c->[1]");
    }

    lock_tree($SECRETS_DIR);
    print "OK: Secrets generated in $SECRETS_DIR/\n";
}

$MODE = 'generate';
for my $arg (@ARGV) {
    if ($arg =~ /^--(generate|dry-run|force|check)$/) {
        $MODE = $1;
    }
    else { die_usage() }
}
main($MODE);
