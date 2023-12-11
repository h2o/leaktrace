#! /usr/bin/env perl

use strict;
use warnings;
use File::Basename qw(basename);
use Getopt::Long;
use List::Util qw(first);

my ($pid, $dumpfn);
my (@maps, @callsites);

GetOptions(
   "pid=i"  => \$pid,
   "file=s" => \$dumpfn,
) or die "invalid command line arguments";

# read maps into @maps
open my $fh, "<", "/proc/$pid/maps"
    or die "failed to open /proc/$pid/maps:$!";
while (my $line = <$fh>) {
    chomp $line;
    $line =~ /^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+([0-9a-f]+)\s+\S+\s+\S+\s+/
        or die "failed to parse memory mapping line:$line";
    if (substr($', 0, 1) eq '/') {
        push @maps, {start => bighex($1), end => bighex($2), offset => bighex($3), exe => $'};
    }
}
close $fh;

# read dumpfn into @callsites
open $fh, "<", $dumpfn
    or die "failed to file $dumpfn:$!";
while (1) {
    my $line = <$fh>;
    die "unexpected end of line in $dumpfn" unless $line;
    chomp $line;
    last unless $line; # empty line terminates the input
    my ($bytes_alloced, $alloc_cnt, $free_cnt, $collision_cnt, @callers) = split /\s/, $line;
    push @callsites, {
        callers       => [ map { bighex($_) } @callers ],
        bytes_alloced => $bytes_alloced,
        alloc_cnt     => $alloc_cnt,
        free_cnt      => $free_cnt,
        collision_cnt => $collision_cnt,
    };
}

# sort the list by bytes_alloced in descending order
@callsites = sort { $b->{bytes_alloced} <=> $a->{bytes_alloced} } @callsites;

# print
for my $cs (@callsites) {
    printf "%d bytes at 0x%x, alloc=%d, free=%d, collision=%d\n", $cs->{bytes_alloced}, $cs->{callers}->[0], $cs->{alloc_cnt}, $cs->{free_cnt}, $cs->{collision_cnt};
    # resolve addresses
    for my $addr (@{$cs->{callers}}) {
        my $map = first { $_->{start} <= $addr && $addr <= $_->{end} } @maps;
        if ($map) {
            my $offset = $addr - $map->{start} + $map->{offset};
            my $loc = addr2line($map->{exe}, $offset)
                or last;
            print $loc;
        }
    }
    print "\n";
}

sub addr2line {
    my ($exe, $addr) = @_;
    open my $fh, "-|", qw(addr2line -pif -e), $exe, sprintf("%x", $addr)
        or return;
    my @lines = <$fh>;
    pop @lines
        if $lines[$#lines] eq '';
    @lines = map { "  $_" } @lines;
    join "", @lines;
}

sub bighex {
    my $s = shift;

    $s =~ s/^0x//;

    no warnings 'portable';
    hex $s;
}
