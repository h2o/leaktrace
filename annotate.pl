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
    if ($') {
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
    $line =~ /^0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/
        or die "failed to parse leaktrace dump line:$line";
    push @callsites, {addr => bighex($1), bytes_alloced => $2, alloc_cnt => $3, free_cnt => $4, collision_cnt => $5};
}

# annotate the entries @callsites with symbols
for my $cs (@callsites) {
    my $map = first { $_->{start} <= $cs->{addr} && $cs->{addr} <= $_->{end} } @maps;
    if ($map) {
        $cs->{exe} = $map->{exe};
        $cs->{exe_off} = $cs->{addr} - $map->{start} + $map->{offset};
        if (my $loc = addr2line($map->{exe}, $cs->{exe_off})) {
            $cs->{location} = $loc;
        }
    }
}

# sort the list by bytes_alloced in descending order
@callsites = sort { $b->{bytes_alloced} <=> $a->{bytes_alloced} } @callsites;

# print
print "addr\tbytes\talloc\tfree\tcoll\tlocation\n";
for my $cs (@callsites) {
    if ($cs->{exe}) {
        printf "%s+%x", basename($cs->{exe}), $cs->{exe_off};
    } else {
        printf "0x%x", $cs->{addr};
    }
    printf "\t%d\t%d\t%d\t%d\t%s\n", $cs->{bytes_alloced}, $cs->{alloc_cnt}, $cs->{free_cnt}, $cs->{collision_cnt}, $cs->{location} || "";
}

sub addr2line {
    my ($exe, $addr) = @_;
    open my $fh, "-|", qw(addr2line -pif -e), $exe, $addr
        or return;
    my $resolved = <$fh>;
    chomp $resolved;
    $resolved;
}

sub bighex {
    no warnings 'portable';
    hex shift;
}
