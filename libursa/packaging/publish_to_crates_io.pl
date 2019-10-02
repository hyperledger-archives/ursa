#!/usr/bin/perl

use v5.18;
use Cwd qw(abs_path);
use File::Basename;
use File::Copy;
use File::Find;
use File::Path;
use File::Spec;

## Figure out where the libursa folder is
## Depends on where the script is executed
my ($script, $dirs, $suffix) = File::Basename::fileparse( $0 );
my $src_dir = "";
if ($dirs eq "./") {
    $src_dir = Cwd::getcwd();
} else {
    if ( $dirs =~ m/^\// ) {
        $src_dir = $dirs;
    } else {
        $src_dir = File::Spec->join( Cwd::getcwd(), $dirs );
    }
}
$src_dir =~ s{(?:/|\\)$}{}; #Remove trailing path separator
my @src_dirs = File::Spec->splitdir( $src_dir );
pop( @src_dirs );
$src_dir = File::Spec->join( @src_dirs );
pop( @src_dirs );
my $root_dir = File::Spec->join( @src_dirs );
my $tgt_dir = File::Spec->join( File::Spec->tmpdir(), "libursa_packaging");

if ( -d $tgt_dir ) {
    File::Path::remove_tree( $tgt_dir );
}

File::Path::make_path($tgt_dir);

my $cargo = find_cargo();

unless ( $cargo ) {
    die( "Unable to find 'cargo' command" );
}

my @files = `$cargo package --manifest-path=$src_dir/Cargo.toml --allow-dirty --list 2>/dev/null`;

foreach my $file ( @files ) {
    chomp($file);
    if ( $file =~ m/^Cargo\.lock$/o ) {
        next;
    }
    my $src = File::Spec->join( $src_dir, $file );
    my $tgt = File::Spec->join( $tgt_dir, $file );

    my ($f, $dir, $s) = File::Basename::fileparse( $tgt );
    File::Path::make_path( $dir );
    File::Copy::copy( $src, $tgt );
}

File::Copy::copy( File::Spec->join( $root_dir, "LICENSE" ), File::Spec->join( $tgt_dir, "LICENSE" ) );
File::Copy::copy( File::Spec->join( $root_dir, "CHANGELOG" ), File::Spec->join( $tgt_dir, "CHANGELOG" ) );
File::Copy::copy( File::Spec->join( $root_dir, "README.md" ), File::Spec->join( $tgt_dir, "README.md" ) );

my $cargo_toml = File::Spec->join( $tgt_dir, "Cargo.toml" );
open( my $TOML, $cargo_toml ) or die( "Unable to read '$cargo_toml'" );
binmode( $TOML );
my @lines = <$TOML>;
close( $TOML );

my $version = "";

say "Updating Cargo.toml";
open( $TOML, ">", $cargo_toml ) or die( "Unable to write '$cargo_toml'" );
binmode( $TOML );

my $skip = 0;
foreach my $line ( @lines ) {
    chomp( $line );
    if ( $line eq "[[bin]]" || $line eq "[[bench]]") {
        $skip = 1;
    }
    elsif ( $line =~ m/^readme/mo ) {
        $line =~ s{\.\./}{}o;
    }
    elsif ( $line =~ m/^ version \s* = \s* "( [^"]+ )" \s* $/mox ) {
        $version = $1;
    }
    elsif ( $line =~ m/default \s* = \s* /mox ) {
        $line =~ s/"ffi"\s*,\s*//o;
    }
    if ( $skip ) {
        if ( $line =~ m/^\[ ( .+ ) \]$/mox ) {
            if ( $1 ne "[bin]" && $1 ne "[bench]" ) {
                $skip = 0;
            }
        }
    }
    if ( !$skip ) {
        say $TOML $line;
    }
}
close( $TOML );

unless ( $version ) {
    die("Missing required 'version' name in $cargo_toml");
}

my $res = system("$cargo publish --manifest-path=$tgt_dir/Cargo.toml --allow-dirty --dry-run");
if ( $res ) {
    exit(1);
}
my $package_dir = File::Spec->join( $tgt_dir, "target", "package", "ursa-$version" );
opendir( my $DIR, $package_dir ) or die( "Unable to find '$package_dir'" );
@files = grep( !/^\.\.?$/, readdir( $DIR ) );
close( $DIR );

say "";
say "Contents for $package_dir";
say "included in the ursa-$version.crate";
print "$/";

foreach my $file ( sort grep(! /target/, @files ) ) {
    say $file;
}
say "";
say "Does this look correct?";
say "Only 'yes' will be accepted to approve";
my $answer = <>;
chomp( $answer );
unless ( $answer eq 'yes' ) {
    say "Exiting...";
    exit(0);
}

system( "$cargo publish --manifest-path=$tgt_dir/Cargo.toml --allow-dirty" );

sub find_cargo {
    my $bin = $^O eq 'MSWin32' ? "cargo.exe" : "cargo";
    foreach my $path ( split( /:/, $ENV{"PATH"} ) ) {
        my $cargo = File::Spec->join( $path, $bin );
        if ( -f $cargo ) {
            return $cargo;
        }
    }
    return "";
}
