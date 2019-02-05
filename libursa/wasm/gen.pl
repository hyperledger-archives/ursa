#!/usr/bin/perl

use v5.18;
use Text::Balanced qw(extract_bracketed);

if (@ARGV < 1) {
    die("Expected rust test or filename");
}
my $buffer = $ARGV[0];
if (-f $buffer) {
    open(my $FILE, $buffer);
    binmode($FILE);
    read($FILE, $buffer, -s $FILE);
    close($FILE);
}

my $namespace = $ARGV[1];
unless ($namespace) {
    $namespace = 'super';
}

my %allowed_args = ('bool' => 1,
                    'str' => 1,
                    'String' => 1,
                    'u8' => 1,
                    'u16' => 1,
                    'u32' => 1,
                    'i8' => 1,
                    'i16' => 1,
                    'i32' => 1,
                    'f32' => 1);

say "use wasm_bindgen::prelude::*;";
say "use super::convert_from_js;";

my @usings = ();

my $output = "";

open my $ref, '>', \$output;
select($ref);

while ($buffer =~ m/\bpub\s+struct\s+(\w+)/gos)
{
    my $struct = $1;

    if ($buffer =~ m/\bimpl\s+\Q$struct\E\s+/gcs)
    {
        push (@usings, $struct);

        my ($block) = extract_bracketed($buffer, '{}');

        while ($block =~ m/\bpub\s+fn\s+(\w+)\s*(?:\<[\w,\s]+\>\s*)?/gosc) {
            my $function = $1;
            my $camelFunction = ucfirst($1);
            $camelFunction =~ s/_(\w)/\U$1/g;

            my ($args, $remainder) = extract_bracketed($block, '()');

            $args =~ s/\r?\n/ /go;
            $args =~ s/\A\s*\(\s*//so;
            $args =~ s/\s*\)\s*\Z//so;

            #anchor `pos` for extract_bracketed
            $remainder =~ s/\A\s*->\s*//gco;
            my $return = "";
            my $is_result = 0;

            if ($remainder =~ m/(\w+)\s*/gco) {
                my $res = $1;

                if ($res eq "Result") {
                    ($return) = extract_bracketed($remainder, '<>');
                    $is_result = 1;
                } else {
                    $return = $res;
                }
            }

            $return =~ s/\r?\n/ /go;
            $return =~ s/\A\s*\<\s*//g;
            $return =~ s/\s*\>\s*\Z//g;

            say "#[wasm_bindgen]";
            say "#[allow(non_snake_case)]";
            print "pub fn ". lcfirst($struct) . $camelFunction ."(";

            my $is_mut_self = 0;
            my $is_self = 0;
            my $comma = "";
            my @params = ();
            my @convert = ();
            while ($args =~ m/(?:^|,)\s*&?((?:mut\s+)?self)|(\w+)(?:\s*:\s*&?)(mut\s+)?(\[?\w+\]?)/goc) {
                print $comma;
                my $arg_self = $1;
                my $arg_name = $2;
                my $arg_is_mut = $3;
                my $arg_type = $4;
                my $arg_full = $&;

                if ($arg_self =~ m/mut\s+self/gso) {
                    $is_mut_self = 1;
                    print "myself: &JsValue";
                }
                elsif ($arg_self) {
                    $is_self = 1;
                    print "myself: &JsValue";
                }
                elsif(exists $allowed_args{$arg_type}) {
                    print $arg_full;
                    push (@params, $arg_name);
                }
                else {
                    my $is_mut = 0;
                    if ($arg_is_mut) {
                        $is_mut = 1;
                    }

                    my $param_name = $arg_name;
                    if ($arg_type eq 'Option') {
                        my ($option_type) = extract_bracketed($args, '<>');
                        my $pos = pos ($args);
                        $pos += length($option_type);
                        pos ($args) = $pos;

                        $arg_type .= $option_type;
                    } else {
                        $param_name = '&'.$arg_is_mut.$arg_name;
                        my ($type) = extract_bracketed($args, '<>');
                        if ($type) {
                            my $pos = pos ($args);
                            $pos += length($type);
                            pos ($args) = $pos;

                            $arg_type .= $type;
                        }
                    }
                    print $arg_name .': &JsValue';
                    push (@params, $param_name);
                    push (@convert, { 'name' => $arg_name, 'type' => $arg_type, 'is_mut' => $is_mut });
                }
                $comma = ", ";
            }

            print ')';
            my $is_void_return = 0;
            if ($return) {
                if ($is_result) {
                    print ' -> Result<';

                    if ($return =~ m/\(\s*\)/so) {
                        print '()';
                        $is_void_return = 1;
                    }
                    elsif ($return =~ m/\w+/so) {
                        print 'JsValue';
                    }

                    print ', JsValue> ';
                } else {
                    print ' -> JsValue ';
                }
            }
            say '{';

            # if ($function eq 'new') {
            #     foreach my $converts (@convert) {
            #         print "    let ";
            #         if ($converts->{'is_mut'}) {
            #             print "mut ";
            #         }
            #         say $converts->{'name'} .': '. $converts->{'type'} .' = convert_from_js('. $converts->{'name'} .')?;';
            #     }
            #     if ($is_result) {
            #         say '    let res = '. $struct . '::new()?;';
            #         say '    Ok(JsValue::from_serde(&res).unwrap())';
            #     }
            #     else {
            #         print "    ". $struct . "::new()";
            #         if ($is_void_return) {
            #             print ";";
            #         }
            #         print "\n";
            #     }
            #     say "}\n";
            # }
            # else {
                my $call_method = "";
                if ($is_mut_self) {
                    say "    let mut myself: $struct = convert_from_js(myself)?;";
                    $call_method = "myself.$function";
                }
                elsif ($is_self) {
                    say "    let myself: $struct = convert_from_js(myself)?;";
                    $call_method = "myself.$function";
                } else {
                    $call_method = $struct ."::". $function;
                }
                foreach my $converts (@convert) {
                    print "    let ";
                    if ($converts->{'is_mut'}) {
                        print "mut ";
                    }
                    say $converts->{'name'} .': '. $converts->{'type'} .' = convert_from_js('. $converts->{'name'} .')?;';
                }
                if ($is_result) {
                    if ($is_void_return) {
                        say "    $call_method(". join(", ", @params) . ")?;";
                        say "    Ok(())";
                    }
                    elsif ($return) {
                        say "    let res = $call_method(". join(", ", @params) . ")?;";
                        say "    Ok(JsValue::from_serde(&res).unwrap())";
                    }
                    else {
                        say "    $call_method(". join(", ", @params) . ")?;";
                    }
                }
                elsif ($return) {
                    if ($is_void_return) {
                        say "    $call_method(". join(", ", @params) . ");";
                    }
                    else {
                        say "    let res = $call_method(" . join(", ", @params) . ");";
                        say "    JsValue::from_serde(&res).unwrap()";
                    }
                }
                else {
                    say "    $call_method(". join(", ", @params) . ");";
                }
                say "}\n";
            # }
        }
    }
} 

select (STDOUT);
if (@usings > 5) {
    say "use $namespace"."::*;";
} else {
    say "use $namespace" . "::{" . join(",\n" . " " x (length("use $namespace" . "::{")), @usings) . "};";
}
say "\n$output";
