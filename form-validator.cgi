#!/usr/bin/env perl

$VERSION = "1.1 alpha";

#
# Script designed to take a submitted form, validate it according to a set of
# rules and either forward form submission to another url or redisplay the form
# in a browser, highlighting fields that could not be validated.
#
#######################################

package UmkaDK::FormValidator;

use strict;
use warnings;

use English;
use CGI;

#
# User Configuration Section
#
#######################################

# Define if we want to use log file
our $use_logfile    = 1;
our $log_path       = './log';
our $log_file       = 'form-validator.log';

# Define if we want to log to a mail message
our $use_emaillog   = 0;
our $mail_address   = 'mail@example.com';
our $mail_subject   = 'Validated Form Submission';

# defina a set of validation rules
our %rules = (
        ".*/form-validator.html" => [

            {   "name"      => 'name',
                "pattern"   => '\d+',
                "error"     => 'Name was entered incorrectly!' },

            {   "name"      => 'position',
                "pattern"   => '\d+',
                "error"     => 'Could not determine your position!' },
        ],
);

#######################################
##    DO NOT EDIT PASS THIS POINT    ##
#######################################

our $date_cmd   = "/bin/date";
our $mail_cmd   = "/usr/bin/mail";
our $lynx_cmd   = "/usr/local/bin/lynx";

#
# Local Subroutine Definitions
#
#######################################

sub get_form_url () {
    my $request = $UmkaDK::FormValidator::request;
    my $url = $request -> param( "UmkaDK::FormValidator::location" );

    if ( !$url ) {
        $url = $request -> referer();
    }

    return( $url );
}

sub fetch_url ($) {
    my $url = shift( @_ );
    my $lynx_cmd = $UmkaDK::FormValidator::lynx_cmd;

    # Use lynx to fetch the source of the page
    my $source = readpipe( "$lynx_cmd -source $url" );
    chomp( $source );

    return( $source );
}

sub find_rule () {
    my $url = $UmkaDK::FormValidator::form_url;
    my %rules = %UmkaDK::FormValidator::rules;

    # Find a set of rules for this referer
    foreach my $id ( keys( %rules )) {
        next unless ( $url =~ qr/^$id$/i );

        $UmkaDK::FormValidator::rules = $rules{ $id };

        return( 1 );
    }

    return( 0 );
}

sub check_post () {
    my $rules = $UmkaDK::FormValidator::rules;
    my $request = $UmkaDK::FormValidator::request;
    my $return_value = 1;

    foreach my $rule ( @$rules ) {
        my $value = $request -> param( $$rule{ "name" });
        my $pattern = $$rule{ "pattern" };

        next unless ( $value !~ qr/^$pattern$/si );

        # Rewrite page source to highlight the error
        show_error( $rule );
        $return_value = 0;
    }

    return( $return_value );
}

sub show_error ($) {
    my $rule = shift( @_ );
    my $source = \$UmkaDK::FormValidator::form_src;

    # Identify search and replace strings
    my $search = '<label for="'.$$rule{ "name" }.'">';
    my $replace = '<span class="error">'.$$rule{ "error" }."</span>";

    # Replace search string with replace string
    $$source =~ s/($search)/$replace\n$1/sg;

    return( 1 );
}

sub rewrite_form () {
    my $source = \$UmkaDK::FormValidator::form_src;
    my $url = $UmkaDK::FormValidator::form_url;
    my $request = $UmkaDK::FormValidator::request;

    my %post = $request -> Vars();

    # Add hidden field identifying form's location
    my $search = '<input type="hidden" '
                .'name="UmkaDK::FormValidator::redirect" '
                .'value=".*?" />';
    my $extra = '<input type="hidden" '
            .'name="UmkaDK::FormValidator::location" '
            .'value="'.$url.'" />';
    $$source =~ s/($search)/$1\n$extra/;

    # Add user submited values into a form
    while ( my( $key, $value ) = each( %post )) {
        # Replace text in an input field (normal order)
        if ( $$source =~ '<input .*?name="'.$key.'" .*?value=".*?" .*?/>' ) {
            my $search = '(<input .*?name="'.$key.'" .*?value=").*?(" .*?/>)';
            $$source =~ s/$search/$1$value$2/;
        }

        # Replace text in an input field (reverse order)
        if ( $$source =~ '<input.*?value=".*?" .*?name="'.$key.'".*? />' ) {
            my $search = '(<input .*?value=").*?(" .*?name="'.$key.'".*? />)';
            $$source =~ s/$search/$1$value$2/;
        }

        # Replace text inside a textarea tag
        if ( $$source =~ '<textarea .*?name="'.$key.'" .*?>' ) {
            my $search = '(<textarea .*?name="'.$key.'".*?>).*?(</textarea>)';
            $$source =~ s/$search/$1$value$2/;
        }

        # Remember our select setting
        if ( $$source =~ '<select .*?name="'.$key.'" .*?>' ) {
            # Cut out the old [selected="selected"]
            my $search = '(<select .*?name="'.$key.
                    '".*?) selected="selected"(>.*?</select>)';
            $$source =~ s/$search/$1$2/;

            # Put in the new [selected="selected"]
            $search = '(<option value="'.$value.'")(>)';
            $$source =~ s/$search/$1 selected="selected"$2/;
        }
    }

    return( 1 );
}

sub resubmit_form () {
    my $request = $UmkaDK::FormValidator::request;
    my $lynx_cmd = $UmkaDK::FormValidator::lynx_cmd;
    my $mail_cmd = $UmkaDK::FormValidator::mail_cmd;
    my $date_cmd = $UmkaDK::FormValidator::date_cmd;
    my $subject = $UmkaDK::FormValidator::mail_subject;
    my $address = $UmkaDK::FormValidator::mail_address;

    # Collect all of the posted data
    my %post = $request -> Vars();
    my $url = $request -> param( "UmkaDK::FormValidator::redirect" );
    my @post;

    # Build post data string
    while ( my( $key, $value ) = each( %post )) {
        push( @post, $key."=".$value );
    }

    # Use lynx to submit posted data
    my $post_str = join( "&", @post );
    my $result = readpipe( "echo \"$post_str\" | $lynx_cmd -post_data $url" );

    # Record posted data to log file
    if ( $use_logfile == 1 ) {
        my $log = "$log_path/$log_file";
        my $date = readpipe( $date_cmd );
        chomp( $date );

        open( LOG, ">> $log" )
                or die( "Couldn't open the log file: $log -> $! \n" );
        print( LOG "\n[ ".$date." ]\n> ".join( "\n> ", @post )."\n" );
        close( LOG );
    }

    # Record posted data to an email
    if ( $use_emaillog == 1 ) {
        my $message = format_mail();
        system( "echo \"$message\" | $mail_cmd -s \"$subject\" $address" );
    }

    # Redirect to url defined by UmkaDK::FormValidator::action
    print( $request -> redirect( $url ));

    return( 1 );
}

sub format_mail () {
    my $request = $UmkaDK::FormValidator::request;
    my $source = $UmkaDK::FormValidator::form_src;

    # Get a list of posted variables
    my %post = $request -> Vars();

    # Define a message header
    my $message = "A new submission was made using Form Validator CGI: \n\n";

    # Cycle through all posted variables
    while( my( $key, $value ) = each( %post )) {
        my ( $label ) = ( $source =~ m#<label for="$key">(.*?)</label>#si );
        $label = $key unless defined( $label );
        $message .= "> $label  $value \n";
    }

    # Close message with this footer
    $message .= "\n\n"
        ."This mail was generated by a script, please do not reply. \n"
        ."Form Validator (CGI) version ".$main::VERSION;

    return( $message );
}

sub debug ($) {
    my $message = shift( @_ );
    my $request = $UmkaDK::FormValidator::request;

    print( $request -> header(), $request -> start_html(),
            $request -> b( " ".$message."<br />" ),
            $request -> end_html());

    return( 1 );
}

#
# Main Script
#
#######################################

# New CGI object
our $request = new CGI;

# Collect referrer, and its source
our $form_url = get_form_url();
our $form_src = fetch_url( $form_url );

# Exit with all clear if no matching rules were found or
if ( !find_rule()) {
    resubmit_form();
    exit;
}

# Exit with all clear if all rules validated correctly
elsif ( check_post()) {
    resubmit_form();
    exit;
}

# The following is only executed when validation fails
else {
    rewrite_form();
    print( $request -> header(), $form_src );
}

exit;
