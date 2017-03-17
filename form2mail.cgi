#!/usr/bin/env perl

$VERSION = '1.1.1';

package UmkaDK::Form2mail;

# Configure package behaviour
use 5.8.1;
use strict;
use warnings;
use utf8;

# Define a list of required modules
use English;
use POSIX;
use File::Basename;
use FindBin;
use CGI;
use Net::DNS;
use Config::General;
use MIME::Lite;
use MIME::Base64;
use Data::Dumper;

# Initialise object interface containers and global variables
our ($Cgi, $Config, $Resolver, $Mail, $invalid, $raw_input);

# Set a path variables used to locate config and template files
my $prefix = dirname($FindBin::Bin);
my $suffix = basename($FindBin::Script, ('.pl', '.cgi'));

# Initialise default configuration, post-processed by configure()
our $config = {
    'prefix'        => $prefix,
    'suffix'        => $suffix,

    # Default config initialisation
    'rc_file'       => 'default.rc',
    'rc_path'       => ["$prefix/etc/$suffix",
                        "$prefix/etc",
                        "/usr/local/etc/$suffix",
                        "/usr/local/etc",
                        "/etc/$suffix",
                        "/etc"],

    # Default values for internal variables
    'path_info'     => 'no-reply',
    'concat_str'    => 'The following data was submitted through URL:',

    # Internal regular expressions
    'url_regexp'    => '^(http|https|ftp)://[^/]+(/[^\s]*)?$',

    # Names the before / after eval hooks in the config
    'eval_before'   => 'rewrite_before_config',
    'eval_after'    => 'rewrite_after_config',

    # Default log file settings
    'log_file'      => '/dev/null',
    'log_indent'    => '  ',
    'log_rewrite'   => 0,

    # Fallback error messages
    'e_initialise'  => 'Form2mail: failed to initialise',
    'e_validate'    => 'Form2mail: invalid data submitted',
    'e_buildmail'   => 'Form2mail: failed to compose mail',
    'e_sendmail'    => 'Form2mail: failed to send mail',

    # A list of RBL domains to try
    'rbl_domains'   => ['bl.spamcop.net',
                        'sbl.dnsbl.ja.net',
                        'xbl.dnsbl.ja.net'],

    # A list of keys to be excluded from the mail submission report
    'exclude_keys'  => ['submit',
                        'returntext',
                        'returnurl',
                        'returnlocation'],

    # A list CGI.pm functions to use for fetching submitted data
    'cgi_fetch'     => {'http'  => 'http',
                        'https' => 'https',
                        'get'   => 'url_param',
                        'post'  => 'param'},
};

# A hack to keep track of the order of the submitted elements
#read(STDIN, $raw_input, $ENV{'CONTENT_LENGTH'});

##
#
# Primary subroutine, invoked after initialising global space
#
# @return bool
#
sub main() {
    # Initialise globally required modules
    $Resolver = Net::DNS::Resolver->new();

    $Cgi = CGI->new();

    # Initialise modules that depend on configured settings
    $Config = new Config::General(
        -DefaultConfig      => configure(),
        -ConfigFile         => $config->{'rc_file'},
        -ConfigPath         => $config->{'rc_path'},
        -ExtendedAccess     => 'yes',
        -StrictObjects      => 'no',
        -StrictVars         => 'no',
        -AutoTrue           => 'yes',
        -LowerCaseNames     => 'yes',
        -AllowMultiOptions  => 'yes',
        -BackslashEscape    => 'yes',
        -CComments          => 'no',
        -SlashIsDirectory   => 'yes',
        -UseApacheInclude   => 'yes',
        -IncludeRelative    => 'yes',
        -IncludeGlob        => 'yes',
        -IncludeDirectories => 'no',
        -InterPolateVars    => 'no');

    # Re-configure and initialise log file output
    $config->{'log_file'} = $Config->value('debug') if (
        $Config->value('debug') and ($Config->value('debug') =~ m/^\//));
    open LOG, '>>', $config->{'log_file'};

    # Output log file header for the current instance of the script
    echoLog('Local Time: '.$config->{'start_time'});
    echoLog('Remote System: '.$config->{'remote_sys'});
    echoLog('HTTP Referer: '.$Cgi->referer());

    my $return = form2mail();

    # Tell user that everything went as planned
    # (in case of an error we would have already informed them)
    if (defined($return)) {
        # Fetch configured defaults
        my $page = getConfigValue($Config->obj('form'), 'title');
        my $code = 200;
        my $text = getConfigValue($Config->obj('form'), 'success');

        # Enable backwards compatibility layer (BCL)
        $text = bclUserReply($text);

        # Redefine current response if redirect detected
        if ($text =~ m/$config->{'url_regexp'}/) {
            $page = $text;
            $code = 302;
        }

        # Define user output message
        echoPage($page, $code, [split("\n\n", $text)]);
    }

    # Output log file footer and terminate log file handle
    echoLog('');
    close LOG;

    return $return;
}

##
#
# Primary processing subroutine. Invoked once, and only once, from main()
# and is used to split off all logical script action from pre- and post-
# processing subroutines.
#
# @return bool
#
sub form2mail() {
    # Complain if process is invoked by invalid user / data
    if (!defined(isValidProcess())) {
        echoLog('Invalid user or data submitted. See log for details.');
        return undef;
    }

    # Submitted data is valid, proceed to compose mail
    echoLog('Submitted data is valid, procceding to compose mail');

    # Abandon no longer required method key configs
    $Config->obj('form')->delete('get');
    $Config->obj('form')->delete('post');

    # Create a human readable container for get and post data
    $Config->value('data_get', getFormattedData('GET'));
    $Config->value('data_post', getFormattedData('POST'));

    # Create a human readable container for all submitted data
    $Config->value('data_all', join($config->{'concat_str'}, grep(/\S/,
        ($Config->value('data_post'), $Config->value('data_get'))
    )));

    # Write current config to a string
    # (Make sure top level vars are defined first)
    my $config_form = $Config->obj('form')->save_string();
    my $config_mail = $Config->obj('mail')->save_string();
    $Config->delete('form');
    $Config->delete('mail');
    my $config = $Config->save_string()
        ."<form>\n${config_form}\n</form>\n"
        ."<mail>\n${config_mail}\n</mail>\n";

    # Re-initialise config with variable interpolation
    $Config = new Config::General(
        -String             => $config,
        -ExtendedAccess     => 'yes',
        -StrictObjects      => 'no',
        -StrictVars         => 'no',
        -AutoTrue           => 'yes',
        -AllowMultiOptions  => 'yes',
        -BackslashEscape    => 'yes',
        -CComments          => 'no',
        -SlashIsDirectory   => 'yes',
        -InterPolateVars    => 'yes');

    # Exit if mail could not be configured
    if (!defined(buildMail($Config->obj('mail')))) {
        my $text = ['CGI script failed to compose a mail message'];
        echoPage($config->{'e_buildmail'}, 500, $text);
        echoLog('Invalid mail configuration. See above log for details.');
        return undef;
    }

    # Proceed to processing submitted data
    echoLog('Mail composed ok, procceeding to send mail');

    # Send mail and check that it was sent successfully
    if (!eval{$Mail->send()}) {
        my $text = ['CGI script failed to send a mail message'];
        echoPage($config->{'e_sendmail'}, 500, $text);
        echoLog("Problems sending mail, MIME::Lite returned 'undef'");
        echoLog($Mail->as_string(), "\n---[ Start of Mail Message ]---");
        echoLog("\n---[ End of Mail Message ]---");
        return undef;
    }

    # Clean up and terminate
    echoLog('Mail sent successfully.');
    return 1;
}

##
#
# Configuration post-processing routine. Used to calculate extra config values
# and re-configure existing values based on user input.
#
# @return 1
#
sub configure() {

    # Define start time and who initialised the script
    $config->{'start_time'} = strftime('%e/%b/%Y %H:%M:%S', localtime());
    $config->{'remote_sys'} = ($Cgi->remote_addr() eq $Cgi->remote_host())
        ? $Cgi->remote_addr()
        : $Cgi->remote_addr().' ('.$Cgi->remote_host().')';

    # Retrieve a list of all user submitted variables
    my $return = {%{$Cgi->https()
            ? getSubmittedData('HTTPS')
            : getSubmittedData('HTTP')},
        %{getSubmittedData('GET', undef, 'get_')},
        %{getSubmittedData('POST', undef, 'post_')}};

    # Add a list of top-level fallback values
    $return->{'start_time'} = $config->{'start_time'};
    $return->{'remote_sys'} = $config->{'remote_sys'};
    $return->{'remote_host'} = $Cgi->remote_host();
    $return->{'remote_addr'} = $Cgi->remote_addr();
    $return->{'path_info'} = $config->{'path_info'};
    $return->{'server_protocol'} = $ENV{'SERVER_PROTOCOL'};

    # Reconfigure rc_file value based on supplied path_info
    # ...only do it if a clean value has been supplied (no slashes, etc)
    if ($Cgi->path_info() =~ m/^\/([a-zA-Z0-9][\w.-]*[a-zA-Z0-9])$/) {
        $return->{'path_info'} = $1;

        # Cycle through all rc directories looking for custom config
        foreach my $rc_path (@{$config->{'rc_path'}}) {
            # Test for custom config file in the defined rc_path
            if (-r "$rc_path/$1.rc") {
                $config->{'rc_file'} = "${1}.rc";
                last;
            }
        }
    }

    return $return;
}

##
#
# Initial environment validation. This subroutine is used to validate current
# user and ensure basic sanity of the config file.
#
# @return bool
#

sub isValidProcess() {
    # Fallback to the following error message during the initialisation
    my $text = ['CGI script failed to process submitted data'];

    # Make sure that submitter's address has not been blacklisted (RBL)
    if (isBlacklisted($Cgi->remote_addr)) {
        echoLog('Remote address is black listed. Refusing to proceed.');
        echoPage($config->{'e_initialise'}, 400, $text);
        return undef;
    }

    # Complain if invalid <Form> section is detected in config
    if (!$Config->exists('form') or !$Config->is_hash('form')) {
        echoLog('ERROR: Invalid config, <Form> section not found');
        echoPage($config->{'e_initialise'}, 500, $text);
        return undef;
    }

    # Complain if invalid <Mail> section is detected in config
    if (!$Config->exists('mail') or !$Config->is_hash('mail')) {
        echoLog('ERROR: Invalid config, <Mail> section not found');
        echoPage($config->{'e_initialise'}, 500, $text);
        return undef;
    }

    # Complain if user submitted invalid data
    if (!defined(isValidSubmission($Config->obj('form')))) {
        my $page = $config->{'e_validate'};
        my $code = 400;
        my $text = getConfigValue($Config->obj('form'), 'failure');

        # Redefine current response if redirect requested
        if ($text =~ m/$config->{'url_regexp'}/) {
            my $page = $text;
            my $code = 302;
        }

        echoPage($page, $code, [split("\n\n", $text), @{$invalid}]);
        echoLog('Invalid data submitted. See above log for details.');
        return undef;
    }

    return 1;
}

##
#
# Allows as to use dns lookup to determine if an address has been blacklisted
# by any of the configured realtime blackhole list (RBL) providers.
#
# @param string An IP address that is to be validated against a black list
#
# @return bool
#
sub isBlacklisted($) {
    my ($remote_addr) = @_;

    # Rewrite remote IP address into a form used by RBLs
    my $address = join('.', reverse split(/\./, $remote_addr));

    # Query all configured RBL domains for remote IP address
    foreach my $domain ($config->{'rbl_domains'}) {
        # Query RBL and see if address is know (know == unlisted)
        my $Query = $Resolver->query("${address}.${domain}", "A");
        next if (!defined($Query));

        # Process all Net::DNS::RR object returned by Net::DNS::Packet
        foreach my $Rr ($Query->answer()) {
            # Only react to know addresses if they've been blacklisted
            next if (($Rr->class ne 'IN') or ($Rr->type ne 'A'));
            return 1;
        }
    }

    return undef;
}

##
#
# Test if all values submitted by the user as part of the GET or POST request
# match rules defined in the config. This subroutine will also pre-process
# config file to make sure that it contains only valid rules.
#
# @param obj(Config::General) Configuration object to be examined
#
# @return bool
#
sub isValidSubmission(\$) {
    my ($Config) = @_;

    # Process all configured GET parameters
    if ($Config->exists('get')) {
        echoLog('Validating HTTP GET data...', 1);

        # Exit if invalid <Get [name]> section is detected in config
        if (!$Config->is_hash('get')) {
            echoLog('ERROR: Invalid config, <Get [key]> not a section', 1);
            return undef;
        }

        # Complain if submitted data doesn't match configured expectations
        if (!defined(processSubmitted($Config, 'GET'))) {
            echoLog('Failed', 1);
            return undef;
        }

        # Record data validation result to the log file
        echoLog('Ok', 1);
    }

    # Process all configured POST parameters
    if ($Config->exists('post')) {
        echoLog('Validating HTTP POST data...', 1);

        # Exit if invalid <Post [name]> section is detected in config
        if (!$Config->is_hash('post')) {
            echoLog('ERROR: Invalid config, <Post [key]> not a section', 1);
            return undef;
        }

        # Complain if submitted data doesn't match configured expectations
        if (!defined(processSubmitted($Config, 'POST'))) {
            echoLog('Failed', 1);
            return undef;
        }

        # Record data validation result to the log file
        echoLog('Ok', 1);
    }

    return 1;
}

##
#
# Process all data submitted by a method (GET/POST) validating each value
# against a set of rules described in the config file.
#
# @param obj(Config::General) Configuration object to be examined
#
# @param string A name of the method who's data is to be validated
#
# @return bool
#
sub processSubmitted(\$$) {
    my ($Config, $method) = @_;

    # Initialise method's configuration, data and return values
    $method = lc($method);
    $Config = $Config->obj($method);
    my $data = getSubmittedData($method);
    my $return = 1;

    # Validate user submissions
    foreach my $key ($Config->keys()) {
        # Describe what we are planning to do
        echoLog("Validating configured key [$key] ...", 2);
        $key = lc($key);

        # Initialise value based on the normalised key
        my $value = exists($data->{$key})
            ? useEvalHook($method, $key,
                $config->{'eval_before'}, $data->{$key})
            : useEvalHook($method, $key, $config->{'eval_before'}, undef);

        # Initialise local variables
        my ($is_required, @is_ignored, $invalid_msg);
        my $is_empty = defined($value) ? undef : 1;

        # Initialise configured require value
        if ($Config->obj($key)->exists('require')) {
            $is_required = getConfigValue($Config->obj($key), 'require');
        }

        # Initialise optional require value
        else {
            echoLog("Missing 'require' option, defaulting to: not required", 3);
            $is_required = 0;
        }

        # Initialise configured ignore value
        if ($Config->obj($key)->exists('ignore')) {
            @is_ignored = getConfigValues($Config->obj($key), 'ignore');
        }

        # Initialise optional ignore value
        else {
            echoLog("Missing 'ignore' option, defaulting to: empty list", 3);
            @is_ignored = ();
        }

        # Initialise configured invalid message
        if ($is_required) {
            $invalid_msg = getConfigValue($Config->obj($key), 'invalid');
        }

        # Initialise optional invalid message
        else {
            $invalid_msg = $Config->obj($key)->exists('invalid')
                ? getConfigValue($Config->obj($key), 'invalid')
                : undef;
        }

        # Fail validation if we detect a configuration error
        if (!defined($is_required)
                or (exists ($is_ignored[0]) and !defined($is_ignored[0]))
                or ($is_required and !defined($invalid_msg))) {
            echoLog('Failed', 2);
            $return = undef;
            next;
        }

        # Validate empty submission values
        if ($is_empty) {
            # Complain if required value is missing
            if ($is_required) {
                echoLog('Submitted value is not allowed to be empty', 3);
                push(@{$invalid}, $invalid_msg);
                echoLog('Failed', 2);
                $return = undef;
                next;
            }

            # Inform log file that an empty value was submitted
            echoLog(defined($value)
                ? 'Submitted value is empty'
                : 'No value has been submitted', 3);
            $value = useEvalHook($method, $key,
                $config->{'eval_after'}, $value);
            echoLog('Ok', 2);
            next;
        }

        # Validate ignored submission values
        if (grep { $_ eq $value } @is_ignored) {
            # Complain if required value is missing
            if ($is_required) {
                echoLog('Submitted value matched one of the ignore values', 3);
                echoLog('Value: '.$value, 3);
                echoLog('Failed', 2);
                push(@{$invalid}, $invalid_msg);
                $return = undef;
                next;
            }

            # Inform log file that an empty value was submitted
            echoLog('Submitted value is ignored', 3);
            $value = useEvalHook($method, $key,
                $config->{'eval_after'}, $value);
            echoLog('Ok', 2);
            next;
        }

        # Check if we need to test value against configured regexp
        if ($Config->obj($key)->exists('regexp')) {
            my @regexp = getConfigValues($Config->obj($key), 'regexp');

            # Fail validation if we detect a configuration error
            if (!defined($regexp[0])) {
                echoLog('Failed', 2);
                $return = undef;
                next;
            }

            # Check if the value matches pre-configured regexp
            foreach my $regexp (@regexp) {
                # Tell user about failed validation if value not match regexp
                if ($value !~ m/$regexp/) {
                    echoLog('Submited value did not match regexp', 3);
                    echoLog('Regexp: '.$regexp, 3);
                    echoLog('Value: '.$value, 3);
                    echoLog('Failed', 2);
                    push(@{$invalid}, $invalid_msg);
                    $return = undef;
                    last;
                }
            }
        }

        # Log that no pattern matching was done
        else {
            echoLog("Missing 'regexp' option, no matching will be done", 3);
        }

        # Report that everything matched ok
        $value = useEvalHook($method, $key, $config->{'eval_after'}, $value);
        echoLog('Ok', 2);
    }

    return $return;
}

##
#
# Allow administrator to modify currently submitted user value based on pre-
# and post- configuration hooks defined in the config file.
#
# @param string The name of the method used to submit the value (GET/POST)
#
# @param string The name of the key used to identify this value in submission
#
# @param string The name of the hook that is to be applied to the value
#
# @param mixed Initial value (will be returned if hook fails)
#
# @return mixed
#
sub useEvalHook($$$$) {
    my ($method, $key, $hook, $value) = @_;

    # Return unchanged value if eval_hooks does not exists
    return $value
        if (!$Config->obj('form')->obj($method)->obj($key)->exists($hook));

    # Inform log file that eval hook has been detected
    echoLog("Eval hook detected: ${hook}", 3);

    # Collect the value of the eval hook
    my $code = getConfigValue(
        $Config->obj('form')->obj($method)->obj($key), $hook);

    # Return unmodified value if there was a problem fetching the code
    return $value if (!defined($code));

    # Initialise eval code and friends
    my $eval = "\n";
    my %config = $Config->getall();

    # Remove form and mail section definitions
    delete $config{'form'};
    delete $config{'mail'};

    # Convert hash ref into a list of 'my' variables
    # Making them available to the evaluated code
    foreach my $key (keys %config) {
        $eval .= "my \$${key} = \$Config->value('$key');\n"
    }

    # Append user hook and evaluate created code
    my $eval_value = eval $eval.$code."\n";
    #echoLog($eval.$code."\n", "\nDEBUG: Evaluated code....");

    # Complain about invalid hook and return original value
    if (!defined($eval_value)) {
        chomp(my $eval_error = $@);
        echoLog("ERROR: Hook failed with $eval_error", 3);
        return $value;
    }

    # Log pre and post modified values to the log file
    if ($config->{'log_rewrite'}) {
        echoLog("-- $value", 3);
        echoLog("++ $eval_value", 3);
    }

    # Override current config value
    $Config->value("${method}_${key}", $eval_value);

    return $eval_value;
}

##
#
# Parse mail section of the config file making sure that it uses sane(ish)
# values and configure a mail composition object accordingly.
#
# @param obj(Config::General) Configuration object to be examined
#
# @return bool
#
sub buildMail(\$) {
    my ($Config) = @_;

    # Refuse to initialise empty message
    if (!$Config->exists('message') or !$Config->is_scalar('message')
            or !$Config->value('message')) {
        echoLog('ERROR: Invalid config, mail message not found or empty',1);
        return undef;
    }

    # UTF-8 encode outgoing message
    my $message = $Config->value('message');
    utf8::encode($message);

    # Initialise OO interface to the MIME Mailer
    $Mail = MIME::Lite->new(
        Type => 'TEXT',
        Data => $message,
    );

    # Identify mail as UTF-8 encoded
    $Mail->attr('content-type.charset' => 'UTF-8');

    # Process all custom headers
    if ($Config->exists('headers')) {
        echoLog('Configuring custom mail headers...', 1);

        # Exit if invalid <Headers> section is detected in config
        if (!$Config->is_hash('headers')) {
            echoLog('ERROR: Invalid config, <Headers> not a section', 1);
            return undef;
        }

        # Exit if we failed to add any of the custom headers
        if (!defined(addMailHeaders($Config))) {
            echoLog('Failed', 1);
            return undef;
        }

        # Log successful exit status and proceed
        echoLog('Ok', 1);
    }

    # Do this if <Headers> section is missing
    else {
        echoLog('ERROR: Invalid config, <Headers> section not found', 1);
        return undef;
    }

    # Process all file/templates to be included with the mail
    if ($Config->exists('attach')) {
        echoLog('Configuring mail attachments...', 1);

        # Exit if invalid <Headers> section is detected in config
        if (!$Config->is_hash('attach')) {
            echoLog('ERROR: Invalid config, <Attach> not a section', 1);
            return undef;
        }

        # Exit if we failed to add any of the custom headers
        if (!defined(addMailAttach($Config))) {
            echoLog('Failed', 1);
            return undef;
        }

        # Log successful exit status and proceed
        echoLog('Ok', 1);
    }

    return 1;
}

##
#
# Parse config file and include all custom headers defined in Mail->Headers
# section. All headers defined in this section will override default values.
#
# @param obj(Config::General) Configuration object to be examined
#
# @return bool
#
sub addMailHeaders(\$) {
    my ($Config) = @_;
    my $return = 1;

    # Configure all defined custom headers
    foreach my $header ($Config->keys('headers')) {
        echoLog("Setting '$header' headers...", 2);
        my @values = getConfigValues($Config->obj('headers'), $header);

        # Fail validation if we detect a configuration error
        if (!defined($values[0])) {
            $return = undef;
            echoLog('Failed', 2);
            next;
        }

        # Add custom headers to the mail message
        if (lc($header) eq 'subject') {
            my $value = join(' ', @values);
            utf8::encode($value);
            chomp($value = encode_base64($value));

            $value = '=?UTF-8?B?'.$value.'?=';
            $Mail->add($header => $value);
        }

        # Add default headers to the mail message
        else {
            $Mail->add($header => \@values);
        }

        # Report validation status to the log
        echoLog(join(' ', $Mail->get($header)), 3);
        echoLog('Ok', 2);
    }

    return $return;
}

##
#
# Parse config file and include all files defined within the Mail->Attach
# section. in order to avoid ambiguity only readable files referenced with an
# absolute path will be included. An error will be logged in all other cases.
#
# @param obj(Config::General) Configuration object to be examined
#
# @return bool
#
sub addMailAttach(\$) {
    my ($Config) = @_;
    my $return = 1;

    # Process all required mail attachments
    foreach my $attach ($Config->keys('attach')) {
        echoLog("Including $attach...", 2);

        if ($attach !~ m/^\//) {
            echoLog("ERROR: Invalid attachment: $attach", 3);
            $return = undef;
            next;
        }

        # Exit if attachment is not readable
        if (!-r $attach) {
            echoLog("ERROR: File not readable: $attach", 3);
            $return = undef;
            next;
        }

        # Determine the attachment MIME type
        my $type = $Config->obj('attach')->value($attach)
            ? getConfigValue($Config->obj('attach'), $attach)
            : 'AUTO';

        # Create a new mail attachment
        $Mail->attach(
            Type    => $type,
            Path    => $attach);
        echoLog('Ok', 2);
    }

    echoLog('Failed', 2) if (!defined($return));

    return 1;
}

##
#
# Retrieve a list value of a key from a given config. This function will
# validate config while retrieving a value, convert scalar value to a list and
# will log an error message if an unexpected value (hash) is encountered.
#
# @param obj(Config::General) Configuration object to be examined
#
# @param string A name of the config key to be retrieved
#
# @return array
#
sub getConfigValues(\$$) {
    my ($Config, $name) = @_;

    # Complain if requested value does not exist in the config
    if (!$Config->exists($name)) {
        echoLog("ERROR: Invalid config, '$name' keys not found", 3);
        return undef;
    }

    # Complain if requested value is configured as a hash
    if ($Config->is_hash($name)) {
        echoLog("ERROR: Invalid config, section '$name' not allowed", 3);
        return undef;
    }

    # Convert scalar value to an array
    if ($Config->is_scalar($name)) {
        return ($Config->value($name));
    }

    return $Config->array($name);
}

##
#
# Retrieve a scalar value of a key from a given config. This function will
# validate config while retrieving a value and will log an error message if
# an unexpected value (list or hash) is encountered.
#
# @param obj(Config::General) Configuration object to be examined
#
# @param string A name of the config key to be retrieved
#
# @return string
#
sub getConfigValue(\$$) {
    my ($Config, $name) = @_;

    # Complain if the key does not exists
    if (!$Config->exists($name)) {
        echoLog("ERROR: Invalid config, '$name' key not found", 3);
        return undef;
    }

    # Complain if the key is a section or is not unique
    if (!$Config->is_scalar($name)) {
        echoLog("ERROR: Invalid config, '$name' key is not unique", 3);
        return undef;
    }

    return $Config->value($name);
}

##
#
# This function is used to collect all data submitted by a specified method (GET
# or POST) format it into pretty columns and return to caller.
#
# @param string The name of the method to interrogate (eg: http, get post)
#
# @return string
#
sub getFormattedData($) {
    my ($method) = @_;
    my (@keys, @return);

    # Initialise required variables
    $method = lc($method);
    my @cgi_keys = keys %{getSubmittedData($method, undef, undef, 1)};

    # Perl CGI does not guarantee that parameters will be returned in the same
    # order as they were defined in the form or submitted by the browser.
    # Ignoring the fact that not all browsers submit parameters in the same
    # order, this great hack allows us to lookup parameter order from the
    # original, raw submission string.
    foreach my $raw_pair (split(/;/, $Cgi->query_string())) {
        my ($raw_key, $raw_value) = split('=', $raw_pair, 2);

        # Un-Webify plus signs and %-encoding
        $raw_key =~ tr/+/ /;
        $raw_key =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        # Stop people from using subshells to execute commands
        $raw_key =~ s/~!/ ~!/g;

        # Validate custom key against a list safe cgi keys
        if (grep(/^$raw_key$/, @cgi_keys)) {
            push(@keys, $raw_key);
            @cgi_keys = grep(!/^$raw_key$/, @cgi_keys);
        }
    }

    # Sort unrecognized key alphabetically
    push(@keys, sort(@cgi_keys));

    # Determine the longest POST key then increase it by 3 (':  ')
    my $length = (reverse sort { $a <=> $b } map { length($_) } @keys)[0];
    $length = defined($length) ? $length + 3 : 4;

    # Convert all found keys into a pretty message
    foreach my $key (@keys) {
        # Ignore excluded submit keys
        next if (($method eq 'post')
            and (grep {$_ eq $key} @{$config->{'exclude_keys'}}));

        # Initialise nicely formatted user values
        my $label = sprintf("%-${length}s", "$key:  ");
        my $indent = ' ' x $length;

        # Only report submitted values
        my $value = $Config->value(normaliseKey($key, "${method}_"));
        next if (!$value);
        $value =~ s/\n/\n$indent/mg;

        push(@return, $label.$value);
    }

    return join("\n\n", @return);
}

##
#
# By default this will collect all "key => value" pairs submitted as part of
# the request, converting all keys to lower case and substituting all spaces
# for underscores. If an option second parameter is supplied (key) then only
# that key's value will be converted and returned.
#
# @param string The name of the method to interrogate (eg: http, get post)
#
# @param string Optional key of the method request which is to be retrieved.
#
# @param string Optional prefix to be prepended to all returned key names.
#
# @param bool Optional flag, indicating if key names are to be returned raw
# (as entered by the user in the submitted form) or reformatted to lower case
# with no spaces. By default, all keys are returned reformatted.
#
# @return mixed
#
sub getSubmittedData($;$$$) {
    my ($name, $key, $prefix, $raw) = @_;
    my $return = {};

    # Normalise method name
    $name = lc($name);

    # Configure method data retrieval tools
    my $sub = $config->{'cgi_fetch'}->{$name};

    # Return a single key value if it was requested
    if ($key) {
        $return = $Cgi->$sub($key);
        utf8::decode($return);
        return $return;
    }

    # Return an empty list if no submitted values detected
    #return $return if (!$Cgi->$sub());
    if (!$Cgi->$sub()) {
    }

    # Collect all submitted method parameters
    foreach my $key ($Cgi->$sub()) {
        # Proceed to next key if entry is empty
        next if (! $key);

        # Decode incoming value into UTF-8
        my $value = $Cgi->$sub($key);

        utf8::decode($key);
        utf8::decode($value);

        # Only reformat the key if it hasn't been requested as 'raw'
        $key = normaliseKey($key, $prefix, $raw);

        # Assign key => value pair
        $return->{$key} = $value;
    }

    return $return;
}

##
#
# Given a name of the key and a set of controlling conditions this function
# will convert that key name in a standardised and predictable way.
#
# @param string A name of the element submitted as part of the form and in the
# format it is returned by the CGI param(), urlparam() or other similar func.
#
# @param string Optional prefix to be prepended to all returned key names.
#
# @param bool Optional flag, indicating if the key name is to be returned raw
# (as entered by the user in the submitted form) or reformatted to lower case
# with no spaces. By default, all keys are returned reformatted.
#
# @return string
#
sub normaliseKey ($;$$) {
    my ($key, $prefix, $raw) = @_;

    # Make sure hat prefix is always defined
    $prefix = '' if (! defined($prefix));

    # Prepends option key prefix
    $key = $prefix.$key if ($prefix);

    # do nothing else if raw key was requested
    return $key if ($raw);

    # Make sure that keys do not contain spaces
    # and are limited to alphanumeric characters
    $key =~ s/\s/_/g;
    $key =~ s/\W//g;

    # Convert key name to lower case
    $key = lc($key);

    return $key;
}

##
#
# Display an html page using supplied page title and text. The page is returned
# with requested HTML status code. If status code is omitted or is 0 then 200 is
# used. If status code is 301, 302 or 303 then a redirect to the url defined by
# the first parameter is invoked (it needs to be a url).
#
# @param string Page title or URL for a page redirect
#
# @param int Optional HTML status code of the returned page
#
# @param list Optional text to be displayed on the page
#
# @return bool
#
sub echoPage($;$$) {
    my ($page, $status, $text) = @_;

    # Default to OK if status is missing
    $status = 200 if (!$status);

    # Redirect if status is 301, 302 or 303
    # (anything other will probably break redirection)
    if (($status eq 301) or ($status eq 302) or ($status eq 303)) {
        print $Cgi->redirect(-uri => "${page}", -status => $status);
        #exit;
        return 1;
    }

    # Start UTF8 encoded html page
    binmode STDOUT, ':utf8';
    print $Cgi->header(
        -status  => $status,
        -charset => 'utf-8');

    # Start UTF8 encoded html page
    print $Cgi->start_html($page);
    print $Cgi->h1($page);

    # Add each element as a new paragraph
    for my $par (@{$text}) {
        print $Cgi->p($par);
    }

    # # Close html body of the output page
    print $Cgi->end_html();

    # Mark output layer as UTF8
    return 1;
}

##
#
# Print a message to the log file. This function accounts for the current log
# file settings thus a message is only stored if 'debug' is enabled, otherwise
# it just disappears.
#
# @param string Message to stored in the log file
#
# @param mixed Optional. If an integer is given than it is used as an indicator
# of the level of indent for the logged message. Otherwise, this value is
# converted to a string and prepended to the log message (eg: '--DEBUG-->')
#
# @return 1
#
sub echoLog($;$) {
    my ($message, $indent) = @_;

    # Re-configure indent if not an integer
    $indent = 0 if (!$indent);
    $indent = $config->{'log_indent'} x $indent if ($indent =~ m/^\d+$/);

    # Re-format message according to indent
    $message = print(LOG $indent.$message."\n");

    return 1;
}

##
#
# This sub is part of a backwards compatibility layer (BCL). It is used to trap
# for user submitted form controls, ie: returnLocation, returnText, returnURL.
# If detected, this controls will be used to override default configurations.
#
# @param string Return message or redirect URL
#
# @return string
#
sub bclUserReply ($) {
    my ($reply) = @_;

    # Initialise user submitted value
    my $location = $Config->value('post_returnlocation');

    # Validate user submitted redirect
    if ($location) {
        return $location if ($location =~ m/$config->{'url_regexp'}/);

        echoLog('Redirect Refused: invalid URL posted in returnLocation');
        return $reply;
    }

    # Initialise user submitted values
    my $text = $Config->value('post_returntext');
    my $link = $Config->value('post_returnurl');

    # Override return text with the one submitted by the user
    $reply = $text if ($text);

    # Validate user submitted return-link
    if ($link) {
        return "${reply}\n\nReturn to <a href=\"${link}\">${link}</a>"
            if ($link =~ m/$config->{'url_regexp'}/);

        echoLog('Return-link Refused: invalid URL posted in returnURL');
    }

    return $reply;
}

exit (main() ? 0 : 1);

__DATA__

##
#
# Default configuration file
#
# This file consists out of two required sections: <Mail> and <Form>: one
# defines all information required to format and send an email; the other
# section contains instructions on how to validate the form.
#

# Defines an absolute path to the log file that stores all debug information
# about each invocation of the script that is based on this config file.
# Debugging can be disabled by omitting 'debug' or setting it to 0/no/off.
#debug = /absolute/path/to/debug.log

<Mail>
    # The following section contains a list of mail headers that will be set
    # on the outgoing mail. Any header set here will override script expected
    # behaviour, ie: use this to force custom From, Cc, Bcc, etc headers.
    #
    # The following headers can be defined in this section:
    #
    # Approved     Content-*     Keywords        References     Organization
    # Bcc          Date          Message-ID      Reply-To       Sender
    # Cc           Encrypted     MIME-Version    Resent-*       Subject
    # Comments     From          Received        Return-Path    To
    #
    # Plus, any X-* headers you wish to set. Also note that to specify a header
    # that's not in the above list, just give it with a trailing ":", eg:
    #
    #   My-field: My Value
    #
    <Headers>
        From      no-reply@localhost
        To        ${path_info}@localhost
        Subject   Form2Mail: Unconfigured Mail
    </Headers>

    # Define all files to be included into the outgoing mail. The format of
    # this section is "[Filename] [Content Type]", where a 'Filename' is a
    # the absolute path to a file which is to be included in the mail; and
    # 'Content Type' is its MIME content type, which may also be:
    #
    # "TEXT"    - means "text/plain"
    # "BINARY"  - means "application/octet-stream"
    # "AUTO"    - means attempt to guess from the filename
    #
    #<Attach>
    #    /absolute/path/to/file.jpg
    #</Attach>

    # A body of the mail message to be sent upon successful validation of the
    # form. As a special feature, you can have any amount of white spaces in
    # front of the end identifier (EOS), exactly that amount of spaces will be
    # removed from the beginning of every line inside the message.
    message <<EOS
        Hmmmm ... Hope you know what you are doing 'cause it really
        looks like you haven't configured this mail drop.

        The following configuration options are currently in use:
          Path info:    ${path_info}
          Config file:  ${config}
          Debug log:    ${debug}

        Data submission received from:
        $http_referer

        The following data was submitted:

        $data_submitted

        --
        Sent automatically by Form2Mail script.
        Please do not reply to this message.
        EOS
</Mail>

<Form>
    # Defines a title of the page to be displayed upon successful form
    # submission. If submission fails the one of the $config-{'e_...'}
    # error titles will be used instead of this.
    title Form2mail

    # A text of the first paragraph of the page shown to the user upon a
    # successful submission or an absolute URL to be used as redirect.
    success <<EOS
        Everything worked ok ...
        but a bear, however hard he tries, grows tubby without exercise.
        EOS

    # A text of the first paragraph of the page shown to the user upon a
    # failed submission or an absolute URL to be used as redirect.
    failure <<EOS
        Something gone wrong ...
        because I am a Bear of Very Little Brain, and long words bother me.
        EOS

    # Validate rules for a parameter submitted using GET
    # <Get [name]>
    #   # Indicates if the current input value is required (true, yes, on, 1)
    #   # or optional (false, no, off, 0). If submitted value matches one of
    #   # the 'ignore' values then submitted value will be considered blank.
    #   require = no
    #
    #   # Perl regular expression(s) that needs to match currently submitted
    #   # value.  Note that you can supply multiple variants of this option.
    #   # Value will be matched against all regexp, in the supplied order.
    #   regexp = ^.*$
    #
    #    # Possible values of the current submission that are to be treated as
    #    # if nothing was submitted at all. You can supply multiple variants of
    #    # this option and submitted value will be matched against them all.
    #    ignore = Example
    #    ignore = Test
    #
    #    # An error message displayed to the user in case a value submitted for
    #    # this element does not match regexp, or the element is required but
    #    # its submitted value is empty or matches one of the 'ignore'.
    #    invalid = You need to supply a valid value
    # </Get>

    # Validate rules for a parameter submitted using POST
    <Post returnLocation>
        # Indicates if the current input value is required (true, yes, on, 1)
        # or optional (false, no, off, 0). If submitted value matches one of
        # the 'ignore' values then submitted value will be considered blank.
        require = no

        # Perl regular expression(s) that needs to match currently submitted
        # value.  Note that you can supply multiple variants of this option.
        # Value will be matched against all regexp, in the supplied order.
        regexp = ^(http|https|ftp)://[^/]+(/[^\s]*)?$

        # A possible values of the current submission that are to be treated as
        # if nothing was submitted at all. You can supply multiple variants of
        # this option and the submitted value will be matched against them all.
        ignore = http://www.example.com
        ignore = http://www.example.org
        ignore = http://www.example.net

        # An error message displayed to the user in case a value submitted for
        # this element does not match regexp, or the element is required but
        # its submitted value is empty or matches one of the 'ignore'.
        invalid = Misconfigured form: returnLocation is not an absolute URL
    </Post>

    # Validate rules for a parameter submitted using POST
    <Post returnURL>
        # Indicates if the current input value is required (true, yes, on, 1)
        # or optional (false, no, off, 0). If submitted value matches one of
        # the 'ignore' values then submitted value will be considered blank.
        require = no

        # Perl regular expression(s) that needs to match currently submitted
        # value.  Note that you can supply multiple variants of this option.
        # Value will be matched against all regexp, in the supplied order.
        regexp = ^(http|https|ftp)://[^/]+(/[^\s]*)?$

        # A possible values of the current submission that are to be treated as
        # if nothing was submitted at all. You can supply multiple variants of
        # this option and the submitted value will be matched against them all.
        ignore = http://www.example.com
        ignore = http://www.example.org
        ignore = http://www.example.net

        # An error message displayed to the user in case a value submitted for
        # this element does not match regexp, or the element is required but
        # its submitted value is empty or matches one of the 'ignore'.
        invalid = Misconfigured form: returnURL is not an absolute URL
    </Post>

    # Validate rules for a parameter submitted using POST
    # <Post email>
    #     # Indicates if the current input value is required (true, yes, on, 1)
    #     # or optional (false, no, off, 0). If submitted value matches one of
    #     # the 'ignore' values then submitted value will be considered blank.
    #     require = yes
    #
    #     # Perl regular expression(s) that needs to match currently submitted
    #     # value.  Note that you can supply multiple variants of this option.
    #     # Value will be matched against all regexp, in the supplied order.
    #     regexp = ^[^@]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+$
    #
    #     # Possible values of the current submission that are to be treated as
    #     # if nothing was submitted. You can supply multiple variants of this
    #     # option and the submitted value will be matched against them all.
    #     ignore = example@example.com
    #     ignore = example@example.org
    #     ignore = example@example.net
    #
    #     # An error message displayed to the user in case a value submitted for
    #     # this element does not match regexp, or the element is required but
    #     # its submitted value is empty or matches one of the 'ignore'.
    #     invalid = You need to supply a valid 'From' email address
    #
    #     # Modifie supplied value before executing all configured tests
    #     rewrite_before_config <<EOS
    #         return ($value ? $value : 'example@example.com');
    #         EOS
    #
    #     # Modifie supplied value after it passed all configured tests
    #     rewrite_after_config <<EOS
    #         return lc($value);
    #         EOS
    # </Post>
</Form>

__END__

=pod

=head1 NAME

form2mail - CGI script that sends an email triggered by a form submission.

=head1 DESCRIPTION

This script is designed to receive data submitted by a form, validates that
data against a set of configured rules, and sends out a pre-formatted email
message upon successful validation of the data.

All strings processed by the script are converted to UTF-8 thus any special
characters submitted with the form should be accepted and preserved. All
validation rules, as well as response messages and mail is configured through
the config file (See $config{'rc_path'} and $config{'rc_file'} definitions at
the top of this file).

=head1 CONFIG VARIABLES

You can use variables inside your config files if you like. Variables defined
at the top level are also available within sub-blocks & can be overridden with
a local, block specific value. In order to avoid endless loops and minimise
potential security risks, no variables are available within <Post *> and <Get
*> sub-blocks of the <Form> block.

The following top level variables are predefined by the script:

=over

=item $path_info

This variable stores additional path information. In other words, it is based
on the script's URI and contains a section of the URI starting from the end of
the script's URL and finishing at the beginning of the GET parameter list. (Eg:
/path/to/script/additional/info?test=1 -> additional/info)

=item $start_time

Contains a human readable string that allows us to see when current process
was initialised. The string is in the following format: DD/MM/YYYY HH:MM:SS.

=item $remote_sys | $remote_addr | $remote_host

Identifies remote host that invoked current process, where $remote_sys a string
id of the remote host formatted for human consumption, and $remote_addr and
$remote_host are the IP address and the host name of the remote server (if the
host name could not be resolved then $remote_host contains remote IP address).

=item $server_protocol

Identifies protocol used to invoke current instance of the script based on the
$ENV{'SERVER_PROTOCOL'} value.

=item $config

Contains an absolute path to the custom configuration file used or the value of
$config{'rc_file'} if default config is in use.

=item $debug

Contains an absolute path to the log file that stores all of the debugging
information for the forms validated against that particular config file. If
debugging is disabled then this variables value will be empty or 0 (depends on
whether variable is omitted from the config file or set to 0/no/off).

=item $http_* | $https_*

One of this variable collections will be set depending on the protocol used to
access this script. This collection provides access to all protocol specific
environment variables, including HTTP_USER_AGENT, HTTP_ACCEPT_LANGUAGE, and
HTTP_ACCEPT_CHARSET, corresponding to the like-named HTTP request headers.

=item $get_*

This variable collection provides access to all "key => value" pairs submitted
as part of the user's GET request by storing submitted values as $get_[key],
where key is the submitted value of the html name parameter converted to lower
case with all spaces substituted for underscores.

=item $post_*

This variable collection provides access to all "key => value" pairs submitted
as part of the user's POST request by storing submitted values as $post_[key],
where key is the submitted value of the html name parameter converted to lower
case with all spaces substituted for underscores.

=item $data_all | $data_*

This variable stores user data submitted to the script and processed by any /
all rewrite hooks. Furthermore, the data is formatted to be easily understood
by a human. If you require data submitted by a specific method (get or post) it
can be retrieved by using $data_[method] variables (eg: $data_post).

=back

=head1 REWRITE HOOKS

It is possible to define a "value rewrite hook" for every key-value pair
submitted by the user. Such hooks are defined inside a named block that
identifies submitted key-value pair (eg: inside <post username> block) and
are evaluated as PERL code.

Hook's code is run inside the script's scope and has access to all "our"
variables and all top level variables available to the config (see CONFIG
VARIABLES). One additional variable is defined for each hook: $value. This
variable contains current key's value.

The following hooks are available:

=over

=item rewrite_before_config

Modifies submitted value before applying configured checks.

=item rewrite_after_config

Modifies submitted value after applying configured checks and only if the
value has successfully passed all of the checks.

=back

Each hook overwrites current value of the key with its own return value. Thus,
each hook must return a valid (or at the very least, sane) value.

Should the code configured inside a hook fail its evaluation, an error will be
logged to the log file and unmodified value will be returned. No error will be
reported through the browser interface, ie: the user who submitted the original
form will not be notified.

=head1 FORM VARIABLES

The following variables have a special meaning if submitted as part of the
form. Please note that this functionality is provided for backwards
compatibility and should probably be avoided as it hands over partial control
of the form submission mechanism to the user and thus may cause a headache and
become a potential security risk.

=over

=item returnText

If submitted as part of the POST request this variable indicates the text to be
displayed to the user upon the successful execution of the script.

=item returnURL

If submitted as part of the POST request than this variable indicates a URL
which will be appended to the 'successful submission' text displayed to the
user to provide a link for further user action.

=item returnLocation

If submitted as part of the POST request than this variable indicates a URL to
which this script will redirect upon a successful submission of the script.

=back

=head1 SAMPLE CONFIG

Sample config is stored inside this CGI script and can be retrieved by
executing the following script at the UNIX command prompt (Note: we are
assuming that we are in the same directory as the script):

    perl -e 'my $e = 0; while (<STDIN>) {
        $e = 0 if (/^\s*__END__\s*$/);
        print if $e;
        $e = 1 if (/^\s*__DATA__\s*$/);
        }' < ./form2mail.pl

=head1 KNOWN BUGS

If a nameless parameter submitted to the script using a GET request then both
the parameter itself and its value become inaccessible with in the config file.

In order to achieve case-insensitive parsing of the submitted parameters all
parameter names in the config file should be in lower case. This rule holds
true irrespective of the case of the submitted parameter.

=head1 AUTHOR

Dmytro Konstantinov <umka.dk@icloud.com>

=cut
