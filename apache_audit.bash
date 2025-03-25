#!/bin/bash
#TODO see if any of the checks should also be checking in virtual host config files for directory directives. probably they should

httpd='sudo apachectl' # TODO this should be swapped out for something to detect os or something. on many installations httpd will be correct
# TODO other debian based quirks such as the main config file being called apache2.conf and not httpd.conf should be generalised using the same OS switch

### Colour Formatting Variables ###
red='\033[1;31m'
green='\033[1;32m'
cyan='\033[1;36m'
yellow='\033[1;33m'
nc='\033[0m'

echo -e "This program is only a tool, and makes no guarantees of compliance. It should be used only alongside the relevant CIS controls document (Apache HTTP Server 2.4 BenchmarkV2.1.0). This tool is not a stand-in for manual auditing."

### Environment Variables ###
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_SERVER_ROOT=/etc/apache2
APACHE_WEB_ROOT=/var/www
APACHE_PID_FILE=/var/run/apache2/apache2.pid
APACHE_RUN_DIR=/var/run/apache2
APACHE_LOCK_DIR=/var/lock/apache2
APACHE_LOG_DIR=/var/log/apache2
APACHE_CGI_BIN=/usr/lib/cgi-bin


### Function Definitions ###
function header {
    echo -e "${cyan}$1${nc}"
}

function verify {
    if [ $? == 0 ]; then
        echo -e "${green}VERIFIED${nc}\n"
    else
        echo -e "${red}FAILED${nc}\n"
    fi
}


### Process ###
header "### SECTION 2 - Minimise Apache Modules ###"

header "2.1 - Ensure Only Necessary Authentication and Authorisation Modules are Enabled:"
echo -e "This task must be done manually using the commands \"apachectl -M | egrep 'auth._'\" and \"apachectl -M | egrep 'ldap'\"\n${yellow}UNVERIFIED${nc}\n"

header "2.2 - Ensure the Log Config Module is Enabled:"
$httpd -M | grep 'log_config'
verify

header "2.3 - Ensure the WebDAV Modules are Disabled:"
$httpd -M | (! grep ' dav_[[:print:]]+module') 
verify

header "2.4 - Ensure the Status Module is Disabled:"
$httpd -M | (! egrep 'status_module')
verify

header "2.5 - Ensure the Autoindex Module is Disabled:"
$httpd -M | (! grep autoindex_module)
verify

header "2.6 - Ensure the Proxy Modules are Disabled if Not in Use:"
$httpd -M | (! grep proxy_)
verify

header "2.7 - Ensure the User Directories Module is Disabled:"
$httpd -M | (! grep userdir_)
verify

header "2.8 - Ensure the Info Module is Disabled"
$httpd -M | (! egrep 'info_module')
verify

header "2.9 - Ensure the Basic and Digest Authentication Modules are Disabled"
$httpd -M | (! grep -e "auth_basic_module|auth_digest_module")
verify



header "### SECTION 3 - Principles, Permissions, and Ownership ###"

header "3.1 - Ensure the Apache Web Server Runs as a Non-Root User"
echo -e "I did not automate this process. One should manually verify the values below and ensure that Apache is configured with a non-root user."
grep -i -e '^User' -e '^Group' $APACHE_SERVER_ROOT/apache2.conf
grep -e "APACHE_RUN_USER" -e "APACHE_RUN_GROUP" $APACHE_SERVER_ROOT/envvars
grep '^UID_MIN' /etc/login.defs
id www-data
echo -e "${yellow}UNVERIFIED${nc}\n"

header "3.2 - Ensure the Apache User Account has an Invalid Shell"
grep -e "www\-data.*/sbin/nologin" /etc/passwd
verify

header "3.3 - Ensure the Apache User Account is Locked"
sudo passwd -S "www-data" | grep L
verify

header "3.4 - Ensure Apache Directories and Files are Owned by Root"
find $APACHE_SERVER_ROOT \! -user root -ls | (! grep ".*")
verify

header "3.5 - Ensure the Group is Set Correctly on Apache Directories and Files"
find $APACHE_SERVER_ROOT -path $APACHE_SERVER_ROOT/htdocs -prune -o \! -group root -ls | (! grep ".*")
verify

header "3.6 - Ensure Other Write Access on Apache Directories and Files is Restricted"
find -L $APACHE_SERVER_ROOT \! -type l -perm /o=w -ls | (! grep ".*")
verify

header " 3.6 - Ensure the Core Dump Directory is Secured"
(! grep -R CoreDumpDirectory $APACHE_SERVER_ROOT)
verify

header "3.8 - Ensure the Lock File is Secured"
grep -Rv "#" $APACHE_SERVER_ROOT | (! grep Mutex)
verify

header "3.9 - Ensure the PID File is Secured"
find $APACHE_PID_FILE -user root -group root \! -perm /o=w
verify

header "3.10 - Ensure the ScoreBoard File is Secured"
(! grep -R ScoreBoardFile $APACHE_SERVER_ROOT)
verify

header "3.11 - Ensure Group Write Access for the Apache Directories and Files is Properly Restricted"
find -L $APACHE_SERVER_ROOT/ \! -type l -perm /g=w -ls | (! grep ".*")
verify

header "3.12 - Ensure Group Write Access for the Document Root Directories and Files is Properly Restricted"
find -L $APACHE_WEB_ROOT -group $APACHE_RUN_GROUP -perm /g=w -ls | (! grep ".*")
verify

header "3.13 - Ensure Access to Special Purpose Writable Directories is Properly Restricted"
echo -e "This is a manual task, as the script does not identify special purpose directories such as those for PHP, Java, or other applications sometimes included in Apache webservers.\n${yellow}UNVERIFIED${nc}\n"



header "### SECTION 4 - Apache Access Control ###"

header "4.1 - Ensure Access to OS Root Directory is Denied by Default"
perl -ne 'print if /^<Directory \/>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf | grep -q "Require all denied"  
verify

header "4.2 - Ensure Appropriate Access to Web Content is Allowed"
echo "Manually verify that the below values are correct and make use of the Require method to restrict access"
perl -ne 'print if /^<Directory .*>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf
perl -ne 'print if /^<Location .*>/i .. /<\/Location>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf
grep -v "^#" $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf | grep -i -C 6 -i 'Allow[[:space:]]from' 
echo -e "${yellow}UNVERIFIED${nc}\n"

header "4.3 - Ensure OverRide is Disabled for the OS Root Directory"
perl -ne 'print if /^<Directory \/>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf | grep -v -i "AllowOverrideList" | grep -i "AllowOverride None"
verify

header "4.4 - Ensure OverRide is Disabled for All Directories"
perl -ne 'print if /^<Directory .*>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf | grep -i "AllowOverride None" #TODO modify to work as intended. right now this just checks for at least one occurrence of the option, it needs to check that every directory directive contains the option. use perl probably
verify



header "### Section 5 - Minimise Features, Content, and Options"

header "5.1 - Ensure Options for the OS Root Directory are Restricted"
perl -ne 'print if /^<Directory \/>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf | grep -i "Options None"
verify

header "5.2 - Ensure Options for the Web Root Directory are Restricted"
perl -ne 'print if /^<Directory \/var\/www\/>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/sites-enabled/*.conf | grep -E -i "Options None|Options Multiviews"
verify

header "5.3 - Ensure Options for Other Directories are Minimised"
perl -ne 'print if /^<Directory .*>/i .. /<\/Directory>/i' $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/sites-enabled/*.conf $APACHE_SERVER_ROOT/conf-enabled/*.conf | (! grep -i "Options.*Includes")
verify

#TODO modify this so that it somehow checks that /var/www/html is not available. any remediation must be permanent (i.e. must not be reversed by updating apache). will updating apache replace 000-default.conf?
header "5.4 - Ensure Default HTML Content is Removed"
echo -e "${yellow}Please note that this checks only for the absence of index.html, apache manual configuration, server-status, server-info, and perl-status directives. Other content that may be default in your installed version of the Apache webservice may not be detected like /var/www/html/index.html.${nc}"
grep -Hn -R -i -e "index\.html" -e "manual" -e "server\-status" -e "server\-info" -e "perl\-status" $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/conf-enabled/ $APACHE_SERVER_ROOT/mods-enabled/
echo -e "${yellow}UNVERIFIED${nc}\n"

header "5.5 - Ensure the Default CGI Content printenv Script is Removed"
ls $APACHE_CGI_BIN | (! grep "printenv")
verify

header "5.6 - Ensure the Default CGI Content test-cgi Script is Removed"
ls $APACHE_CGI_BIN | (! grep "test-cgi")
verify

header "5.7 - Ensure HTTP Request Methods are Restricted"
test $(grep -R "</Directory>" $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/*-enabled/ | wc -l) -eq $(grep -R "Require all denied" $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/*-enabled/ | wc -l) #TODO verify this is actually correct
verify

header "5.8 - Ensure the HTTP TRACE Method is Disabled"
grep -R "TraceEnable off" $APACHE_SERVER_ROOT/apache2.conf $APACHE_SERVER_ROOT/*-enabled/
verify

header "5.9 - Ensure Old HTTP Protocol Versions are Disallowed"
test $(grep -F 'RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1\.1$
RewriteRule .* - [F]' $APACHE_SERVER_ROOT/apache2.conf) &&
$(perl -0777 -ne 'print "$&\n" and exit 0 if /<VirtualHost\b[^>]*>(?:(?!<\/VirtualHost>).)*RewriteEngine\s+On(?:(?!<\/VirtualHost>).)*RewriteOptions\s+Inherit(?:(?!<\/VirtualHost>).)*<\/VirtualHost>/s; END { exit 1 }' $APACHE_SERVER_ROOT/sites-enabled/*) #TODO there is probably a more elegant way of doing this, i just don't know what it is. also, is it really meant to say "THE_REQUEST"?
verify

header "5.10 - Ensure Access to .ht* Files is Restricted"
perl -0777 -ne 'exit 1 unless /<FilesMatch\s+"\^\\\.ht">/s; exit 1 if /<FilesMatch\s+"\^\\\.ht">(?:(?!Require\s+all\s+denied).)*<\/FilesMatch>/s' /etc/apache2/apache2.conf
verify

header "5.11 - Ensure Access to .git Files is Restricted"
perl -0777 -ne 'exit 1 unless /<DirectoryMatch\s+"\/\\\.git">/s; exit 1 if /<DirectoryMatch\s+"\/\\\.git">(?:(?!Require\s+all\s+denied).)*<\/DirectoryMatch>/s' $APACHE_SERVER_ROOT/apache2.conf
verify

header "5.12 - Ensure Access to .svn Files is Restricted"
perl -0777 -ne 'exit 1 unless /<DirectoryMatch\s+"\/\\\.svn">/s; exit 1 if /<DirectoryMatch\s+"\/\\\.svn">(?:(?!Require\s+all\s+denied).)*<\/DirectoryMatch>/s' $APACHE_SERVER_ROOT/apache2.conf
verify

header "5.13 - Ensure Access to Files with Inappropriate File Extensions is Restricted"
#TODO

header "5.14 - Ensure IP Address Based Requests are Disallowed"
# grep -F 'RewriteCond %{HTTP_HOST} !^[a-zA-Z0-9\-\.]* [NC]
# RewriteCond %{REQUEST_URI} !^/error [NC]
# RewriteRule ^.(.*) - [L,F]' #TODO verify this is even valid. we need to match valid domain names in the first condition. maybe iterate over a list of provided domains instead?

header "5.15 - Ensure the IP Addresses for Listening for Requests are Specified"
grep -R -e "Listen \d*" foobar | grep -e "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$" | grep -v -e "0\.0\.0\.0" #TODO this only works for ipv4, it needs to also work for ipv6

header "5.16 - Ensure Browser Framing is Restricted"
test $(grep -i "Header always append Content-Security-Policy \"frame-ancestors 'self'\"" $APACHE_SERVER_ROOT/apache2.conf) || $(grep -i "Header always set X-Frame-Options SAMEORIGIN" $APACHE_SERVER_ROOT/apache2.conf)
verify

header "5.17 - Ensure HTTP Header Referrer-Policy is Set Appropriately"
grep 'Header set Referrer-Policy "<Directive>"' /etc/apache2/apache2.conf
verify

header "5.18 - Ensure HTTP Header Permissions-Policy is Set Appropriately"
grep 'Header set Permissions-Policy "<Directive> <allowlist>"' /etc/apache2/apache2.conf
verify

header "### Section 6 - Operations, Logging, Monitoring, and Maintenance"

header "6.1 - Ensure the Error Log Filename and Severity Level are Configured Correctly"
#TODO check that the log level is one of notice, warn, error, crit, alert, or emerg for all modules except core, for which core is also acceptable. debug should not be set for any modules
# correct config should resemble "LogLevel notice core:info" or something similar 
# additionally verify that there is a config resembling "ErrorLog 'logs/error_log'" and possibly analagous ones for the virtual hosts

header "6.2 - Ensure a Syslog Facility is Configured for Error Logging"
#TODO

header "6.3 - Ensure the Server Access Log is Configured Correctly"
#TODO

header "6.4 - Ensure Log Storage and Rotation is Configured Correctly"
#TODO

header "6.5 - Ensure Applicable Patches are Applied"
#TODO

header "6.6 - Ensure ModSecurity is Installed and Enabled"
#TODO

header "6.7 - Ensure the OWASP ModSecurity Core Rule Set is Installed and Enabled"
#TODO

header "### Section 7 - SSL/TLS Configuration"

header "7.1 - Ensure mod_ssl and/or mod_nss is Installed"
#TODO

header "7.2 - Ensure a Valid Trusted Certificate is Installed"
#TODO

header "7.3 - Ensure the Server's Private Key is Protected"
#TODO

header "7.4 - Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled"
#TODO

header "7.5 - Ensure Weak SSL/TLS Ciphers are Disabled"
#TODO

header "7.6 - Ensure Insecure SSL Renegotiation is Not Enabled"
#TODO

header "7.7 - Ensure SSL Compression is not Enabled"
#TODO

header "7.8 - Ensure Medium Strength SSL/TLS Ciphers are Disabled"
#TODO

header "7.9 - Ensure All Web Content is Accessed via HTTPS"
#TODO

header "7.10 - Ensure OCSP Stapling is Enabled"
#TODO

header "7.11 - Ensure HTTP Strict Transport Security is Enabled"
#TODO

header "7.12 - Ensure Only Cipher Suites that Provide Forward Secrecy are Enabled"
#TODO

header "### Section 8 - Information Leakage"

header "8.1 - Ensure ServerTokens is Set to 'Prod' or 'ProductOnly'"
#TODO

header "8.2 - Ensure ServerSignature is Not Enabled"
#TODO

header "8.3 - Ensure All Default Apache Content is Removed"
#TODO

header "8.4 - Ensure ETag Response Header Fields Do Not Include Inodes"
#TODO

header "### Section 9 - Denial of Service Mitigations"

header "9.1 - Ensure the TimeOut is Set to 10 or Less"
#TODO

header "9.2 - Ensure KeepAlive is Enabled"
#TODO

header "9.3 - Ensure MaxKeepAliveRequests is Set to a Value of 100 or Greater"
#TODO

header "9.4 - Ensure KeepAliveTimeout is Set to a Value of 15 or Less"
#TODO

header "9.5 - Ensure the Timeout Limits for Request Headers is Set to 40 or Less"
#TODO

header "9.6 - Ensure Timeout Limits for the Request Body is Set to 20 or Less"
#TODO

header "### Section 10 - Request Limits"

header "10.1 - Ensure the LimitRequestLine Directive is Set to 512 or Less"
#TODO

header "10.2 - Ensure the LimitRequestFields Directive is Set to 100 or Less"
#TODO

header "10.3 - Ensure the LimitRequestFieldsize Directive is Set to 1024 or Less"
#TODO

header "10.4 - Ensure the LimitRequestBody Directive is Set to 102400 or Less"
#TODO

exit
