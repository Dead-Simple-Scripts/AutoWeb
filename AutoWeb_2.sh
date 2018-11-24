#! /bin/bash
echo ""
echo "********************************"
echo "*           AutoWeb            *"
echo "*    Automated Weblog Triage   *"
echo "*          Version 2           *"
echo "*                              *"
echo "*           by Michael Leclair *"
echo "********************************"
echo ""
echo "Script to autorun weblog triage searches"
echo ""
echo "Runs commonly used grep & regex commands for incident response fast triage methodologies"
echo "Automatic post-processing on some results is built in to faciliate frequency analysis"
echo ""
echo ""
echo "Usage: ./autoweb.sh <weblog directory> "
echo ""
echo "Example: ./autoweb.sh logs/ "
echo ""
echo""
read -p "Press [Enter] key to start AutoWeb"
clear
echo""
# Start of AutoWeb script
echo "****************************"
echo "*  AutoWeb script started  *"
echo "****************************"
echo ""
exec 2>/dev/null
mkdir autoweb_results
results=autoweb_results
#
echo  "Custom IOC search started"
grep -E -r -i -f iocs.txt -r $1 > $results/custom_ioc_search.txt
echo ">>> Custom IOC search completed"
echo ""
echo  "IP frequency searches started"
grep -E -r -o "([0-9]{1,3}\.){3}[0-9]{1,3}" $1 | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -n > $results/ip_search.txt
# IP only lists for open source intelligence searches
grep -E -r -o "([0-9]{1,3}\.){3}[0-9]{1,3}" $1 | sort | uniq | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > $results/ips_for_osint_check_all.txt
grep -E -r -o "([0-9]{1,3}\.){3}[0-9]{1,3}" $1 | sort | uniq | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" | grep -E -o -v "(^127\.0\.0\.1)|(^192\.168)|(^10\.)|(^172\.1[6-9])|(^172\.2[0-9])|(^172\.3[0-1])" > $results/ips_for_osint_check_external_only.txt
echo ">>> IP frequency searches completed"
echo ""
echo  "HTTP request method search started"
grep -r -E -i -o "(get|post|connect|put|patch|delete|head|options|trace)" $1 | grep -E -i -o "(get|post|connect|put|patch|delete|head|options|trace)" | sort | uniq -c | sort -n > $results/http_methods.txt
echo ">>> HTTP request method search completed"
echo ""
echo "SQLi attack pattern searches started"
# basic keyword search
grep -r -E -i "(select|union|1=1|join|inner)" $1 > $results/sqli_search_basic.txt
# MS SQL Server Pivoting off of exec sp or xp
grep -r -E -i "/exec(\s|\+)+(s|x)p\w+/ix" $1 > $results/sqli_search_mssql.txt
# better keyword search using single quote or hex equivalent followed by keywords
grep -r -E -i "/((\%27)|(\'))(union|select|inner|join|drop|update|insert)/ix" $1 > $results/sqli_search_keyword.txt
# Search pivoting off of keyword "or" preceded by a single quote for its hex equivalent
grep -r -E -i "/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix" $1 > $results/sqli_search_typical.txt
# Search pivoting off of a single quote,doible dash or hash symbol or their hex equivalents
grep -r -E -i "/(\%27)|(\')|(\-\-)|(\%23)|(#)/ix" $1 > $results/sqli_search_metachar_1.txt
# Search pivoting off of an equal sign, single quote, double dash or semicolon or there hexa Quillivant
grep -r -E -i "/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i" $1 > $results/sqli_search_metachar_2.txt
echo ">>> SQLi attack pattern searches completed"
echo ""
echo "Web shell attack pattern searches started"
grep -E -i -r "\.(jsp|asp|aspx|js|php|cfm)" $1 | grep -E -i -o "(\/|\\\)[a-z0-9 -_]{1,15}\.(jsp|asp|aspx|js|php|cfm)" | sort | uniq -c | sort -n > $results/webshell_search_1.txt
grep -E -i -r "\.(jsp|asp|aspx|js|php|cfm)" $1 | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -n > $results/webshell_search_ip_freq.txt
grep -E -i -r "(jspspy|%eval)" $1 > $results/webshell_search_2.txt
# The following searches are repeat of the above three searches but only focused on records with "post" requests
grep -E -i -r post $1 | grep -E -i "\.(jsp|asp|aspx|js|php|cfm)" | grep -E -i -o "(\/|\\\)[a-z0-9 -_]{1,15}\.(jsp|asp|aspx|js|php|cfm)" | sort | uniq -c | sort -n > $results/webshell_search_1_postonly.txt
grep -E -i -r post $1 | grep -E -i "\.(jsp|asp|aspx|js|php|cfm)" | grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -n > $results/webshell_search_ip_freq_postonly.txt
grep -E -i -r post $1 | grep -E -i "(jspspy|%eval)" > $results/webshell_search_2_postonly.txt
echo ">>> Web shell attack pattern searches completed"
echo ""
echo "XSS attack pattern searches started"
# Simple search
grep -E -r -i "<script>" $1 > $results/xss_search_widenet.txt
# Search pivoting off of opening and closing bracket or their hex equivalents
grep -E -r -i "/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix" $1 > $results/xss_search_simple.txt
# Search Pivoting off of "<img src"
grep -E -r -i "/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/I" $1 > $results/xss_search_imgsrc.txt
# More encompassing search pivoting off of opening and closing bracket or their hex equivalents
grep -E -r -i "/((\%3C)|<)[^\n]+((\%3E)|>)/I" $1 > $results/xss_search_paranoid.txt
echo ">>> XSS attack pattern searches completed"
echo ""
echo "base64 attack pattern search started"
grep -E -i -r "[a-z0-9+/]+={1,2}" $1 > $results/base64_search.txt
echo ">>> base64 attack pattern search completed"
echo ""
echo "Directory Traversal attack pattern search started"
grep -E -r "(\/\.\/|\/\.\.\/)" $1 > $results/directory_traversal_search.txt
echo ">>> Directory Traversal attack pattern search completed"
echo ""
echo "Encoding attack pattern search started"
grep -E -i -r "(%[a-f0-9]{2}%)" $1 > $results/encoding_search.txt
echo ">>> Encoding attack pattern search completed"
echo ""
echo "Long URL attack pattern search started"
grep -E -i -o -r "(\/|\.)([a-z0-9-]{30,75})(\/|\.)" $1 | grep -E -i -o "(\/|\.)([a-z0-9-]{30,75})(\/|\.)" | sort | uniq -c | sort -n > $results/long_url_search.txt
echo ">>> Long URL attack pattern search completed"
echo ""
echo "Archiving results"
zip -r autoweb_results.zip $results
echo ">>>>> AutoWeb Searches completed <<<<<"
