# AutoWeb

Script to autorun weblog triage searches

Weblog triage training available at: https://www.udemy.com/sdf-weblog-forensics/?couponCode=PODCAST 

Runs commonly used grep & regex commands for incident response fast triage methodologies
Automatic post-processing on some results is built in to faciliate frequency analysis

Usage: ./autoweb.sh <weblog directory>

Example: ./autoweb.sh logs/ 

Searches include:
  1. IOC searches (put any custom IOCs in .txt file called iocs.txt, drop in same directory as script)
  2. IP Frequency
  3. HTTP request method frequency
  4. SQLi attack patterns
  5. Webshell attack patterns
  6. XSS attack patterns
  7. Base64 encoding
  8. Directory travsersal
  9. Hex encoding
  10. Long URL
