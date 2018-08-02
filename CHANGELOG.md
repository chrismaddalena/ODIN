# Change Log
## August 1, 2018, 1.9.1
* Fixed Neo4j graph database not being if the --nuke flag was not used.
* Fixed bug with email address hunting that could cause only a portion of the discovered email addresses to be recorded in the database.
* Improved the recording of Have I Been Pwned results in the database.
* Added some status updates for Have I Been Pwned as this process can take a while if a lot of addresses are discovered.

## July 31, 2018, 1.9.1
* Improved boto3 / AWS error handling for unusual edge cases where the bucket is unreachable due to AWS region or other issue.
* Incorporated the Neo4j grapher into the CLI options so the database can be generated automatically at the end of a run.
* Fixed the HTML reporter's SQL queries after making changes to the tables for Neo4j updates.
* Switched back to the Censys Python package after testing and further improved data collection for certificates.
* Updated requirements in the Pipfile.

## July 26, 2018, 1.9.0
This brings ODIN closer to its v2.0 release:
* ODIN now has a helper script, grapher.py, that will take your complete ODIN SQLite3 database and convert it to a Neo4j graph database with relationships!
* Certificates are better than ever! ODIN will now use the returned ID from Censys to look-up all of the additional details about the certificate, like alternative names. Even more subdomains and fun to be had with certificates! Additionally, certificates ar enow paired properly with the subdomains to which they are attached, not the root *.whatever.tld domain.
* The DNSDumpster output has been cleaned-up to remove some weird artifacts (e.g. HTTP: added to the end of some subdomains during scraping).

## July 7, 2018, 1.8.6
* Company Info table now supports a target organization having multiple profiles on one social media platform.
* Chromium now operates in headless mode, so no more Chrome windows covering your screen.
* Scope generation and parsing is no longer tripped up by domain names with hyphens in them.
* Some minor text chanes for typos and small clarifications.
* [BETA] Improved the screenshots functionality to add both HTTP and HTTPS to hostnames for screenshots.

## May 25, 2018, 1.8.5
* Fixed a few bugs in the HTML report and made it much, much prettier.
* The reports directory has been organized! Now a reports/<organization_name>/ directory will be made. Under that, separate file_downloads, screenshots, and html_report directories are created for these items.
* Fixed a few misc bugs reported by users.
* [BETA] A new `--screenshots` flag has been added. If used, ODIN will take screenshots of the web services on hosts. For now this is limited to adding "http://" to the front of the IP address, domain, or subdomain and giving it a shot.
* [BETA] Added a screenshots.html report page to the HTML report. This page serves as a gallery for web screenshots.

## May 24, 2018, 1.8.5
This is another large update with an all new arbitrary version number, v1.8.5! Many, many improvements and changes have been implemented to make ODIN better but also to pave the way for some plans coming for version 2.0 :D

Here we go:

* Fixed an issue with the Have I Been Pwned API failing to return results due to changes in API endpoints.
* Redesigned SQLite3 database to be more in-line with design standards -- naming conventions, keys, and so forth.
* Reworked multiprocess implementation to share variables between processes. This was to allow for the next several changes...
* Reverse DNS is performed against all subdomains and IP addresses are added to the new hosts tables (formerly the report scope table).
* IP addresses from DNS records and other sources are now added to the hosts table as well.
* The hosts table now as a "source" column to note where the IP or domain was found if it wasn't in your scope file.
    * There is also a column with True/False values that makes it easy to run a query and see the IPs and domains found that were not in the provided scope file.
* Speaking of the scope file, it's no longer required. Feel free to not include it if you would rather just provide a name and a single domain name to get started.
* Updated Full Contact API queries to v3, up from v2.
* Shodan queries are now run against all IP addresses and domains discovered during the initial discovery phase instead of just those found in the provided scope file.
* Tables have been cleaned up, made leaner, and can now be connected using keys. This will allow for link tables to create relationships between an IP address in the hosts table and DNS records or subdomains in other tables.
* Link tables now exist to connect relationships between different information.
* A new `--html` option now exists to generate an HTML report from the database upon completion.
* Also fixed a dozen little things like typos, little periods hanging out at the ends of domain names, and other stuff!

## May 13, 2018
* Full SSL/TLS certificates from Censys are now stored in their own table by default (not only verbose mode).
* Subdomains pulled from Censys certificate data is now added to the Subdomains table.
* Subdomains in the DB should now be unique and the table now includes a "Sources" column.
* Fixed an issue tha could cause Censys query credits to be gobbled up if your target has a lot of certificates.
* Cymon API searches now use Cymon API v2.
* Added a progress bar for AWS S3 Bucket and Digital Ocean Spaces hunting.
    * Known Issue: This causes messy terminal output, but better than nothing for when large wordlists are used.
* URLVoid is now used for URLCrazy typosqautted domains, like the Cymon API.
* URLVoid is no longer has its own table and there will be no ore searches for domains in scope because, really, that just didn't make sense. URLVoid is for malware/malicious domains, not domains that are in scope for testing.
* Added a check to make sure boto3 and AWS credentials are setup prior to attempting S3 bucket hunting using awscli.

## March 6, 2018
* Added support for detecting oportunities for DNS cache snooping.
* Added a new option to provide a wordlist of terms to be used as prefixes and suffixes for S3 bucket hunting.
* Added Pipfile to replace requirements.txt and avoid conflicts with Python 2.x installs.
* Finally updated the URLCrazy module for the SQLite3 database change.

## January 3, 2018 v1.7.0
* Converted the old XLSX reports to a SQLite3 database solution!
* Implemented multiprocessing (!) to greatly improve efficiency and shorten runtime!
* Various other little bug fixes and tweaks.