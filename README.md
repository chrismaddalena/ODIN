# ODIN
## Observe, Detect, and Investigate Networks

[![Python Version](https://img.shields.io/badge/Python-3.7-brightgreen.svg)]() [![License](https://img.shields.io/badge/License-BSD3-darkred.svg)]()

![ODIN](https://github.com/chrismaddalena/ODIN/raw/master/ODIN.png)

**Current version: v2.0.0 "Huginn"**

ODIN is Python tool for automating intelligence gathering, asset discovery, and reporting. Remember, check the dev branch for the bleeding edge, and feedback is welcome!

See the GitHub wiki for details and installation and setup instructions.

## What Can ODIN Do?
ODIN aims to automate the basic recon tasks used by red teams to discover and collect data on network assets, including domains, IP addresses, and internet-facing systems. The key feature of ODIN is the data management and reporting. The data is organized in a database and then, optionally, that database can be converted into an HTML report or a Neo4j graph database for visualizing the data.

ODIN performs this in multiple phases:

### Phase 1 - Asset Discovery
* Collect basic organization information from sources like the Full Contact marketing database.
* Check DNS Dumpster, Netcraft, and TLS certificates to discover subdomains for the provided domains.
* Resolve domain and subdomains to IP addresses via socket connections and DNS records.
* Collect information for all IP addresses, such as ownership and organization data, from RDAP, whois, and other data sources.
* Lookup domains and search for IP addresses on Shodan to collect additional data, such as operating systems, service banners, and open ports.
* Check for the possibility of takeovers and domain fronting with the domains and subdomains.

### Phase 2 - Employee Discovery
* Harvest email addresses and employee names for the target organization.
* Link employees to social media profiles via search engines and the Twitter API.
* Cross check discovered email addresses with Troy Hunt's Have I Been Pwned.

### Phase 3 - Cloud and Web Services
* Hunt for Office files and PDFs under the target domain, download them, and extract metadata.
* Search for AWS S3 buckets and Digital Ocean Spaces using keywords related to the organization.
* Take screenshots of discovered web services for a quick, early review of services.

### Phase 4 - Reporting
* Save all data to a SQLite3 database to allow the data to be easily queried.
* Generate an HTML report using default SQL queries to make it simple to peruse the data in a web browser.
* Create a Neo4j graph database that ties all of the discovered entities (IP addresses, domains, subdomains, ports, and certificates) together with relationships (e.g. RESOLVES_TO, HAS_PORT).

At the end of all of this you will have multiple ways to browse and visualize the data. Even a simple Neo4j query like `MATCH (n) RETURN n` (display everything) can create a fascinating graph of the organization's external perimeter and make it simple to see how assets are linked. The [Neo4j wiki pages](https://github.com/chrismaddalena/ODIN/wiki/Graphing-Data) contain better query examples.