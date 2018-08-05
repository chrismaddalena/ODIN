# Neo4j Graph Database Schema

The grapher.py library can be run independently or as part of ODIN when using the `--graph` flag. It takes the provided SQLite3 database and creates a Neo4j graph database. That database contains these nodes and relationhips:

## Nodes

### Organization
Each organization name ODIN learns about is recorded. This is typically pulled form whois records for domains related to the target organization. Organization nodes have these labels:

* Name: The organization's name.

* Website: The organization's website(s) pulled from Full Contact.

* WebsiteOverview: A brief description of the organization based on their website and pulled from Full Contact.

* Employees: The number of employees pulled from Full Contact.

* YearFounded: The year the organization was founded, pulled from Full Contact.

### IP
These are IP addresses ODIN has learned about and contain these labels:

* Address: The IP address.

* Scoped: A True/False value indicating if the address was in the user-provided scope file.

* Source: Where ODIN learned about this address.

* RDAPSource: The source of the RDAP information, which will always be ARIN.

* Organization: The organization that owns the IP address.

* CIDR: The CIDR that contains the IP address.

* ASN: The AS number for the IP address.

* CountryCode: The country to which the IP address is attached.

* RelatedDomains: Domains known to be attached to the IP address, accordinf to Robtex.

### Domain
These are domain names ODIN has learned about and contain these labels:

* Name: The domain name.

* Scoped: A True/False value indicating if the address was in the user-provided scope file.

* Source: Where ODIN learned about this address.

* NameServers: Name servers collected from the domain's DNS records.

* Address: The address, if one exists, for the registrant in the domain's whois record.

* MXRecords: MX record collected from the domain's DNS records.

* TXTRecords: TXT record(s) collected from the domain's DNS records.

* SOARecords: SOA records collected from the domain's DNS records.

* DMARC: DMARC record pulled for the domain.

* Registrar: The registrar listed in the domain's whois record.

* Expiration: The expiration date listed in the domain's whois record.

* Organization: The organization listed in the domain's whois record.

* Registrant: The registrant listed in the domain's whois record.

* Admin: The Admin contact listed in the domain's whois record.

* Tech: The Technical contact listed in the domain's whois record.

* ContactAddress: The registrant's contact information listed in the domain's whois record.

* DNSSEC: The domain's DNSSEC status listed in the domain's whois record.

### Subdomain
These are subdomains ODIN has found and contain these labels:

Name: The subdomain name.

Address: The IP address of the subdomain. This is listed as "Lookup Failed" if the subdomain could not be resolved.

DomainFrontable: If this domain might be use dfor domain fronting this label will contain the CDN information.

### Certificate
These are certificates ODIN collected from Censys.io and have these labels:

* Subject: The certificate's subject.

* Issuer: The certificate's issuer.

* StartDate: The certificate's start date.

* ExpirationDate: The certificate's expiry date.

* SelfSigned: A True/False value indicating if the certificate is self-signed or not.

* SignatureAlgo: The certificate's signature algorithm.

* CensysFingerprint: Censys' hash assigned to the certificate that can be used to look-up this particular signature on censys.io.

### Port
These are ports reported as open by Shodan and have these labels:

* Number: The port number reported as open.

* OS: The operating system, if the information is available.

* Organization: The organization attache dhte IP address and therefore the port.

* Hostname: The hostname of the IP address, if the information is available.

## Relationships
The above nodes share these relationships:

* :OWNS
    * Organization nodes -[:OWNS]-> Domain nodes

* :SUBDOMAIN_OF
    * Subdomains are -[:SUBDOMAIN_OF]-> Domain nodes

* :HAS_PORT
    * IP nodes -[:HAS_PORT]-> Port nodes

* :RESOLVES_TO
    * Domain nodes -{:RESOLVES_TO]-> IP nodes}

* :ISSUED_FOR
    * Certificate nodes are -[:ISSUED_FOR]-> Domain or Subdomain nodes

## Example Queries
Here are some example queries showing how this database might be used to visualize the perimter or collect lists of potentially interesting information:

### 1. Return a List of Network Providers
This will return providers like Google, Amazon.com, CloudFlare, etc.

`MATCH (p:Port) RETURN DISTINCT p.Organization`

### 2. Return a List of IP Addresses with Known Open Ports
This will return only IP address that have open ports.

`MATCH (n)-[:HAS_PORT]->(p:Port) RETURN DISTINCT n.Address`

### 3. Return a List of all Unique Subdomains
This returns all unique subdomains found the various domain names.

`MATCH (sub:Subdomain) RETURN DISTINCT sub.Name`

### 4. Map the External Perimeter
This query first matches the Organization, Domain, and IP nodes that have :OWNS and :RESOLVES_TO relationships. It then matches the Subdomains that have :SUBDOMAIN_OF or :RESOLVES_TO relationships with any node. Finally, it matches any Port nodes with a :HAS_PORT relationship with one of the matches IP nodes.

```
MATCH (org:Organization)-[r1:OWNS]->(dom:Domain)-[:RESOLVES_TO]->(add:IP)
MATCH (sub:Subdomain)-[r2:SUBDOMAIN_OF|:RESOLVES_TO]->(n)
MATCH (p:Port)<-[r3:HAS_PORT]-(add)
RETURN org,dom,sub,add,p,n,r1,r2,r3
```