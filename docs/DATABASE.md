# Database Schema

## Primary Tables
```
CREATE TABLE 'certificates' ('id' INTEGER PRIMARY KEY, 'host' text, 'subject' text, 'issuer' text)
```
```
CREATE TABLE 'cloud' ('name' text, 'bucket_uri' text, 'bucket_arn' text, 'publicly_accessible' text)
```
```
CREATE TABLE 'company_info' ('company_name' text, 'logo' text, 'website' text, 'employees' text, 'year_founded' text, 'website_overview' text, 'corporate_keyword' text, 'email_address' text, 'phone_number' text, 'physical_address' text)
```
```
CREATE TABLE 'dns' ('id' INTEGER PRIMARY KEY, 'domain' text, 'ns_record' text, 'a_record' text, 'mx_record' text, 'txt_record' text, 'soa_record' text, 'dmarc' text, 'vulnerable_cache_snooping' text)
```
```
CREATE TABLE 'email_addresses'  ('email_address' text, 'breaches' text, 'pastes' text)
```
```
CREATE TABLE 'employee_data' ('name' text, 'job_title' text, 'phone_number' text, 'linkedin_url' text)
```
```
CREATE TABLE 'hosts' ('id' INTEGER PRIMARY KEY, 'host_address' text, 'in_scope_file' text, 'source' text)
```
```
CREATE TABLE 'ip_history' ('id' INTEGER PRIMARY KEY, 'domain' text, 'netblock_owner' text, 'ip_address' text)
```
```
CREATE TABLE 'rdap_data' ('id' INTEGER PRIMARY KEY, 'ip_address' text, 'rdap_source' text, 'organization' text, 'network_cidr' text, 'asn' text, 'country_code' text, 'robtex_related_domains' text)
```
```
CREATE TABLE 'shodan_host_lookup' ('id' INTEGER PRIMARY KEY, 'ip_address' text, 'os' text, 'organization' text, 'port' text, 'banner_data' text)
```
```
CREATE TABLE 'shodan_search' ('id' INTEGER PRIMARY KEY, 'domain' text, 'ip_address' text, 'hostname' text, 'os' text, 'port' text, 'banner_data' text)
```
```
CREATE TABLE 'subdomains' ('id' INTEGER PRIMARY KEY,'domain' text, 'subdomain' text, 'ip_address' text, 'domain_frontable' text, 'source' text)
```
```
CREATE TABLE 'twitter' ('handle' text, 'real_name' text, 'follower_count' text, 'location' text, 'description' text)
```
```
CREATE TABLE 'whois_data' ('id' INTEGER PRIMARY KEY, 'domain' text, 'registrar' text, 'expiration' text, 'organization' text, 'registrant' text, 'admin_contact' text, 'tech_contact' text, 'address' text, 'dns_sec' text)"
```

## Link Tables
```
CREATE TABLE 'certificate_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'cert_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(cert_id) REFERENCES certificates(id))
```
```
CREATE TABLE 'dns_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'dns_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(dns_id) REFERENCES dns(id))
```
```
CREATE TABLE 'ip_hist_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'hist_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(hist_id) REFERENCES ip_history(id))
```
```
CREATE TABLE 'rdap_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'rdap_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(rdap_id) REFERENCES rdap_data(id))
```
```
CREATE TABLE 'shodan_host_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'shodan_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(shodan_id) REFERENCES shodan_search(id))
```
```
CREATE TABLE 'shodan_search_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'shodan_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(shodan_id) REFERENCES shodan_host_lookup(id))
```
```
CREATE TABLE 'subdomain_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'subdomain_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(subdomain_id) REFERENCES subdomains(id))
```
```
CREATE TABLE 'whois_link' ('link_id' INTEGER PRIMARY KEY, 'host_id' text, 'whois_id' text, FOREIGN KEY(host_id) REFERENCES hosts(id), FOREIGN KEY(whois_id) REFERENCES whois_data(id))
```