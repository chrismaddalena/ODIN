#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains the tools required for collecting and parsing DNS records.
"""

import asyncio
import logging
from asyncio import Semaphore
from typing import Union

import click
from dns import asyncresolver
from dns.exception import DNSException, Timeout
from dns.resolver import NXDOMAIN, Answer, NoAnswer

logger = logging.getLogger(__name__)


class DNSCollector(object):
    """
    Retrieve and parse DNS records asynchronously.

    **Parameters**

    ``concurrent_limit``
        Set limit on number of concurrent DNS requests to avoid hitting system limits
    """

    # Configure the DNS resolver to be asynchronous and use specific nameservers
    resolver = asyncresolver.Resolver()
    resolver.lifetime = 1
    resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    def __init__(self, concurrent_limit=100):
        # Limit used for Semaphore to avoid hitting system limits on open requests
        self.concurrent_limit = concurrent_limit
        self.semaphore = Semaphore(value=100)

    async def _query(
        self, domain: str, record_type: str
    ) -> Union[Answer, NXDOMAIN, NoAnswer]:
        """
        Execute a DNS query for the target domain and record type.

        **Parameters**

        ``domain``
            Domain to be used for DNS record collection

        ``record_type``
            DNS record type to collect
        """
        try:
            # Wait to acquire the semaphore to avoid too many concurrent DNS requests
            await self.semaphore.acquire()
            answer = await self.resolver.resolve(domain, record_type)
        except Exception as e:
            answer = e
        # Release semaphore to allow next request
        self.semaphore.release()
        return answer

    async def _parse_answer(self, dns_record: Answer) -> list:
        """
        Parse the provided instance of dns.resolver.Answer.

        **Parameters**

        ``dns_record``
            Instance of dns.resolve.Answer
        """
        record_list = []
        for rdata in dns_record.response.answer:
            for item in rdata.items:
                record_list.append(item.to_text())
        return record_list

    async def fetch_dns_record(self, domain: str, record_type: str) -> dict:
        """
        Fetch a DNS record for the given domain and record type.

        **Parameters**

        ``domain``
            Domain to be used for DNS record collection

        ``record_type``
            DNS record type to collect (A, NS, SOA, TXT, MX, CNAME, DMARC)
        """
        logger.debug("Fetching %s records for %s", record_type, domain)
        # Prepare the results dictionary
        result = {}
        result[domain] = {}
        result[domain]["domain"] = domain

        # Handle DMARC as a special record type
        if record_type.lower() == "dmarc":
            record_type = "A"
            query_type = "dmarc_record"
            query_domain = "_dmarc." + domain
        else:
            query_type = record_type.lower() + "_record"
            query_domain = domain

        # Execute query and await completion
        response = await self._query(domain, record_type)

        # Only parse result if it's an Answer
        if isinstance(response, Answer):
            record = await self._parse_answer(response)
            result[domain][query_type] = record
        else:
            # Return the type of exception (e.g., NXDOMAIN)
            result[domain][query_type] = type(response).__name__
        return result

    async def check_office_365(self, domain: str) -> dict:
        """
        Check if the provided domain is an Office 365 tenant.

        **Parameters**

        ``domain``
            Domain to check for Office 365
        """
        # O365 tenant domains are the domain with all "." converted to a "-"
        tenant_domain = domain.replace(".", "-")

        # Different domains for North America, China, and international customers
        na_o365 = tenant_domain + ".mail.protection.outlook.com"
        china_o365 = tenant_domain + ".mail.protection.partner.outlook.cn"
        international_o365 = tenant_domain + ".mail.protection.outlook.de"

        # Prepare the results dictionary
        tenant_info = {}
        tenant_info[domain] = {}
        tenant_info[domain]["domain"] = domain
        tenant_info[domain]["o365"] = {}
        tenant_info[domain]["o365"]["tenant_uri"] = ""

        # Check if any of the domains resolve -- NXDOMAIN means the domain is not a tenant
        answer = await self._query(na_o365, "A")
        if isinstance(answer, Answer):
            tenant_info[domain]["o365"]["tenant_uri"] = na_o365

        answer = await self._query(china_o365, "A")
        if isinstance(answer, Answer):
            tenant_info[domain]["o365"]["tenant_uri"] = china_o365

        answer = await self._query(international_o365, "A")
        if isinstance(answer, Answer):
            tenant_info[domain]["o365"]["tenant_uri"] = international_o365

        # TODO: Resolve tenant ID from endpoints like:
        # https://login.windows.net/domain.com/.well-known/openid-configuration

        return tenant_info
