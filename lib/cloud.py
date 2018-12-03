#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
This module contains functions for brute forcing bucket names for Amazon Web Services and Digital
Ocean. If a bucket is found, the bucket is checked for public access.
"""

import re

import click
import requests
import validators
import boto3
from botocore.exceptions import ClientError,EndpointConnectionError


class BucketHunter(object):
    """Class for hunting buckets, cloud storage containers, in AWS and Digital Ocean."""
    # Timeout, in seconds, for web requests
    requests_timeout = 10

    def __init__(self):
        """Everything that should be initiated with a new object goes here."""
        # Test connecting to a test S3 bucket with the credentials supplied to `aws configure`
        try:
            self.boto3_client = boto3.client('s3')
            self.boto3_client.head_bucket(Bucket="hostmenow")
        except Exception:
            self.boto3_client = None
            click.secho("[!] Could not create an AWS client with the supplied secrets.",fg="yellow")

    def enumerate_buckets(self,client,domain,wordlist=None,fix_wordlist=None):
        """Search for AWS S3 buckets and Digital Ocean Spaces. Default search terms are the
        client, domain, and domain without its TLD. A wordlist is optional.

        If a wordlist is provided, it may have comments that begin with a #.

        This is based on modules from aws_pwn by Dagrz on GitHub.

        Parameters:
        client          The name of the client organization (for wordlist generation)
        domain          The organization's domain name (for wordlist generation)
        wordlist        An optional user-provided wordlist
        fix_wordlist    An option user-provided list of prefixes and suffixes
        """
        # Take the user input as the initial list of keywords here
        # Both example.com and example are valid bucket names, so domain+tld and domain are tried
        search_terms = [domain,domain.split(".")[0],client.replace(" ","").lower()]
        # Potentially valid and interesting keywords that might be used a prefix or suffix
        fixes = ["apps","downloads","software","deployment","qa","dev","test","vpn",
                 "secret","user","confidential","invoice","config","backup","bak",
                 "backups","xls","csv","ssn","resources","web","testing","uac",
                 "legacy","adhoc","docs","documents","res","nas"]
        bucket_results = []
        # account_results = []
        # Add user-provided wordlist terms to our list of search terms
        if wordlist is not None:
            with open(wordlist,"r") as bucket_list:
                for name in bucket_list:
                    name = name.strip()
                    if name and not name.startswith("#"):
                        search_terms.append(name)
        # Add user-provided list of pre/suffixes to our list of fixes
        if fix_wordlist is not None:
            with open(fix_wordlist,"r") as new_fixes:
                for fix in new_fixes:
                    fix = fix.strip()
                    if fix and not fix.startswith("#"):
                        fixes.append(fix)
        # Modify search terms with some common prefixes and suffixes
        # We use this new list to avoid endlessly looping
        final_search_terms = []
        for fix in fixes:
            for term in search_terms:
                final_search_terms.append(fix + "-" + term)
                final_search_terms.append(term + "-" + fix)
                final_search_terms.append(fix + "." + term)
                final_search_terms.append(term + "." + fix)
                final_search_terms.append(fix + term)
                final_search_terms.append(term + fix)
        # Now include our original list of base terms
        for term in search_terms:
            final_search_terms.append(term)
        # Ensure we have only unique search terms in our list and start hunting
        final_search_terms = list(set(final_search_terms))
        click.secho("[*] There are {} possible bucket names for the hunt.".format(len(final_search_terms)),fg="yellow")
        with click.progressbar(final_search_terms,
                               label="[*] Enumerating Cloud Storage Buckets",
                               length=len(final_search_terms)) as bar:
            # Check for buckets and spaces
            for term in bar:
                if self.boto3_client:
                    result = self.validate_bucket("head",term)
                    bucket_results.append(result)
                result = self.validate_do_space("ams3",term)
                bucket_results.append(result)
                result = self.validate_do_space("nyc3",term)
                bucket_results.append(result)
                result = self.validate_do_space("sgp1",term)
                bucket_results.append(result)
                # Check for accounts
                # result = self.validate_account(term)
                # account_results.append(result)
        return bucket_results

    def validate_bucket(self,validation_type,bucket_name):
        """Used by validate_bucket_head() to validate an AWS bucket name.

        Parameters:
        validation_type     Web request type to use for validation, e.g. head
        bucket_name         The bucket name to check
        """
        validation_functions = {
            'head': self.validate_bucket_head
        }
        if validation_functions[validation_type]:
            return validation_functions[validation_type](bucket_name)

    def validate_bucket_head(self,bucket_name):
        """Check a string to see if it exists as the name of an Amazon S3 bucket. This version uses
        awscli to identify a bucket and then uses Requests to check public access. The benefit of
        this is awscli will gather information from buckets that are otherwise inaccessible via
        anonymous web requests.

        This test requires authentication. Check credentials before use!

        Parameters:
        bucket_name     The bucket name to validate
        """
        error_values = {
            '400':True,
            '403':True,
            '404':False
        }
        result = {
            'bucketName':bucket_name,
            'bucketUri':'http://' + bucket_name + '.s3.amazonaws.com',
            'arn':'arn:aws:s3:::' + bucket_name,
            'exists':False,
            'public':False
        }
        try:
            self.boto3_client.head_bucket(Bucket=bucket_name)
            result['exists'] = True
            try:
                # Request the bucket to check the response
                request = requests.get(result['bucketUri'],timeout=self.requests_timeout)
                # All bucket names will get something, so look for the NoSuchBucket status
                if "NoSuchBucket" in request.text:
                    result['exists'] = False
                else:
                    result['exists'] = True
                # Check for a 200 OK to indicate a publicly listable bucket
                if request.status_code == 200:
                    result['public'] = True
                    click.secho("\n[*] Found a public bucket: {}".format(result['bucketName']),fg="yellow")
            except requests.exceptions.RequestException:
                result['exists'] = False
        except ClientError as error:
            result['exists'] = error_values[error.response['Error']['Code']]
        except EndpointConnectionError as error:
            click.secho("\n[*] Warning: Could not connect to a bucket to check it. If you see this \
message repeatedly, it's possible your awscli region is misconfigured, or this bucket is weird.",fg="red")
            click.secho("L.. Details: {}".format(error),fg="red")
            result['exists'] = error
        return result

    def validate_bucket_noncli(self,bucket_name):
        """Check a string to see if it exists as the name of an Amazon S3 bucket. This version uses
        only Requests and the bucket's URL.

        This is deprecated, but here just in case.

        Parameters:
        bucket_name     The bucket name to validate
        """
        bucket_uri = "http://" + bucket_name + ".s3.amazonaws.com"
        result = {
            'bucketName':bucket_name,
            'bucketUri':bucket_uri,
            'arn':'arn:aws:s3:::' + bucket_name,
            'exists':False,
            'public':False
        }
        try:
            # Request the bucket to check the response
            request = requests.get(bucket_uri,timeout=self.requests_timeout)
            # All bucket names will get something, so look for the NoSuchBucket status
            if "NoSuchBucket" in request.text:
                result['exists'] = False
            else:
                result['exists'] = True
            # Check for a 200 OK to indicate a publicly listable bucket
            if request.status_code == 200:
                result['public'] = True
        except requests.exceptions.RequestException:
            result['exists'] = False
        return result

    def validate_do_space(self,region,space_name):
        """Check a string to see if it exists as the name of a Digital Ocean Space.

        Parameters:
        region      The Digital Ocean region to use for searches
        space_name  The name of the Space to validate
        """
        space_uri = "http://" + space_name + region + ".digitaloceanspaces.com"
        result = {
            'bucketName':space_name,
            'bucketUri':space_uri,
            'arn':'arn:do:space:::' + space_name,
            'exists':False,
            'public':False
        }
        try:
            # Request the Space to check the response
            request = requests.get(space_uri)
            # All Space names will get something, so look for the NoSuchBucket status
            if "NoSuchBucket" in request.text:
                result['exists'] = False
            else:
                result['exists'] = True
            # Check for a 200 OK to indicate a publicly listable Space
            if request.status_code == 200:
                result['public'] = True
        except requests.exceptions.RequestException:
            result['exists'] = False
        return result

    def validate_account(self,account):
        """Check a string to see if it exists as the name of an AWS alias.

        Parameters:
        account     The AWS account alias to validate
        """
        result = {
            'accountAlias': None,
            'accountId': None,
            'signinUri': 'https://' + account + '.signin.aws.amazon.com/',
            'exists': False,
            'error': None
        }
        # Check if the provided account name is a string of numbers (an ID) or not (an alias)
        if re.match(r'\d{12}',account):
            result['accountId'] = account
        else:
            result['accountAlias'] = account
        if not validators.url(result['signinUri']):
            result['error'] = 'Invalid URI'
            return result
        try:
            # Request the sign-in URL and don't allow the redirect
            request = requests.get(result['signinUri'],allow_redirects=False,timeout=self.requests_timeout)
            # If we have a redirect, not a 404, we have a valid account alias for AWS
            if request.status_code == 302:
                result['exists'] = True
        except requests.exceptions.RequestException as error:
            result['error'] = error
        return result
