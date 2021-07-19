#!/usr/bin/python3

"""
Get a list of all the public repos of a given github organization
"""

import sys
import argparse
from github import Github

parser = argparse.ArgumentParser(description="Get a list of GitHub repository URLs for a given organization.")
parser.add_argument("organization", type=str, help="The organization to pull repos from.")
parser.add_argument("--access-token", type=str, default=None, help="A github access token to use (improved rate limiting).")
parser.add_argument("--include-members", default=False, action="store_true", help="Recursively gets repos from all organization members.")
args = parser.parse_args()

def main():
    g = Github(args.access_token)
    
    # Get the organization you want to search
    org = g.get_organization(args.organization)

    # File to write repository URLs to
    repo_file = open("repos.txt","a")

    # Get the organization's repos
    for repo in org.get_repos():
        repo_file.write(repo.clone_url + "\n")

    # If we're recursing through org members to get their repos too
    if args.include_members:
        # Find all members in that organization
        for member in org.get_members():
            # Make a list of all public organization member repos
            for repo in member.get_repos():
                repo_file.write(repo.clone_url + "\n")

    repo_file.close()

if __name__=="__main__":
    main()
