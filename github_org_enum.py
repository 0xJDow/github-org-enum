#!/usr/bin/python3

import os
import json
import re
import shutil
import argparse
import threading
import queue
import json
from urllib.parse import urlparse
from slack_sdk.webhook import WebhookClient
from github import Github
from truffleHog import truffleHog
from termcolor import colored

parser = argparse.ArgumentParser(description="Enumerate an entire github organization and, optionally, it's members for secrets in source.")
parser.add_argument("organization", type=str, help="The organization to enumerate.")
parser.add_argument("--access-token", type=str, default=None, help="A github access token to use (improved rate limiting).")
parser.add_argument("--include-members", default=False, action="store_true", help="Enumerate repositories of organization members.")
parser.add_argument("--slack-webhook", type=str, default=None, help="A slack webhook token for optionally emitting parsed results to slack.")
parser.add_argument("--threads", type=int, default=5, help="How many threads you want to run the application with (default 5).")
args = parser.parse_args()

# Queue object for multithreading
q = queue.Queue()

# Trufflehog regexes stripped down to reduce noise
# Credit where it's due: https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json
regexes = {
    "Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
}

"""
Authenticates to github and writes a list of organization repositories to a repos.txt file for processing
Optionally includes organization user repositories as well.
"""
def get_org_repos():
    # Authenticate to GitHub with the provided access token
    g = Github(args.access_token)
    
    # Get the organization you want to search
    org = g.get_organization(args.organization)

    # File to write repository URLs to
    repo_file = open("repos.txt","w")

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

"""
Searches a given GitHub repository for secrets in commit history
Results are emitted as 'trufflehog{repo_name}.json'
Credit where it's due: https://github.com/trufflesecurity/truffleHog/blob/dev/scripts/searchOrg.py#L44
"""
def find_secrets(url):
    # Empty object to store our trufflehog output
    output = []

    # Compile the regexes
    for key in regexes:
        regexes[key] = re.compile(regexes[key])

    # Run trufflehog against the specified repo
    results = truffleHog.find_strings(url, do_regex=True, custom_regexes=regexes, do_entropy=False, max_depth=100000)

    # Apply formatting to each trufflehog result
    url = os.path.splitext(url)[0] # Strip .git from the url to fix links
    for issue in results["foundIssues"]:
        d = json.loads(open(issue).read())
        d['github_url'] = "{}/blob/{}/{}".format(url, d['commitHash'], d['path'])
        d['github_commit_url'] = "{}/commit/{}".format(url, d['commitHash'])
        d['diff'] = d['diff'][0:200]
        d['printDiff'] = d['printDiff'][0:200]

        # Append each individual issue to store them altogether as output
        output.append(d)

    # Remove forward slashes in output file name
    path = urlparse(url).path.replace('/', '-') # Use splitext because we don't want '.git' in the filename
    with open(f"./output_raw/trufflehog{path}.json", "a") as outfile:
        json.dump(output, outfile, ensure_ascii=False, indent=4)

    # cleanup
    try:
        shutil.rmtree(results["issues_path"])
    except OSError as e:
        print("Error: %s : %s" % (results["issues_path"], e.strerror))

    return output

"""
Takes a list of trufflehog result dictionaries and attempts to remove duplicate secrets:
- printing the results to the console
- saving them to a local 'parsed_{file}.json' file
- and (optionally) sending them to slack via webhook
"""
def parse_results(repo, results):            
    # List of strings
    identified_secrets = []

    # List of dicts
    parsed_results = []

    # Iterate over the results extracting found secrets
    for result in results:
        # stringsFound is also a list object so we need to iterate over that too
        for s in result["stringsFound"]:

            # Add the secret to our list of secrets if its not already there
            if s not in identified_secrets:
                identified_secrets.append(s)

                # Store the new result
                parsed_results.append(result)

                # Let the user know we found a new secret
                print(colored("[!] Found New Secret:", "red"), colored(result['reason'], "yellow"), "\n", \
                    colored("Value:", "red"), colored(s, "yellow"), "\n", \
                    colored("Path:", "red"), colored(result['path'], "yellow"), "\n", \
                    colored("Commit:", "red"), colored(result['github_commit_url'], "yellow"), "\n")

                # emit to slack here if webhooks are enabled, so we don't iterate over the list twice
                if args.slack_webhook is not None:
                    send_result_to_slack(s, result)

    # Save the parsed_results to a .json file for reference
    cleaned_repo_name = os.path.splitext(urlparse(repo).path.replace('/', '-'))[0]
    with open(f"./output_parsed/parsed-trufflehog{cleaned_repo_name}.json", "a") as parsedfile:
        json.dump(parsed_results, parsedfile, ensure_ascii=False, indent=4)

"""
Worker method to find secrets and parse results
"""
def worker():
    while True:
        repo = q.get()
        results = find_secrets(repo)
        parse_results(repo, results)
        q.task_done()

"""
Send generic text to slack in a slightly-formatted way
"""
def send_text_to_slack(text):
    webhook = WebhookClient(args.slack_webhook)
    webhook.send(
    text = f"{text}\n",
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{text}\n"
            }
        }
    ]
)


"""
Send the passed secret and result to a slack channel via webhook
"""
def send_result_to_slack(secret, result):
    webhook = WebhookClient(args.slack_webhook)
    webhook.send(
    text = f"[!] Found New Secret: {result['reason']}\nValue: {secret}\nPath: {result['path']}\nCommit: {result['github_commit_url']}\n",
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```[!] Found New Secret: {result['reason']}\nValue: {secret}\nPath: {result['path']}\nCommit: {result['github_commit_url']}```\n"
            }
        }
    ]
)

def main():
    # Get the list of organization repos
    get_org_repos()

    # Let the user know what organization we are scanning against
    print(colored("[+] Running trufflehog against organization:", "green"), colored(args.organization, "cyan"), "\n")
    if args.slack_webhook is not None:
        send_text_to_slack(f"*[+] Running trufflehog against organization:* `{args.organization}`")

    # Run trufflehog, multithreaded, against all of the repositories
    with open("repos.txt") as f:
        repos = f.read().splitlines()

        # testing queues
        for i in range(args.threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
        
        for repo in repos:
            q.put(repo)

        # block until all tasks are done
        q.join()

if __name__=="__main__":
    main()
