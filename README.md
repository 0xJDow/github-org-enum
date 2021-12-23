# GitHub Org Enum

## Installation

```
pip3 install -r requirements.txt
```

## Usage:

Purpose of this repo is to provide testers with the ability to enumerate an entire github organization and, optionally, it's members for secrets in source.

```
usage: github_org_enum.py [-h] [--access-token ACCESS_TOKEN] [--include-members] [--slack-webhook SLACK_WEBHOOK] [--threads THREADS]
                          organization

Get a list of GitHub repository URLs for a given organization.

positional arguments:
  organization          The organization to pull repos from.

optional arguments:
  -h, --help            show this help message and exit
  --access-token ACCESS_TOKEN
                        A github access token to use (improved rate limiting).
  --include-members     Recursively gets repos from all organization members.
  --slack-webhook SLACK_WEBHOOK
                        A slack webhook token for optionally emitting parsed results to slack.
  --threads THREADS     How many threads you want to run the application with
```