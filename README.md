# GitHub Org Enum

## Installation

```
pip3 install -r requirements.txt
```

## Requirements:

* Must have [trufflehog](https://github.com/trufflesecurity/truffleHog) installed and in your `$PATH`.

## Usage:

Purpose of this repo is to provide testers with the ability to enumerate an entire github organization and, optionally, it's members for secrets in source. This is done by running two scripts sequentially:

1. `get_org_repos.py`: Running this script as `python3 ./get_org_repos.py [-h] [--access-token ACCESS_TOKEN] [--include-members] organization` will produce `repos.txt` which contains a list of repository URLs for a given organization.
2. `run_trufflehog.sh`: Running this script will take `repos.txt` and use bash to run `trufflehog` against it. Trufflehog output will be in the `output` folder, organized by repository. **Note:** this can take a very long time depending on how many repos you're going through (you can tweak `xargs --max-procs=5` in `run_trufflehog.sh` to try and speed it up.)
