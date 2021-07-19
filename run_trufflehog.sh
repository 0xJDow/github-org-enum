#!/usr/bin/bash

# Use after running `python3 get_org_repos.py <org_name>` to run trufflehog against all found repos.
mkdir -p ./output
xargs -I % --arg-file=repos.txt --max-procs=5 --delimiter='\n' bash -c 'trufflehog --regex --entropy=False % | sed "s/\x1b\[[0-9;]*m//g" > ./output/$(basename %)'
