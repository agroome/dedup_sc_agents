import argparse
import os
import sys
from io import StringIO
from dotenv import load_dotenv
from tenable.sc import TenableSC
from pprint import pprint

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--source-repository', help='read ips from this repository')
parser.add_argument('-t', '--target-repository', help='delete matching ips from this repository')
args = parser.parse_args()

load_dotenv()

user_access_key = os.getenv('TSC_ACCESS_KEY')
user_secret_key = os.getenv('TSC_SECRET_KEY')
admin_access_key = os.getenv('TSC_ADMIN_ACCESS_KEY')
admin_secret_key = os.getenv('TSC_ADMIN_SECRET_KEY')

access_key = user_access_key
secret_key = user_secret_key

def use_admin_key(value: bool=True):
    global access_key
    global secret_key
    if value:
        os.environ['TSC_ACCESS_KEY'] = admin_access_key
        os.environ['TSC_SECRET_KEY'] = admin_secret_key
        access_key = admin_access_key
        secret_key = admin_secret_key
    else:
        os.environ['TSC_ACCESS_KEY'] = user_access_key
        os.environ['TSC_SECRET_KEY'] = user_secret_key
        access_key = user_access_key
        secret_key = user_secret_key

# import requests
# import urllib3
# from pprint import pprint

# urllib3.disable_warnings()

# access_key = os.getenv('TSC_ADMIN_ACCESS_KEY')
# secret_key = os.getenv('TSC_ADMIN_SECRET_KEY')

# headers = {
#     'x-apikey': f'accessKey={access_key}; secretKey={secret_key}'
# }
# repos = requests.get('https://127.0.0.1:8443/rest/repository?type=All', headers=headers, verify=False)
# pprint(repos.json())


template_file='template.nessus'
sc_host = '127.0.0.1'
sc_port = 8443

sc = TenableSC(host=sc_host, port=sc_port)

repositories = {repo['name']: repo for repo in sc.repositories.list()}

pprint(repositories['Agents'])
pprint(repositories[args.target_repository])

# identify source repository to read IPs targets
source_repo = repositories.get(args.source_repository)
if not source_repo:
    sys.exit(f'{args.source_repository} not found')
elif source_repo['dataFormat'] != 'agent':
    sys.exit(f'{args.source_repository} must be an agent repository')

# identify target repository to delete matching IPs 
target_repo = repositories.get(args.target_repository)
if not target_repo:
    sys.exit(f'{args.target_repository} not found')
elif target_repo['dataFormat'] != 'IPv4':
    sys.exit(f'{args.target_repository} must be an IPv4 repository')

print(f'source: [{source_repo["id"]}] {source_repo["name"]}')
print(f'target: [{target_repo["id"]}] {target_repo["name"]}')

# get the target IPs from the source repository
repository_filter = [int(source_repo['id'])]
source_findings = sc.analysis.vulns(('repository', '=', repository_filter), tool='sumip')

ip_list = [record['ip'] for record in source_findings]
targets = ','.join(ip_list)
print(f'identified {len(ip_list)} targets: {targets}')

# combine the nessus template file with the desired targets

# with open(template_file, 'r') as fp:
#     nessus_template = fp.read()
# nessus_file_str = nessus_template.format(TARGET_IPS=targets)

# upload the 'scan results' to the target repository
# sc.scan_instances.import_scan(StringIO(nessus_file_str), target_repo['id'])

