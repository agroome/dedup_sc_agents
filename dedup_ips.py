import argparse
import sys
from io import StringIO
from dotenv import load_dotenv
from tenable.sc import TenableSC

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--source-repository', help='read ips from this repository')
parser.add_argument('-t', '--target-repository', help='delete matching ips from this repository')
args = parser.parse_args()

load_dotenv()

template_file='template.nessus'
sc_host = '127.0.0.1'
sc_port = 8443

sc = TenableSC(host=sc_host, port=sc_port)

repositories = {repo['name']: repo for repo in sc.repositories.list(repo_type='Local')}

# identify source repository to read IPs targets
source_repo = repositories.get('args.source_repository')
if not source_repo:
    sys.exit(f'{source_repo} not found')
elif source_repo['dataType'] != 'agent':
    sys.exit(f'{source_repo} must be an agent repository')

# identify target repository to delete matching IPs 
target_repo = repositories.get('args.target_repository')
if not target_repo:
    sys.exit(f'{target_repo} not found')
elif target_repo['dataType'] != 'ipv4':
    sys.exit(f'{target_repo} must be an ipv4 repository')

print(f'source: [{source_repo["id"]}] {source_repo["name"]}')
print(f'target: [{target_repo["id"]}] {target_repo["name"]}')

# get the target IPs from the source repository
source_results = sc.analysis.vulns(tool='ipsum', filters=[('repository', '=', source_repo['id'])])
targets = ','.join([record['ipv4'] for record in source_results])
print(f'identified {len(source_results)} targets: {targets}')

# combine the nessus template file with the desired targets
with open(template_file, 'r') as fp:
    nessus_template = fp.read()
nessus_file_str = nessus_template.format(TARGET_IPS=targets)

# upload the 'scan results' to the target repository
# sc.scan_instances.import_scan(StringIO(nessus_file_str), target_repo['id'])
