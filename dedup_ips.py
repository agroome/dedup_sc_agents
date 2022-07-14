import argparse
import sys
from io import StringIO
from dotenv import load_dotenv
from tenable.sc import TenableSC

class RepositoryNotFound(Exception):
    pass

class RepositoryWrongType(Exception):
    pass

class BadInput(Exception):
    pass

load_dotenv()

nessus_template_file='template.nessus'
    

def update_asset_list(sc: TenableSC, name: str, ip_list: list):
    asset_lists = sc.asset_lists.list()
    matching_lists = [a for a in asset_lists['manageable'] if a['name'] == name]
    if matching_lists:
        asset_list = matching_lists.pop()
        sc.asset_lists.edit(id=int(asset_list['id']), ips=ip_list)
        print(f'updated asset_list: {name}')
    else:
        asset_list = sc.asset_lists.create(name, list_type='static', ips=ip_list)
        print(f'created asset_list: {name}')
    
        
def get_repository_ips(sc: TenableSC, repository: dict) -> list:
    # get a list of IPv4 addresses from the repository
    repository_filter = [int(repository['id'])]
    findings = sc.analysis.vulns(('repository', '=', repository_filter), tool='sumip')
    return [record['ip'] for record in findings]


def delete_from_repository(sc: TenableSC, repository: dict, ip_list: list) -> None:
    # combine the nessus template file with the desired targets
    global nessus_template_file
    with open(nessus_template_file, 'r') as fp:
        nessus_template = fp.read()
    nessus_file_str = nessus_template.format(TARGET_IPS=','.join(ip_list))

    # upload the empty scan results for the ips into the target repository
    sc.scan_instances.import_scan(StringIO(nessus_file_str), repo=int(repository['id']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--input-file', help='read ips from this file')
    parser.add_argument('-i', '--input-repository', help='read ips from this repository, ignored when --input-file is used')
    parser.add_argument('-t', '--target-repository', help='delete matching ips from this repository')
    parser.add_argument('-l', '--list', action='store_true', help='list ips with -f or -i, otherwise list repository names then exit')
    parser.add_argument('-a', '--update-asset-list', help='create or update a static asset list (replacing contents with the input IPs)')
    parser.add_argument('-s', '--tsc-server', required=True, help='Tenable.sc hostname or ip address')
    parser.add_argument('-p', '--tsc-port', default=443, help='Tenable.sc port')
    args = parser.parse_args()

    sc = TenableSC(host=args.tsc_server, port=args.tsc_port)
    
    repositories = {repo['name']: repo for repo in sc.repositories.list()}

    # inputs: source for IPs is either input_file or input_repository
    if args.input_file:
        # get the ip_list from a file
        with open(args.input_file) as fp:
            ip_list = ','.join([
                line.strip().replace(' ', '') for line in fp.readlines()
            ]).split(',')
        print(f'reading from {args.input_file}')

    elif args.input_repository:
        # get the ip_list from the input_repo
        input_repo = repositories.get(args.input_repository)
        if not input_repo:
            raise RepositoryNotFound(f'{args.input_repository} not found')

        ip_list = get_repository_ips(sc, input_repo)
        print(f'read {len(ip_list)} IP addresses from {args.input_repository}')

    # actions: remove input IPs from target repository and/or update static asset list
    if args.target_repository:
        # remove IPs from target_repository
        if not ip_list:
            raise BadInput('input IP addresses not specified')

        target_repo = repositories.get(args.target_repository)
        if not target_repo:
            raise RepositoryNotFound(f'{args.target_repository} not found')
        elif target_repo['dataFormat'] != 'IPv4':
            raise RepositoryWrongType(f'{args.target_repository} must be an IPv4 repository')

        print(f'deleting from {args.target_repository}')
        delete_from_repository(sc, target_repo, ip_list)

    if args.update_asset_list:
        # create or update a static asset list
        if not ip_list:
            raise BadInput('input IP addresses not specified')

        update_asset_list(sc, args.update_asset_list, ip_list)

    print("complete.")



if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(repr(e))