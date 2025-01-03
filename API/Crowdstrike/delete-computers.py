from falconpy import APIHarnessV2
from dotenv import load_dotenv, dotenv_values
from crowdstrike_dao import CrowdstrikeDao
import argparse

def configure_parser():
    parser = argparse.ArgumentParser(
        prog="Crowdstrike Falcon Bulk Hosts Delete", 
        description="Herramienta para eliminar equipos del Tenant de Crowdstrike"
    )
    parser.add_argument("--ssl-verify",type=bool, default=True)
    parser.add_argument("--debug",action="store_true")
    parser.add_argument("--action",choices=["simulate","delete"],default="simulate")
    parser.add_argument("--hosts",required=True)
    parser.add_argument("--search-tenant-childs",action='store_true')
    
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = configure_parser()
    config = dotenv_values(".env")

    crowd_dao = CrowdstrikeDao() 
    crowd_dao.login(client_id=config["CLIENT_ID"],client_secret=config["CLIENT_SECRET"],
                    parent_tenant_name="Parent Tenant",connect_child_tenants=args.search_tenant_childs, ssl_verify=args.ssl_verify)
    
    hosts = args.hosts.split(",")

    for host in hosts:
        dev = crowd_dao.get_device_by_hostname(host)
        if dev is None:
            print(f"NOTFOUND - {host}")
            continue
        
        if args.action == "simulate":
            print(f"SIMULATE - {dev.get('hostname')} - AID:{dev.get('device_id')} AgentVer:{dev.get('agent_version')} OS:{dev.get('os_version')}@{dev.get('os_build')} last_login_user:{dev.get('last_login_user')}")
        if args.action == "delete":
            deleted = crowd_dao.delete_host(dev)
            if deleted:
                print(f"DELETED - {dev.get('hostname')} AID:{dev.get('device_id')} AgentVer:{dev.get('agent_version')} OS:{dev.get('os_version')}@{dev.get('os_build')} last_login_user:{dev.get('last_login_user')}")
            else:
                print(f"ERROR - Failed to delete {dev.get('hostname')}")
    


