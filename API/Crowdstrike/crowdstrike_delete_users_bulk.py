from falconpy import APIHarnessV2
from dotenv import dotenv_values
from crowdstrike_dao import CrowdstrikeDao
import argparse

def configure_parser():
    parser = argparse.ArgumentParser(
        prog="Crowdstrike Falcon Bulk User Delete", 
        description="Herramienta para eliminar usuarios obsoletos del Tenant de Crowdstrike"
    )
    parser.add_argument("--ssl-verify",type=bool, default=True)
    parser.add_argument("--debug",type=bool,default=False)
    parser.add_argument("--action",choices=["simulate","delete"],default="simulate")
    parser.add_argument("--connect-child",type=bool,default=True)
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = configure_parser()
    config = dotenv_values(".env")

    crowd_dao = CrowdstrikeDao() 
    crowd_dao.login(client_id=config["CLIENT_ID"],client_secret=config["CLIENT_SECRET"],parent_tenant_name="Parent Tenant",connect_child_tenants=args.connect_child, ssl_verify=args.ssl_verify)

    with open("usuarios_baja.txt","r") as f:
        for line in f:
            user = crowd_dao.get_user_by_email(line)
            if user:
                if args.action == "delete":
                    if crowd_dao.delete_user(user):
                        print(f"DELETE - {line} con uuid: {user['uuid']}, Tenant {user['tenant']["name"]}")
                    else:
                        print(f"ERROR - {line} encontrado con uuid: {user['uuid']}, en Tenant {user['tenant']["name"]} pero ha fallado el borrado")
                else:
                    print(f"SIMULATE - {line} - Simulando borrado con uuid: {user['uuid']}, Tenant {user['tenant']['name']}")
            else:
                print(f"NOTFOUND - {user} - No se ha encontrado en ningun tenant")
