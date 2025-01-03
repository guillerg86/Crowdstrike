##############################################################################
# Modulo con las funciones para gestionar usuarios con la API de Crowdstrike
# @author: Guille Rodríguez González 
# 
# CHANGELOG: 
# @version: 2025.01.03-1021 - Host find, get & hide (delete) 
# @version: 2024.05.09-1245 - User functions
##############################################################################
from falconpy import APIHarnessV2
import copy


class VariableIsNotDictInstanceException(Exception):
    def __init__(self, variable, message="La variable indicada no es del tipo dict"):
        self.variable = variable
        super().__init__(message)

class CrowdstrikeDao(object):
##########################################################################################
# PRIVATE METHODS
##########################################################################################
    def __init__(self) -> None:
        self.__tenant_connections = []
        self.__auth = {
            "client_id": None,
            "client_secret": None,
            "debug": False,
            "ssl_verify": False,
        }

    def __set_tenant_config(self,client_id, client_secret):
        """
        Configura las credenciales
        """
        self.__auth["client_id"] = client_id
        self.__auth["client_secret"] = client_secret

    def __get_falcon_connection(self,tenant_id=None):
        """
        Configura la conexión con el Tenant y crea el objeto para realizar las llamadas API
        @param tenant_id: Si es None, configurará la conexión con el tenant padre, si tiene un identificador, configurará la conexión con el tenant con dicho identificador
        @return APIHarnessV2: Conexión con la API
        """
        if tenant_id is None:
            tenant_config = self.__auth
        else:
            tenant_config = copy.deepcopy(self.__auth)
            tenant_config["member_cid"] = tenant_id
        return APIHarnessV2(**tenant_config)
    
    def __get_child_tenants(self,falcon_parent_connection):
        """
        Consulta a la API si existen Tenant hijos y los obtiene
        @param falcon_parent_connection: Conexión establecida con la API
        @return array: Listado de child tenants (dict)
        """
        childs = []
        childs.extend(falcon_parent_connection.command("getChildren", ids=falcon_parent_connection.command("queryChildren")["body"]["resources"])["body"]["resources"])
        return childs
    


##########################################################################################
# PUBLIC METHODS
##########################################################################################    
    def get_connections(self):
        """
        Devuelve el listado de conexiones
        @return array
        """
        return self.__tenant_connections
    
    def login(self,client_id,client_secret,connect_child_tenants=True,ssl_verify=True, debug=False, parent_tenant_name="Parent Tenant"):
        """
        Conecta al tenant mediante las credenciales de la API proporcionadas
        @param client_id: ClientID de la API de Crowdstrike
        @param client_secret: ClientSecret de la API de Crowdstrike
        @param connect_child_tenants: Indica si se ha de conectar a los tenant hijos, default=True
        @param ssl_verify: Indica si ha de comprobar el certificado. default=True. Si usa Netskope -> configure como False
        @param parent_tenant_name 
        """
        self.__set_tenant_config(client_id,client_secret)
        falcon_parent_connection = self.__get_falcon_connection()
        if falcon_parent_connection.login() == False:
            raise ConnectionError("No se pudo conectar con la API de Crowdstrike al Tenant padre. Revise credenciales o la API")
        
        self.__tenant_connections = [{"connection": falcon_parent_connection, "name": parent_tenant_name, "cid": None}]
        if connect_child_tenants == True:
            for child in self.__get_child_tenants(falcon_parent_connection):
                child_connection = self.__get_falcon_connection(child['child_cid'])
                if child_connection.login():
                    self.__tenant_connections.append({"connection":child_connection, "name":child['name'], "cid":child["child_cid"]})
                else:
                    raise ConnectionError(f"No se pudo conectar con la API de Crowdstrike al tenant {child['name']} con cid {child['cid']}")

##########################################################################################
# USER METHODS
##########################################################################################

    def find_user(self, email, tenant_connection):
        """
        Busca al usuario en el tenant proporcionado
        Ejemplo de retorno de usuario encontrado:
        {'firstName': 'Usuario', 'lastName': 'Apellido', 'uid': 'user@ciberseguretat.cat', 'uuid': '07b61a51-00e5-4947-b5a0-1520456f1c1b', 'customer': '9889013e3aa74eb28370dc224a9e2066', 'status': 'active'}
        
        @param email: Email del usuario a buscar
        @param falcon_connection: Conexión del tenant
        @return dict or None: Devuelve un diccionario con la información del usuario si lo ha encontrado
        """
        response = tenant_connection.command("RetrieveUserUUID", uid=email)["body"].get("resources")
        if response and len(response) > 0:
            return tenant_connection.command("RetrieveUser", ids=response[0])["body"]["resources"][0]
        return None


    def get_user_by_email(self,email):
        """
        Busca al usuario en todos los tenant disponibles y obtiene su información. 
        Adicionalmente, añade información del tenant en el que se ha encontrado
        Ejemplo de retorno de usuario encontrado:
        {'firstName': 'Usuario', 'lastName': 'Apellido', 'uid': 'user@ciberseguretat.cat', 'uuid': '07b61a51-00e5-4947-b5a0-1520456f1c1b', 'customer': '9889013e3aa74eb28370dc224a9e2066', 'status': 'active', 'tenant': {'name': 'ACC Parent Tenant', 'cid': None}}

        @param email: Email del usuario a buscar
        @return dict or None: Devuelve un diccionario con la información del usuario si lo ha encontrado, añade los campos con el id del tenant
        """
        for tenant in self.__tenant_connections:
            user = self.find_user(email,tenant["connection"])
            if user:
                user["tenant"] = {"name":tenant['name'], "cid":tenant['cid']}
                return user
        return None    
        

    def delete_user(self,user):
        """
        Recibe un diccionario con la información del usuario y el tenant donde está dado de alta por lo general el extraido de get_user_by_email.
        Ejemplo generado por get_user_by_email:
        {'firstName': 'Usuario', 'lastName': 'Apellido', 'uid': 'user@ciberseguretat.cat', 'uuid': '07b61a51-00e5-4947-b5a0-1520456f1c1b', 'customer': '9889013e3aa74eb28370dc224a9e2066', 'status': 'active', 'tenant': {'name': 'ACC Parent Tenant', 'cid': None}}
        
        @param user: Diccionario con la información del usuario. Información mínima {"uuid":"user_uuid", "tenant":{"cid": "tenant_cid"}} -> Si es el parent, el tenant_cid ha de ser None
        @return bool: Si encuentra y ELIMINA al usuario devuelve True, en cualquier otro caso devuelve False
        """
        if not isinstance(user,dict):
            raise VariableIsNotDictInstanceException(user)
      
        tenant_cid = user.get("tenant").get("cid")
        # Buscamos el tenant a través del CID
        for tenant in self.__tenant_connections:
            if tenant.get("cid") == tenant_cid:
                response = tenant["connection"].command("DeleteUser",user_uuid=user['uuid'])
                if response.get('status_code') == 200:
                    return True
        return False


##########################################################################################
# HOST METHODS
##########################################################################################    

    def find_device(self,hostname,tenant_connection):        
        response = tenant_connection.command("QueryDevicesByFilter", filter=f"hostname:'{hostname}'").get('body',{}).get('resources',None)
        if response and len(response)>0:
            return tenant_connection.command("GetDeviceDetails", ids=response[0])["body"]["resources"][0]
        return None

    def get_device_by_hostname(self,hostname):
        for tenant in self.__tenant_connections:
            device = self.find_device(hostname,tenant["connection"])
            if device:
                device["tenant"] = {"name":tenant['name'], "cid":tenant['cid']}
                return device
        return None    
    
    def delete_host(self,device):
        body = {"ids":[device.get('device_id')],}
        tenant_cid = device.get("tenant").get("cid")
        for tenant in self.__tenant_connections:
            if tenant.get("cid") == tenant_cid:
                response = tenant["connection"].command("PerformActionV2",action_name="hide_host",body=body)
                #print(response)
                sc = response.get('status_code')
                if sc >= 200 and sc <= 299:
                    return True
        return False


        
