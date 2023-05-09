#!/usr/bin/env python3

import datetime
import Ice
import IceFlix
import json
import os
import secrets
import time

Ice.loadSlice('iceflix/iceflix.ice')

PATH_USERS = 'iceflix/users.json'

try:
	import iceflix
except ModuleNotFoundError:
	Ice.loadSlice(os.path.join(os.path.dirname(__file__), "iceflix/iceflix.ice"))
	import iceflix                       
	
# Auth server #
class AuthenticatorData:
    def __init__(self):
        self.adminToken = ""
        self.currentUsers = {}  # users: passwords
        self.activeTokens = {}  # users: tokens

class Authenticator:
    def refreshAuthorization(self, user, passwordHash):
        #Crea un nuevo token de autorizacion de usuario si las credenciales son validas.
        password = self.usersDB.userPasswords.get(user)
        if password is None:
            raise IceFlix.Unauthorized()
        elif password == passwordHash:
            token = secrets.token_hex(16)
            self.userUpdate.newToken(user,token,self.id)
        else:
            raise IceFlix.Unauthorized()
        return token

    def isAuthorized(self, userToken):
        #Indica si un token dado es valido o no.
        if userToken in self.usersDB.usersToken:
            return True
        else:
            return False

    def whois(self, userToken):
        #Permite descubrir el nombre del usuario a partir de un token valido.
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized()
        else:
            user = self.usersDB.usersToken.get(userToken)
            return user

    def isAdmin(self, adminToken):
        #Devuelve un valor booleano para comprobar si el token proporcionado corresponde o no con el administrativo.
        return self.adminToken == adminToken

    def addUser(self, user, passwordHash, adminToken):
        #Funcion administrativa que permite aniadir unas nuevas credenciales en el almacen de datos si el token 
        #administrativo es correcto.

        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized

        self.users[user] = [{
            "token": secrets.token_hex(16),
            "passwordHash": passwordHash,
            "timestamp": time.mktime(datetime.datetime.now().timetuple())
        }]

        with open(PATH_USERS, 'w') as file:
            json.dump(self.users, file)

        self.userUpdate.newUser(user, passwordHash, self.id)

    def removeUser(self, user, adminToken):
        #Funcion administrativa que permite eliminar unas credenciales del almacen de datos si el token 
        #administrativo es correcto.
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        self.users.pop(user)

        with open(PATH_USERS, 'w') as file:
            json.dump(self.users, file)

        self.userUpdate.removeUser(user, self.id)

    def bulkUpdate(self):
        auth_data = IceFlix.AuthenticatorData()
        auth_data.adminToken = self.adminToken
        auth_data.currentUsers = {user: data[0]['passwordHash'] for user, data in self.users.items()}
        auth_data.activeTokens = {user: data[0]['token'] for user, data in self.users.items() if data[0]['token']}
        
        return auth_data

# Interface to be used in the topic for user related updates
class UserUpdate:
    def newToken(self, user, token, serviceId):
        
        pass

    def revokeToken(self, token, serviceId):
        
        pass

    def newUser(self, user, passwordHash, serviceId):
        
        pass

    def removeUser(self, user, serviceId):
        
        pass

class Announcement:
    def announce(self, service, serviceId):
        
        pass