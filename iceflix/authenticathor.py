#!/usr/bin/env python3

import datetime
import threading
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
        password = self.currentUsers.userPasswords.get(user)
        if password is None:
            raise IceFlix.Unauthorized()
        elif password == passwordHash:
            token = secrets.token_hex(16)
            self.userUpdate.newToken(user,token,self.id)
            clock = threading.Timer(120.0, self.revocations.revokeToken, args=[token, self.id])
            clock.start()
        else:
            raise IceFlix.Unauthorized()
        return token

    def isAuthorized(self, userToken):
        if userToken in self.currentUsers.activeTokens:
            auth = True
        else:
            auth = False
        return auth

    def whois(self, userToken):
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized()
        else:
            return self.currentUsers.activeTokens.get(userToken)

    def isAdmin(self, adminToken):
        return self.adminToken == adminToken

    def addUser(self, user, passwordHash, adminToken):
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized

        self.currentUsers[user] = [{
            "token": secrets.token_hex(16),
            "passwordHash": passwordHash,
            "timestamp": time.mktime(datetime.datetime.now().timetuple())
        }]

        with open(PATH_USERS, 'w') as file:
            json.dump(self.currentUsers, file)

        self.userUpdate.newUser(user, passwordHash, self.id)

    def removeUser(self, user, adminToken):
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        self.currentUsers.pop(user)

        with open(PATH_USERS, 'w') as file:
            json.dump(self.currentUsers, file)

        self.userUpdate.removeUser(user, self.id)

    def bulkUpdate(self):
        auth_data = IceFlix.AuthenticatorData()
        auth_data.adminToken = self.adminToken
        auth_data.currentUsers = {user: data[0]['passwordHash'] for user, data in self.currentUsers.items()}
        auth_data.activeTokens = {user: data[0]['token'] for user, data in self.currentUsers.items() if data[0]['token']}
        
        return auth_data

# Interface to be used in the topic for user related updates
class UserUpdate:
    def __init__(self,authenticator:Authenticator):
        self.authenticator = authenticator

    def newToken(self, user, token, serviceId):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print('New token for ', user, ' received from', serviceId)
            self.servant.currentUsers.activeTokens[token] = user
        else:
            print('New token for ', user, ' from', serviceId, ' ignored')

    def revokeToken(self, token, serviceId):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print("Token ", token, " revoked from ", serviceId)
            self.authenticator.currentUsers.activeTokens.pop(token)
        elif serviceId == self.authenticator.id:
            print('Token ', token, ' timed out')
            self.authenticator.currentUsers.activeTokens.pop(token)
        else:
            print('Token ', token, ' from', serviceId, ' ignored')

    def newUser(self, user, passwordHash, serviceId):
        
        pass

    def removeUser(self, user, serviceId):
        
        pass

class Announcement:
    def announce(self, service, serviceId):
        
        pass