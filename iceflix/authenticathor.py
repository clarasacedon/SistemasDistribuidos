#!/usr/bin/env python3

import datetime
import Ice
import IceFlix
import json
import os
import secrets
import threading
import time

Ice.loadSlice('iceflix/iceflix.ice')

PATH_USERS = 'iceflix/users.json'

try:
	import IceFlix
except ModuleNotFoundError:
	Ice.loadSlice(os.path.join(os.path.dirname(__file__), "iceflix/iceflix.ice"))
	import IceFlix                       

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
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print('New user for ', user, ' received from', serviceId)
            self.servant.currentUsers.userPasswords[user] = passwordHash
        else:
            print('New user for ', user, ' from', serviceId, ' ignored')

    def removeUser(self, user, serviceId):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print('User ', user, ' removed from ', serviceId)
            self.authenticator.currentUsers.userPasswords.pop(user)
        else:
            print('User ', user, ' from', serviceId, ' ignored')

class Announcement:
    def __init__(self,authenticator:Authenticator):
        self.authenticator = authenticator

    def announce(self, service, serviceId):
        if serviceId != self.authenticator.id and serviceId not in self.authenticator.proxies:
            if service.ice_isA('::IceFlix::Authenticator'):
                self.authenticator.proxies[serviceId] = IceFlix.AuthenticatorPrx.uncheckedCast(service)
            elif service.ice_isA('::IceFlix::Main'):
                self.authenticator.proxies[serviceId] = IceFlix.MainPrx.uncheckedCast(service)
        else:
            print('Service: ', service, ' ignored')
