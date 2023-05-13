#!/usr/bin/env python3 

import random
import sys
import Ice
import json
import os
import secrets
import time

Ice.loadSlice('iceflix/iceflix.ice')

PATH_USERS = 'iceflix/users.json'

try:
    import IceFlix
    import IceStorm
except ModuleNotFoundError:
    Ice.loadSlice(os.path.join(os.path.dirname(__file__), "iceflix/iceflix.ice"))
    import IceFlix
    import IceStorm                    

# Auth server #
class AuthenticatorData(IceFlix.AuthenticatorData):
    def __init__(self):
        self.adminToken = ""
        self.currentUsers = {}  # users: passwords
        self.activeTokens = {}  # users: tokens

class Authenticator(IceFlix.Authenticator):
    def __init__(self):
        self.id = str(random.randint(0, 1000000))
        self.proxies = {}
        self.database = AuthenticatorData()
        self.userUpdate = None

    def refreshAuthorization(self, user, passwordHash, current=None):
        password = self.database.currentUsers[user]
        if password is None:
            raise IceFlix.Unauthorized()
        elif password == passwordHash:
            token = secrets.token_hex(16)
            self.userUpdate.newToken(user,token,self.id)
            time.sleep(120.0, self.userUpdate.revokeToken, args=[token, self.id])
        else:
            raise IceFlix.Unauthorized()
        return token

    def isAuthorized(self, userToken, current=None):
        if userToken in self.database.activeTokens:
            auth = True
        else:
            auth = False
        return auth

    def whois(self, userToken, current=None):
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized()
        else:
            for user, token in self.database.activeTokens.items():
                if token == userToken:
                    return user
        return None
    
    def isAdmin(self, adminToken, current=None):
        return self.database.adminToken == adminToken

    def addUser(self, user, passwordHash, adminToken, current=None):
        if self.database.currentUsers.get(user) or not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        self.database.activeTokens[user] = secrets.token_hex(16)
        self.database.currentUsers[user] = passwordHash

        with open(PATH_USERS, 'w') as file:
            json.dump(self.database.currentUsers, file)

        self.userUpdate.newUser(user, passwordHash, self.id)

    def removeUser(self, user, adminToken, current=None):
        if not self.database.currentUsers.get(user) or not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        self.database.currentUsers.pop(user)

        with open(PATH_USERS, 'w') as file:
            json.dump(self.database.currentUsers, file)

        self.userUpdate.removeUser(user, self.id)

    def bulkUpdate(self, current=None):
        authData = self.database
        return authData

# Interface to be used in the topic for user related updates
class UserUpdate(IceFlix.UserUpdate):
    def __init__(self, servant):
        self.servant = servant

    def newToken(self, user, token, serviceId, current=None):
        if serviceId != self.servant.id and serviceId in self.servant.proxies:
            print('New token for ', user, ' received from', serviceId)
            self.servant.database.activeTokens[user] = token
        else:
            print('New token for ', user, ' from', serviceId, ' ignored')

    def revokeToken(self, token, serviceId, current=None):
        if serviceId != self.servant.id and serviceId in self.servant.proxies:
            print("Token ", token, " revoked from ", serviceId)
            for user, t in self.servant.database.activeTokens.items():
                if t == token:
                    self.servant.database.activeTokens.pop(user)
        elif serviceId == self.servant.id:
            print('Token ', token, ' timed out')
            for user, t in self.servant.database.activeTokens.items():
                if t == token:
                    self.servant.database.activeTokens.pop(user)
        else:
            print('Token ', token, ' from', serviceId, ' ignored')

    def newUser(self, user, passwordHash, serviceId, current=None):
        if serviceId != self.servant.id and serviceId in self.servant.proxies:
            print('New user for ', user, ' received from', serviceId)
            self.servant.database.currentUsers[user] = passwordHash
        else:
            print('New user for ', user, ' from', serviceId, ' ignored')

    def removeUser(self, user, serviceId, current=None):
        if serviceId != self.servant.id and serviceId in self.servant.proxies:
            print('User ', user, ' removed from ', serviceId)
            self.servant.database.currentUsers.pop(user)
        else:
            print('User ', user, ' from', serviceId, ' ignored')

class Announcement(IceFlix.Announcement):
    def __init__(self, servant):
        self.servant = servant

    def announce(self, service, serviceId, current=None):
        if serviceId != self.servant.id and serviceId not in self.servant.proxies:
            if service.ice_isA('::IceFlix::Authenticator'):
                proxy = IceFlix.AuthenticatorPrx.uncheckedCast(service)
                self.servant.proxies.setdefault('Authenticator', {})[serviceId] = proxy
            else:
                print('Unknown service type:', service)
        else:
            print('Service: ', service, ' ignored')

class Server(Ice.Application):
    def subscribe_topic(self, object, topic_manager, topic_name, current=None):
        proxy = None
        microservice = self.adapter.addWithUUID(object)
        
        try:
            topic = topic_manager.retrieve(topic_name)
        except IceStorm.NoSuchTopic:
            topic = topic_manager.create(topic_name)

        topic.subscribeAndGetPublisher({}, microservice)
        publisher = topic.getPublisher()
        
        if topic_name == "Announcement":
            proxy = IceFlix.AnnouncementPrx.uncheckedCast(publisher)
        elif topic_name == "UserUpdate":
            proxy = IceFlix.UserUpdatePrx.uncheckedCast(publisher)
        
        return topic, proxy

    def announceAuth(self, announcement, authenticator_proxy, id, current=None):
        while True:
            announcement.announce(authenticator_proxy, id)
            time.sleep(random.randint(1,10))

    def find_authenticator(self, servant, current=None):
        auth = None

        for serviceId, proxy in servant.proxies.get('Authenticator', {}).items():
            if auth is None:
                auth = proxy
            else:
                print('Warning: Found multiple Authenticators')
                break
                
        return auth

    def run(self, argv):
        tester_proxy = "IceStorm.TopicManager"
        broker = self.communicator()

        topic_manager = IceStorm.TopicManagerPrx.checkedCast(broker.propertyToProxy(tester_proxy))

        adminToken = broker.getProperties().getProperty('adminToken')
        servant = Authenticator()
        servant.database.adminToken = adminToken
        self.adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter", "tcp")
        authenticator_proxy = self.adapter.add(servant, broker.stringToIdentity("authenticator"))
        self.adapter.activate()

        user_updates = UserUpdate(servant)
        announce = Announcement(servant)

        topicA, proxyA = self.subscribe_topic(announce, topic_manager, 'Announcement')
        topicU, proxyU = self.subscribe_topic(user_updates, topic_manager, 'UserUpdates')
        servant.userUpdate = proxyU

        time.sleep(12)
        
        if len(servant.proxies) == 0:
            self.announceAuth(proxyA, authenticator_proxy, servant.id)
        else:
            authenticator = self.find_authenticator(servant)

            if authenticator != None:
                print("BulkUpdate from ", authenticator, "\n")
                authData = authenticator.bulkUpdate()
                servant.database.adminToken = authData.adminToken
                servant.database.currentUsers = authData.currentUsers
                servant.database.activeTokens = authData.activeTokens
                self.announceAuth(proxyA, authenticator_proxy, servant.id)

        broker.waitForShutdown()
        self.shutdownOnInterrupt()
        topicA.unsubscribe(proxyA)
        topicU.unsubscribe(proxyU)

        return 0
        
if __name__ == "__main__":
    server=Server()
    sys.exit(server.main(sys.argv))