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
class AuthenticatorData:
    def __init__(self):
        self.adminToken = ""
        self.currentUsers = {}  # users: passwords
        self.activeTokens = {}  # users: tokens

class Authenticator:
    def refreshAuthorization(self, user, passwordHash, current=None):
        password = self.currentUsers.userPasswords.get(user)
        if password is None:
            raise IceFlix.Unauthorized()
        elif password == passwordHash:
            token = secrets.token_hex(16)
            self.userUpdate.newToken(user,token,self.id)
            time.sleep(120.0, self.revocations.revokeToken(token, self.id), args=[token, self.id])
        else:
            raise IceFlix.Unauthorized()
        return token

    def isAuthorized(self, userToken, current=None):
        if userToken in self.currentUsers.activeTokens:
            auth = True
        else:
            auth = False
        return auth

    def whois(self, userToken, current=None):
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized()
        else:
            return self.currentUsers.activeTokens.get(userToken)

    def isAdmin(self, adminToken, current=None):
        return self.adminToken == adminToken

    def addUser(self, user, passwordHash, adminToken, current=None):
        if self.currentUsers.get(user) or not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        self.currentUsers[user] = [{
            "token": secrets.token_hex(16),
            "passwordHash": passwordHash,
            "timestamp": time.time()
        }]

        with open(PATH_USERS, 'w') as file:
            json.dump(self.currentUsers, file)

        self.userUpdate.newUser(user, passwordHash, self.id)

    def removeUser(self, user, adminToken, current=None):
        if not self.currentUsers.get(user) or not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        self.currentUsers.pop(user)

        with open(PATH_USERS, 'w') as file:
            json.dump(self.currentUsers, file)

        self.userUpdate.removeUser(user, self.id)

    def bulkUpdate(self, current=None):
        auth_data = IceFlix.AuthenticatorData()
        auth_data.adminToken = self.adminToken
        auth_data.currentUsers = {user: data[0]['passwordHash'] for user, data in self.currentUsers.items()}
        auth_data.activeTokens = {user: data[0]['token'] for user, data in self.currentUsers.items() if data[0]['token']}
        
        return auth_data

# Interface to be used in the topic for user related updates
class UserUpdate:
    def __init__(self, authenticator):
        self.authenticator = IceFlix.AuthenticatorPrx.uncheckedCast(Authenticator)

    def newToken(self, user, token, serviceId, current=None):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print('New token for ', user, ' received from', serviceId)
            self.authenticator.currentUsers.activeTokens[token] = user
        else:
            print('New token for ', user, ' from', serviceId, ' ignored')

    def revokeToken(self, token, serviceId, current=None):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print("Token ", token, " revoked from ", serviceId)
            self.authenticator.currentUsers.activeTokens.pop(token)
        elif serviceId == self.authenticator.id:
            print('Token ', token, ' timed out')
            self.authenticator.currentUsers.activeTokens.pop(token)
        else:
            print('Token ', token, ' from', serviceId, ' ignored')

    def newUser(self, user, passwordHash, serviceId, current=None):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print('New user for ', user, ' received from', serviceId)
            self.authenticator.currentUsers[user] = passwordHash
        else:
            print('New user for ', user, ' from', serviceId, ' ignored')

    def removeUser(self, user, serviceId, current=None):
        if serviceId != self.authenticator.id and serviceId in self.authenticator.proxies:
            print('User ', user, ' removed from ', serviceId)
            self.authenticator.currentUsers.pop(user)
        else:
            print('User ', user, ' from', serviceId, ' ignored')

class Announcement:
    def __init__(self, authenticator):
        self.authenticator = IceFlix.AuthenticatorPrx.uncheckedCast(Authenticator)

    def announce(self, service, serviceId, current=None):
        if serviceId != self.authenticator.id and serviceId not in self.authenticator.proxies:
            if service.ice_isA('::IceFlix::Authenticator'):
                self.authenticator.proxies[serviceId] = IceFlix.AuthenticatorPrx.uncheckedCast(service)
            elif service.ice_isA('::IceFlix::Main'):
                self.authenticator.proxies[serviceId] = IceFlix.MainPrx.uncheckedCast(service)
        else:
            print('Service: ', service, ' ignored')

class Server(Ice.Application):
    def subscribe_topic(topic_manager, topic_name, servant_type, adapter, proxy_name, current=None):
        servant = servant_type()
        proxy = adapter.addWithUUID(servant)
        try:
            topic = topic_manager.create(topic_name)
        except IceStorm.TopicExists:
            topic = topic_manager.retrieve(topic_name)
        topic.subscribeAndGetPublisher({}, proxy)
        setattr(servant, proxy_name, IceFlix.uncheckedCast(proxy))
        return topic
        
    def announceAuth(self, authenticator_proxy, servant, topic, current=None):
        while True:
            publisher = topic.getPublisher()
            servant.announcement = IceFlix.AnnouncementPrx.uncheckedCast(publisher)
            servant.announcement.announce(authenticator_proxy,servant.id)
            time.sleep(random.randint(1,10), self.announceAuth(authenticator_proxy, servant, topic))

    def find_authenticator_main(authenticator):
        auth, main = None
        for key in authenticator.proxies:
            value = authenticator.proxies.get(key)[0]["service"]
            if(IceFlix.AuthenticatorPrx.checkedCast(value)):
                auth = IceFlix.AuthenticatorPrx.checkedCast(value)
            elif(IceFlix.MainPrx.checkedCast(value)):
                main = IceFlix.MainPrx.checkedCast(value)
        return auth, main

    def run(self, args):
        tester_proxy = "IceStorm.TopicManager"
        broker = self.communicator()

        topic_manager = IceStorm.TopicManagerPrx.checkedCast(broker.stringToProxy(tester_proxy))

        adminToken = broker.getProperties().getProperty('adminToken')
        servant = Authenticator(adminToken)
        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter", "tcp")
        authenticator_proxy = adapter.add(servant, broker.stringToIdentity("authenticator"))
        adapter.activate()

        topic = self.subscribe_topic(topic_manager, 'Announcements', Announcement, adapter, 'discovery_publisher')
        topic_updates = self.subscribe_topic(topic_manager, 'UserUpdates', UserUpdate, adapter, 'updates_publisher')
        
        time.sleep(12)
        if len(servant.proxies) == 0:
            self.announceAuth(authenticator_proxy, servant, topic, topic_updates)
        else:
            authenticator, main = self.find_authenticator_main(servant)

            if main == None:
                print("No main found, shutting down")
                self.communicator().shutdown()
                return
            
            if authenticator != None:
                print("BulkUpdate from", authenticator, "\n")
                authData = authenticator.bulkUpdate()
                servant.adminToken = authData.adminToken
                servant.currentUsers = authData.currentUsers
                servant.activeTokens = authData.activeTokens
                self.announceAuth()

        broker.waitForShutdown()
        self.shutdownOnInterrupt()
        
        return 0
        
if __name__ == "__main__":
    server=Server()
    sys.exit(server.main(sys.argv))