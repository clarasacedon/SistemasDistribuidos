#!/usr/bin/env python3

import datetime
import logging
import sys
import Ice
import IceFlix
import IceStorm
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

class Server(Ice.Application):
    def subscribe_topic(topic_manager, topic_name, servant_type, adapter, proxy_name):
        servant = servant_type()
        proxy = adapter.addWithUUID(servant)
        try:
            topic = topic_manager.create(topic_name)
        except IceStorm.TopicExists:
            topic = topic_manager.retrieve(topic_name)
        topic.subscribeAndGetPublisher({}, proxy)
        setattr(servant, proxy_name, IceFlix.uncheckedCast(proxy))
        return topic
        
    def announceAuth(self, authenticator_proxy, servant, topic):
        while True:
            publisher = topic.getPublisher()
            servant.announcement = IceFlix.AnnouncementPrx.uncheckedCast(publisher)
            servant.announcement.announce(authenticator_proxy,servant.id)
            time.sleep(10)

    def wait_and_announce(self, authenticator_proxy, auth:Authenticator, topic, topic_updates):
        print("Waiting for other services to be announced...")
        t = threading.Thread(target=self.announceAuth,args=(authenticator_proxy, auth, topic))
        t.daemon = True
        t.start()

        print("Making the announcement...")
        t = threading.Thread(target=Announcement.announce,args=(authenticator_proxy, auth, topic))
        t.daemon = True
        t.start()

    def run(self, args):
        tester_proxy = "IceStorm.TopicManager"
        broker = self.communicator()

        topic_manager = IceStorm.TopicManagerPrx.checkedCast(broker.stringToProxy(tester_proxy))

        adminToken = broker.getProperties().getProperty('AdminToken')
        servant = Authenticator(adminToken)
        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter", "tcp")
        authenticator_proxy = adapter.add(servant, broker.stringToIdentity("authenticator"))
        adapter.activate()

        topic = self.subscribe_topic(topic_manager, 'Announcements', Announcement, adapter, 'discovery_publisher')
        topic_updates = self.subscribe_topic(topic_manager, 'UserUpdates', UserUpdate, adapter, 'updates_publisher')

        timer = threading.Timer(10, self.wait_and_announce(authenticator_proxy, servant, topic, topic_updates), 
                                args=[topic, topic_updates])
        timer.daemon = True
        timer.start()

        print("PRUEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        broker.waitForShutdown()
        self.shutdownOnInterrupt()
        
        return 0
        
if __name__ == "__main__":
    server=Server()
    sys.exit(server.main(sys.argv))