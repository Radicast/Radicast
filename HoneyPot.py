import argparse
import os
import json
from twisted.cred import checkers, portal
from twisted.conch import avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, transport, keys, session
from twisted.conch.insults import insults
from twisted.internet import reactor, defer
from twisted.python import log
import sys
import datetime
import pygeoip

# Setup logging
log.startLogging(sys.stdout)
LOG_FILE = "honeypot.log"

# GeoIP setup
geoip = pygeoip.GeoIP('GeoLiteCity.dat')

# Define the avatar class
class HoneyPotAvatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({b'session': session.SSHSession})

    def openShell(self, protocol):
        serverProtocol = insults.ServerProtocol(HoneyPotProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd):
        raise NotImplementedError

    def closed(self):
        pass

class HoneyPotProtocol(recvline.HistoricRecvLine):
    def __init__(self, user):
        self.user = user

    def connectionMade(self):
        self.client_ip = self.terminal.transport.getPeer().host
        geo_data = geoip.record_by_addr(self.client_ip) or {}
        location_info = {
            "ip": self.client_ip,
            "country": geo_data.get("country_name", "N/A"),
            "city": geo_data.get("city", "N/A"),
            "latitude": geo_data.get("latitude", "N/A"),
            "longitude": geo_data.get("longitude", "N/A"),
        }

        log_message = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "connection_made",
            "username": self.user.username,
            "location": location_info,
        }
        self.log_event(log_message)
        
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write("Welcome to the honeypot, %s!\n" % (self.user.username,))
        self.terminal.write("root@honeypot:~# ")

    def lineReceived(self, line):
        log_message = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "command_received",
            "username": self.user.username,
            "command": line.decode('utf-8'),
            "client_ip": self.client_ip,
        }
        self.log_event(log_message)
        
        self.terminal.write("Command not found: %s\n" % (line,))
        self.terminal.write("root@honeypot:~# ")

    def log_event(self, message):
        with open(LOG_FILE, 'a') as log_file:
            log_file.write(json.dumps(message) + '\n')

class HoneyPotRealm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], HoneyPotAvatar(avatarId), lambda: None

def getRSAKeys():
    with open('ssh_host_rsa_key', 'rb') as privateBlobFile:
        privateBlob = privateBlobFile.read()
    with open('ssh_host_rsa_key.pub', 'rb') as publicBlobFile:
        publicBlob = publicBlobFile.read()
    return keys.Key.fromString(privateBlob), keys.Key.fromString(publicBlob)

class HoneyPotFactory(factory.SSHFactory):
    def __init__(self):
        self.portal = portal.Portal(HoneyPotRealm())
        self.portal.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(test='test'))

    publicKeys = {
        b'ssh-rsa': getRSAKeys()[1]
    }
    privateKeys = {
        b'ssh-rsa': getRSAKeys()[0]
    }
    services = {
        b'ssh-userauth': userauth.SSHUserAuthServer,
        b'ssh-connection': connection.SSHConnection
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple SSH Honeypot")
    parser.add_argument("--port", type=int, default=2222, help="Port to run the honeypot on")
    parser.add_argument("--user", type=str, default="test", help="Username for the honeypot login")
    parser.add_argument("--password", type=str, default="test", help="Password for the honeypot login")
    args = parser.parse_args()

    # Update checker with provided username and password
    honey_factory = HoneyPotFactory()
    honey_factory.portal.checkers[0].addUser(args.user.encode(), args.password.encode())

    reactor.listenTCP(args.port, honey_factory)
    print(f"Honeypot running on port {args.port}")
    reactor.run()
