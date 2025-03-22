from __future__ import annotations
from .ldap import LdapConnection
from .listeners.eventlistener import EventListener
from .listeners.extsystemlistener import ExtSystemListener
from .databases.base import Database
from .databases.dict import Dict
from .loghandlers.base import LogHandler
from .user import User
from .firewalls.base import Firewall
from . import error, krb, log
from socket import gethostbyname, gethostbyaddr, herror
from multiprocessing import Manager
from threading import Thread
from typing import Generator
from ldap3 import RESTARTABLE, KERBEROS, SASL
from datetime import datetime, timezone
from re import sub as reSub
from re import match as reMatch
from json import load, loads, dumps
from ipaddress import ip_network, ip_address
from getpass import getpass
from pathlib import Path
import logging, logging.config, os



logging.config.dictConfig(log.LOGGING_BASE_CONF)

# Määritä käytettävä krb5-konfiguraatio ja keytab.
KRB5_CONFIG_PATH = str(Path(Path.cwd() / Path("kuisti_krb5.conf")))
KRB5_KEYTAB_PATH = str(Path(Path.cwd() / Path("kuisti_krb5.keytab")))



class Kuisti():

    def __init__(self, logConfPath: str, environmentConfPath: str, db: type[Database] = Dict(database={})):

        # Lataa konfiguraatiot muistiin.
        self.logConf, self.environmentConf = self.loadConfig([logConfPath, environmentConfPath])
        self.roomPrefix = self.environmentConf["ldap"]["roomPrefix"]
        self.rolePrefix = self.environmentConf["ldap"]["rolePrefix"]
        self.roomDitAttr = self.environmentConf["ldap"]["roomDitAttr"]
        self.roleDitAttr = self.environmentConf["ldap"]["roleDitAttr"]
        self.userDitAttr = self.environmentConf["ldap"]["userDitAttr"]
        self.extSystemLog = log.LOGGING_BASE_CONF["handlers"]["extSystemLog"]["filename"]
        self.implicitTrustAtBoot = self.environmentConf["common"]["implicitTrustAtBoot"]

        self.logger = logging.getLogger("kuisti")
        self.roomTimeouts = dict((k.lower(), v) for k, v in list(self.environmentConf["roomTimeouts"].items()))
        self._routes = dict((k.lower(), v) for k, v in list(self.environmentConf["routes"].items()))
        self._networks = dict((k.lower(), v) for k, v in list(self.environmentConf["networks"].items()))
        
        # Alusta DB.
        self.db = db

        self.serviceUser = self.environmentConf["ldap"]["serviceUser"]
        self.domain = self.environmentConf["ldap"]["domain"]

        # Aseta env-muuttuja kerb5:n konfiguraation käyttöä varten.
        os.environ["KRB5_CONFIG"] = KRB5_CONFIG_PATH


    def followFile(self, filePath: str) -> Generator[str]:

        with open(filePath, 'r') as file:
            file.seek(0, 2) # Aloitetaan tiedoston luku viimeiseltä riviltä (0 = offset, 2 = from_what, eli EOF).

            while (True):

                line = file.readline()

                if (not line):
                    continue

                else:
                    yield line


    def start(self, logHandler: type[LogHandler], firewall: type[Firewall]) -> None:

        self.logHandler = logHandler
        self.firewall = firewall

        # Luo krb5-konfiguraatio ja keytab-tiedosto, jos niitä ei vielä ole.
        if (not Path(KRB5_CONFIG_PATH).exists()):
            self.generateKrbConf(KRB5_CONFIG_PATH, self.domain)

        if (not Path(KRB5_KEYTAB_PATH).exists()):
            self.generateKrbKeytab(KRB5_KEYTAB_PATH)

        # Luo LDAP-yhteys hakemistopalvelimelle.
        self.ldapConnection = self._connectLdap()

        # Luodaan tarkastusjonot Inspector-säiettä varten.
        self._manager = Manager()
        self.roomEventQueue = self._manager.Queue()
        self.filterEventQueue = self._manager.Queue()

        # Luodaan tarvittavat komponentit.
        self.inspector = Inspector(self, self.firewall)
        self.eventListener = EventListener(self.firewall, self.inspector, self)
        self.extSystemListener = ExtSystemListener(self)

        #self._lock = Lock()
        self._threadLogHandler = Thread(target=self._logHandlerWorker)
        self._threadEventListener = Thread(target=self.eventListener.start)
        self._threadInspector = Thread(target=self.inspector.worker)
        self._threadExtSystemListener = Thread(target=self.extSystemListener.start)

        # Tarkasta paikan päällä olevat käyttäjät ohjelman käynnistyessä.
        self.logger.info("Aloitetaan ohjelman alustus...")
        self.roleDnList = self._getRoleDn()
        self._checkActiveUsers()
        if (self.firewall): self.inspector.checkFilters()
        self.logger.info("Alustus valmis.")

        self._threadEventListener.start()
        self._threadInspector.start()
        self._threadLogHandler.start()
        self.extSystemListener.start()


    def loadConfig(self, configFiles: list[str]) -> None:

        dicts = []

        for fileName in configFiles:
            with open(fileName, "r") as file:

                dicts.append(load(file))

        if (len(dicts) == 1):
            return dicts[0]

        return dicts


    def _logHandlerWorker(self) -> None:

        while (True):

            # Aloitetaan lokitiedoston seuraaminen.
            for line in self.followFile(self.extSystemLog):

                logEntry = self.logHandler.parseLog(line=line)
                self.logHandler.handleLog(logEntry=logEntry)


    def _getRoleDn(self) -> list[str]:

        return self.ldapConnection.getObjectDn(

            self.environmentConf["ldap"]["ditSearchBase"],
            f"(&(objectClass=group)({self.roleDitAttr}={self.rolePrefix}*))",
            returnAll=True

        )


    def _checkActiveUsers(self):

        roomDnList = self.ldapConnection.getObjectDn(

                    self.environmentConf["ldap"]["ditSearchBase"],
                    f"(&(objectClass=group)({self.roomDitAttr}={self.roomPrefix}*))",
                    returnAll=True

        )

        # Sulje ohjelma, jos yhtäkään huoneryhmää ei löydetä.
        if (roomDnList is None):

            errorMsg = "Huoneryhmiä ei löytynyt hakemistopalvelimelta. Tarkasta, että huoneryhmät ovat konfiguroitu oikein."

            self.logger.error(errorMsg)
            raise error.KuistiNoRoomsFound(errorMsg)
            

        for roomDn in roomDnList:

            roomName = reSub(fr'^CN={self.roomPrefix}(.+?),.+$', r'\1', roomDn).lower()

            members = self.ldapConnection.checkGroupMembership(

                self.environmentConf["ldap"]["ditSearchBase"],
                roomDn,
                getAllMembers=True

            )
            
            if (not(members)): continue
        
            #members = [reSub(r'^CN=(.+?),.+$', r'\1', member) for member in members]
            #members = [reSub(r'^((?:.+?)\s*(?:.+?)?)$', r'\1', member) for member in members]

            for member in members:

                userId = self.ldapConnection.getObjectAttr(

                    self.environmentConf["ldap"]["ditSearchBase"],
                    f"(&(objectClass=user)(distinguishedName={member}))",
                    attributes=[f'{self.userDitAttr}']

                )[self.userDitAttr][0]

                newUser = User(self, userId)
                newUser.activate()
                newUser.addRoom(roomName)
                routeToRoom = self.getRoute(roomName)
                self.logger.info(f'Lisätty käyttäjä "{newUser.identifier}" huoneeseen "{roomName}".')

                if (routeToRoom):
                    if (self.implicitTrustAtBoot or newUser.pathTaken(roomName)):

                        for name in routeToRoom[:-1]:

                            newUser.addRoom(name)
                            self.logger.info(f'Lisätty käyttäjä "{newUser.identifier}" huoneeseen "{name}".')

                        newUser.allowLogon([roomName])
                        self.logger.info(f'Sallittu käyttäjän "{newUser.identifier}" kirjautuminen huoneen "{roomName}" työasemille.')


    def getRoute(self, forRoom: str = "any") -> dict | list[str]:

        if (forRoom == "any"): return self._routes

        try:
            return self._routes[forRoom.lower()]

        except KeyError:
            return []


    def generateKrbConf(self, confPath: str, domain: str) -> None:

        with open(confPath, 'w') as fp:

            conf = f"""[libdefaults]
default_realm = {domain.upper()}
kdc_timesync = 1

[realms]
    {domain.upper()} = {{

        kdc = {domain.lower()}
        default_domain = {domain.lower()}

    }}

[domain_realm]
    .{domain.lower()} = {domain.upper()}
    {domain.lower()} = {domain.upper()}

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    default = FILE:/var/log/krb5lib.log
"""
            fp.write(conf)


    def generateKrbKeytab(self, keytabPath: str) -> None:

        password = getpass(f'Palvelukäyttäjän "{self.serviceUser}" salasana: ')
        confirm = getpass("Kirjoita salasana uudelleen: ")

        if (password != confirm):
            raise RuntimeError("Salasanat eivät täsmää.")
        
        krb.create_keytab(keytabPath, f'{self.serviceUser}@{self.domain.upper()}', password)
        

    def getRoomName(self, ipAddress: str) -> str | None:

        for roomName, network in self._networks.items():

            if (ip_address(ipAddress) in ip_network(network)): return roomName

        return None
    

    def getIpNetwork(self, forRoom: str) -> str:

        try:
            return self._networks[forRoom]
        
        except:
            raise error.KuistiNetworkNotFound(f'Huoneen {forRoom} verkkoa ei ole määritetty.')
        
    
    def _connectLdap(self) -> LdapConnection:

        ldapConnection = LdapConnection(

                self,
                domain=self.environmentConf["ldap"]["domain"],
                client_strategy=RESTARTABLE,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                user=self.environmentConf["ldap"]["serviceUser"],
                auto_bind=True,
                receive_timeout=5

        )

        ldapConnection.start_tls()

        return ldapConnection



class Inspector():

    def __init__(self, kuistiInstance: Kuisti, firewall: Firewall) -> None:

        self.kuistiInstance = kuistiInstance
        self.logger = logging.getLogger("inspector")
        self.firewall = firewall


    # Tarkasta ohjelman käynnistyessä, onko palomuurilla olemassa suodatussääntöjä käyttäjiä varten ja merkkaa ne tietokantaan.
    def checkFilters(self):

        hostnames = {}

        for kuistiFilter in loads(self.firewall.searchFilter("kuisti_").text)["rows"]:

            filterExists = False
            filterInfo = self.firewall.getInfoFromName(kuistiFilter["description"])
            currentTime = datetime.now(timezone.utc).timestamp() * 1000

            newUser = User(self.kuistiInstance, filterInfo["userId"])
            ipAddress = filterInfo["ipAddress"]
            roomName = self.kuistiInstance.getRoomName(ipAddress).lower()
            routeToRoom = self.kuistiInstance.getRoute(roomName)

            if (not newUser.isPresent()):
                newUser.activate()

            if ((newUser.isPresent()) and (not newUser.isInRoom(roomName))):

                newUser.addRoom(roomName)
                self.logger.info(f'Lisätty käyttäjä "{newUser.identifier}" huoneeseen "{roomName}".')

            if (routeToRoom and not newUser.isLogonAllowed(roomName)):
                if (self.kuistiInstance.implicitTrustAtBoot or newUser.pathTaken(roomName)):

                    for name in routeToRoom[:-1]:

                        newUser.addRoom(name)
                        self.logger.info(f'Lisätty käyttäjä "{newUser.identifier}" huoneeseen "{name}".')

                    newUser.allowLogon([roomName])
                    self.logger.info(f'Sallittu kirjautuminen käyttäjälle "{newUser.identifier}" huoneessa "{roomName}".')

            if (newUser.getFilterInfo(kuistiFilter["description"])):

                filterExists = True
                break

            if ((newUser.isPresent()) and (newUser.isInRoom(roomName)) and (not filterExists)):
                
                if (ipAddress not in hostnames.keys()):

                    try:
                        hostnames[ipAddress] = gethostbyaddr(ipAddress)

                    except herror:
                        hostnames[ipAddress] = ipAddress

                newUser.addFilter(roomName, currentTime, hostnames[ipAddress], ipAddress)
                newUser.updateFilterAutolock(dumps(filterInfo), ipAddress, autoLocked=True)


    def worker(self) -> None:

        pendingRoomEvent = None
        pendingFilterEvent = None
        roomEventQueue = []
        filterEventQueue = []

        while (True):

            currentTime = datetime.now(timezone.utc).timestamp() * 1000

            # Huonetapahtumien käsittely.
            try:

                # Korvataan myöhemmin PriorityQueuella.
                newEvent = self.kuistiInstance.roomEventQueue.get_nowait()

                if (self.kuistiInstance.roomTimeouts[newEvent["roomName"]] != 0):

                    newEvent["expiryTime"] = int(newEvent["timestamp"]) + int(self.kuistiInstance.roomTimeouts[newEvent["roomName"]]*60*1000)
                    roomEventQueue.append(newEvent)
                    roomEventQueue.sort(key=lambda event: event["expiryTime"])

            except:
                pass

            #if (int(self.kuistiInstance.timeoutRoom) != 0):

            pendingRoomEvent = roomEventQueue[0] if (len(roomEventQueue) > 0) else None

            if (pendingRoomEvent):
                if (currentTime > pendingRoomEvent["expiryTime"]):

                    self._handleRoomEvent(pendingRoomEvent)
                    pendingRoomEvent = None
                    roomEventQueue.pop(0)

            # Suodatussääntöihin liittyvien tapahtumien käsittely.
            if (not self.firewall): continue

            try:

                newEvent = self.kuistiInstance.filterEventQueue.get_nowait()

                if (self.firewall.filtersets[newEvent["role"]]["timeout"] != 0):
                    newEvent["expiryTime"] = int(newEvent["timestamp"]) + int(self.firewall.filtersets[newEvent["role"]]["timeout"]*60*1000)
                    filterEventQueue.append(newEvent)
                    filterEventQueue.sort(key=lambda event: event["expiryTime"])

            except:
                pass

            pendingFilterEvent = filterEventQueue[0] if (len(filterEventQueue) > 0) else None

            if (pendingFilterEvent):
                if (currentTime > pendingFilterEvent["expiryTime"]):

                    self._handleFilterEvent(pendingFilterEvent)
                    pendingFilterEvent = None
                    filterEventQueue.pop(0)
                

    def _handleFilterEvent(self, event: dict) -> None:

        userObj = User(self.kuistiInstance, event["userId"])
        filterName = event["filterName"]
        filterInfo = userObj.getFilterInfo(filterName)
        filterIdx = self.firewall.getInfoFromName(filterName)["filterIdx"]
        deviceIp = event["deviceIp"]
        #deviceName = event["deviceName"]
        roomName = event["roomName"]
        userRole = event["role"]

        if (not filterInfo): return
        filterInfo = filterInfo[0]

        if (filterInfo["timestamp"] == "paused"): return

        # Jos sääntö on poistettu tai säännön aikaleima on päivitetty, lopeta käsittely.
        if (int(filterInfo["timestamp"]) > int(event["timestamp"])): return

        try:
            renewalAmount = filterInfo["renewalAmount"]

            if (renewalAmount == 0): raise RuntimeError

            for serviceAddr, servicePort in self.firewall.filtersets[event["role"]]["monitoredServices"].items():

                sessionInProgress = False
                states = self.firewall.getStates(deviceIp, loads(filterInfo["filterConf"]), returnValues=['dst_port', 'dst_addr'])
                serviceAddr = gethostbyname(serviceAddr) if (not reMatch(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$', serviceAddr)) else serviceAddr

                for state in states:

                    portMatches = True if (int(servicePort) == 0) else (int(state['dst_port']) == int(servicePort))

                    # Päivitä huoneen ja sääntöjen aikaleimat, jos johonkin monitoroituun palveluun linkitetty sessio on käynnissä.
                    if (portMatches and (state['dst_addr'] == serviceAddr)):

                        currentTime = datetime.now(timezone.utc).timestamp() * 1000
                        userObj.updateFilterTimestamp(filterName, currentTime)
                        sessionInProgress = True

                        break

                if (sessionInProgress):
                    
                    userObj.updateFilterInfo(filterName, {"renewalAmount": renewalAmount - 1})
                    routeToRoom = self.kuistiInstance.getRoute(roomName)

                    if (routeToRoom):
                        for name in routeToRoom:
                            userObj.updateRoomTimestamp(name, currentTime)

                    return

        except:
            pass

        #if (not self.firewall.filtersets[event["role"]]["timeoutEnabled"]): return

        self.logger.info(f'Poistetaan sääntö "{filterName}" aikakatkaisun takia.')
        userObj.removeFilter(exactName=filterName)


    def _handleRoomEvent(self, event: dict) -> None:
        
        userObj = User(self.kuistiInstance, event["userId"])
        roomName = event["roomName"]
        roomTs = userObj.getRoomTimestamp(roomName)

        if (not roomTs): return
        if (roomTs == "paused"): return

        # Jos huoneen aikaleima on päivitetty, lopeta käsittely.
        if (int(roomTs) > int(event["timestamp"])): return

        if (userObj.isInRoom(roomName)):

            routeToRoom = self.kuistiInstance.getRoute(roomName)
            if (routeToRoom):

                self.logger.info(f'Estetään kirjautuminen huoneen "{roomName}" työasemille käyttäjältä "{userObj.identifier}" aikakatkaisun takia.')
                userObj.denyLogon([roomName])

                if (self.firewall):
                    self.logger.info(f'Poistetaan käyttäjän "{userObj.identifier}" suodatussäännöt huoneen "{roomName}" laitteilta aikakatkaisun takia.')

                    deviceIps = []
                    
                    for filterInfo in userObj.searchFilter(roomName):
                        if (filterInfo["deviceIp"] not in deviceIps): deviceIps.append(filterInfo["deviceIp"])

                    for ipAddress in deviceIps: userObj.removeFilter(ipAddress, roomName)

            else:
                            
                for name, route in self.kuistiInstance.getRoute("any").items():
                    if ((roomName in route) and userObj.isInRoom(name)):

                        userObj.denyLogon([name])
                        self.logger.info(f'Estetty kirjautuminen huoneen "{name}" työasemille käyttäjältä "{userObj.identifier}" huoneen "{roomName}" aikakatkaisun takia.')

                        if (self.kuistiInstance.firewall):

                            userObj.removeFilter(forRoom=name)
                            self.logger.info(f'Poistetaan käyttäjän "{userObj.identifier}" suodatussäännöt huoneen "{name}" laitteilta aikakatkaisun takia.')
                        
                        for rn in route:
                            if (rn == roomName): continue

                            try:

                                userObj.removeRoom(rn)
                                self.logger.info(f'Poistettu käyttäjä "{userObj.identifier}" huoneesta "{rn}".')

                            except error.KuistiNoRoomsFound as err:
                                self.logger.warning(err)

            self.logger.info(f'Poistetaan käyttäjä "{userObj.identifier}" huoneesta "{roomName}" aikakatkaisun takia.')
            userObj.removeRoom(roomName)

        if (userObj.isPresent() and not userObj.isInRoom("any")):

            if (self.firewall): userObj.removeFilter()
            userObj.deactivate()


    def updateTimeout(self, userObj: User, ipAddress: str, *, timeoutType: str = "room", roomName: str = "any", paused: bool = False) -> None:
    
        if (not roomName):
            roomName = self.kuistiInstance.getRoomName(ipAddress)

        if (self.firewall and (timeoutType == 'rule')):

            for role in userObj.roles:
                for idx, _ in enumerate(self.firewall.filtersets[role]["filters"]):

                    filterName = self.kuistiInstance.firewall.generateFilterName(userObj.identifier, roomName, ipAddress, role, idx)
                    filterTimestamp = userObj.getFilterTimestamp(filterName)

                    if (not filterTimestamp): continue

                    if (paused and (filterTimestamp != "paused")):

                        userObj.updateFilterTimestamp(filterName, "paused")
                        self.logger.info(f'Pysäytetty käyttäjän "{userObj.identifier}" suodatussäännön "{filterName}" aikakatkaisu.')

                    elif ((not paused) and (filterTimestamp == "paused")):

                        userObj.updateFilterTimestamp(filterName, datetime.now(timezone.utc).timestamp() * 1000)
                        self.logger.info(f'Resetoitu käyttäjän "{userObj.identifier}" suodatussäännön "{filterName}" aikakatkaisu.')

        elif (timeoutType == 'room'):

            if (not userObj.isInRoom(roomName)): return

            roomTimestamp = userObj.getRoomTimestamp(roomName)

            if (paused and (roomTimestamp != "paused")):

                userObj.updateRoomTimestamp(roomName, "paused")
                self.logger.info(f'Pysäytetty käyttäjän "{userObj.identifier}" tilan "{roomName}" aikakatkaisu.')

            elif ((not paused) and (roomTimestamp == "paused")):

                userObj.updateRoomTimestamp(roomName, datetime.now(timezone.utc).timestamp() * 1000)
                self.logger.info(f'Resetoitu käyttäjän "{userObj.identifier}" tilan "{roomName}" aikakatkaisu.')

        else:
            self.logger.error('Määritä timeoutType funktiokutsuun (rule/room).')