from __future__ import annotations
from . import error
from datetime import datetime, timezone
from ldap3 import MODIFY_ADD, MODIFY_DELETE
from typing import TYPE_CHECKING
from re import sub as reSub
from json import dumps, loads



if (TYPE_CHECKING):
    from .kuisti import Kuisti



class User():

    def __init__(self, kuistiInstance: Kuisti, identifier: str, roles: list[str] = ["default"]) -> None:

        # Referenssi Kuisti-instanssiin Kuistiin liittyvien metodien ja muuttujien käyttöä varten.
        self.kuistiInstance = kuistiInstance
        self.logger = self.kuistiInstance.logger
        self.roles = [role.lower() for role in roles]

        #if (predefinedIdentifier):
        self.identifier = identifier
            #self.name = reSub(r'^CN=(.+?),.+$', r'\1', self.dn)

        #else:

        #    self.identifier = self.kuistiInstance.ldapConnection.formatToDitAttr(name, self.kuistiInstance.objDetectionConf["userNameFormatting"]).lower()
        
        userInfo = self.kuistiInstance.db.getUserInfo(self.identifier)

        if (userInfo):

            self.dn = userInfo["dn"]
            self.roles = userInfo["roles"]

        else:

            self.dn = self._getDn()

            if ((len(self.roles) == 1) and (self.roles[0] == "default")):
                self.roles = self._getRoles()


    def _getDn(self) -> str:

        return self.kuistiInstance.ldapConnection.getObjectDn(

            self.kuistiInstance.environmentConf["ldap"]["ditSearchBase"],
            f'(&(objectClass=person)({self.kuistiInstance.environmentConf["ldap"]["userDitAttr"]}={self.identifier}))'
            
        )
    

    def _getRoles(self) -> list[str]:

        roles = self.roles

        for roleDn in self.kuistiInstance.roleDnList:

            roleName = reSub(fr'^CN={self.kuistiInstance.rolePrefix}(.+?),.+$', r'\1', roleDn).lower()

            memberOfGroup = self.kuistiInstance.ldapConnection.checkGroupMembership(

                self.kuistiInstance.environmentConf["ldap"]["ditSearchBase"],
                roleDn,
                self.dn

            )
            
            if (memberOfGroup):
                roles.append(roleName.lower())

        return roles


    def addRoom(self, roomName: str) -> None:

        formattedRoomName = f'{self.kuistiInstance.roomPrefix}{roomName}'

        roomDn = self.kuistiInstance.ldapConnection.getObjectDn(

            self.kuistiInstance.environmentConf["ldap"]["ditSearchBase"],
            f'(&(objectClass=group)({self.kuistiInstance.environmentConf["ldap"]["roomDitAttr"]}={formattedRoomName}))'

        )

        if (not roomDn): raise error.KuistiNoRoomsFound(f'Huonetta {roomName} ei löydy hakemistopalvelimelta.')

        timestamp = datetime.now(timezone.utc).timestamp() * 1000
        roomInfo = self.kuistiInstance.db.addUserToRoom(self.identifier, roomName, roomDn, timestamp)
        self.kuistiInstance.roomEventQueue.put(roomInfo)

    
    def allowLogon(self, rooms: list[str]) -> None:
        
        for room in rooms:

            roomInfo = self.getRoomInfo(room)
            if (not roomInfo): raise error.KuistiUserNotInRoom

            # Lisää käyttäjä ryhmään, jos käyttäjä ei siellä vielä ole.
            alreadyInGroup = self.kuistiInstance.ldapConnection.checkGroupMembership(

                self.kuistiInstance.environmentConf["ldap"]["ditSearchBase"],
                roomInfo["roomDn"],
                self.dn

            )

            if (not(alreadyInGroup)):

                modificationSuccess = self.kuistiInstance.ldapConnection.modify(roomInfo["roomDn"], {"member": [(MODIFY_ADD, [self.dn])]})
                if (not(modificationSuccess)): raise error.KuistiLdapModificationError("Ryhmäjäsenyyksien muokkaus epäonnistui."); exit(1)

            self.kuistiInstance.db.updateRoomLogon(self.identifier, room, logonAllowed=True)


    def addFilter(self, roomName: str, timestamp: str, deviceName: str, deviceIp: str) -> None:

        for role in self.roles:

            renewalAmount = 0

            if ("renewalAmount" in self.kuistiInstance.firewall.filtersets[role].keys()):
                renewalAmount = self.kuistiInstance.firewall.filtersets[role]["renewalAmount"]

            for idx, filterConf in enumerate(self.kuistiInstance.firewall.filtersets[role]["filters"]):

                filterName = self.kuistiInstance.firewall.generateFilterName(self.identifier, roomName, deviceIp, role, idx)
                searchResult = self.kuistiInstance.firewall.searchFilter(filterName)

                if (searchResult.status_code == 200):

                    searchResultParsed = loads(searchResult.text)

                    # Luo uusi sääntö, jos sitä ei ole olemassa palomuurilla. Muutoin päivitä olemassa olevan säännön aikaleima.
                    if (len(searchResultParsed["rows"]) == 0):

                        newFilterInfo = self.kuistiInstance.db.addFilter(self.identifier, role, filterName, roomName, timestamp, deviceName, deviceIp, renewalAmount=renewalAmount, filterConf=dumps(filterConf))

                        self.kuistiInstance.firewall.createFilter(filterName, deviceIp, filterConf)
                        self.kuistiInstance.filterEventQueue.put(newFilterInfo)

                    else:

                        for row in searchResultParsed["rows"]:
                            if (not self.getFilterInfo(row["description"])):
                                self.kuistiInstance.db.addFilter(self.identifier, role, row["description"], roomName, timestamp, deviceName, deviceIp, renewalAmount=renewalAmount, filterConf=dumps(filterConf))

                            self.updateFilterTimestamp(row["description"], timestamp)

                else:
                    self.logger.error(f"{searchResult.text}")


    def updateFilterTimestamp(self, filterName: str, timestamp: str) -> None:

        updatedEntry = self.kuistiInstance.db.updateFilterTs(filterName, timestamp)

        if (timestamp == "paused"): return
        self.kuistiInstance.filterEventQueue.put(updatedEntry)


    def updateFilterInfo(self, filterName: str, updatedInfo: dict) -> dict:

        return self.kuistiInstance.db.updateFilterInfo(filterName, updatedInfo)


    def updateFilterAutolock(self, roomName: str, ipAddress: str, autoLocked: bool = True) -> None:

        for role in self.roles:
            for idx, _ in enumerate(self.kuistiInstance.firewall.filtersets[role]["filters"]):

                filterName = self.kuistiInstance.firewall.generateFilterName(self.identifier, roomName, ipAddress, role, idx)
                self.kuistiInstance.db.updateFilterAutolock(filterName, autoLocked)


    def updateRoomTimestamp(self, roomName: str, timestamp: str) -> None:

        updatedEntry = self.kuistiInstance.db.updateRoomTs(self.identifier, roomName, timestamp)

        if (timestamp == "paused"): return
        self.kuistiInstance.roomEventQueue.put(updatedEntry)


    def isFilterAutolocked(self, filterName: str) -> bool:

        try:
            ret = bool(self.kuistiInstance.db.getFilterInfo(self.identifier, filterName)[0]["autoLocked"])

        except IndexError:
            ret = False
        
        return ret

    
    def isInRoom(self, room: str = "any") -> bool:

        rooms = self.kuistiInstance.db.getUserAttendance(self.identifier)

        if (rooms and (room == "any")): return True

        for e in rooms:
            if (room == e["roomName"]): return True
        
        return False
        

    def isPresent(self) -> bool:

        isPresent = self.kuistiInstance.db.getUserInfo(self.identifier)
        
        if (isPresent): return True
        return False
    

    def getFilterInfo(self, filterName: str = "any") -> list[str]:

        return self.kuistiInstance.db.getFilterInfo(self.identifier, filterName)
    

    def searchFilter(self, roomName: str = "any", deviceName: str = "any", deviceIp: str = "any") -> list[dict]:

        return self.kuistiInstance.db.searchFilter(self.identifier, roomName, deviceName, deviceIp)
    

    def getRoomInfo(self, room: str = "any") -> dict | None:

        rooms = self.kuistiInstance.db.getUserAttendance(self.identifier)

        for e in rooms:
            if (room == e["roomName"]): return e

        return None
    

    def isLogonAllowed(self, forRoom: str) -> bool:

        try:
            return self.getRoomInfo(forRoom)["logonAllowed"]

        except KeyError:
            return False
    

    def getFilterTimestamp(self, filterName: str) -> str | None:
    
        filters = self.kuistiInstance.db.getFilterInfo(self.identifier, filterName)

        for e in filters:
            if (filterName == e["filterName"]): return e["timestamp"]

        return None


    def getRoomTimestamp(self, room: str) -> str | None:

        rooms = self.kuistiInstance.db.getUserAttendance(self.identifier)

        for e in rooms:
            if (room == e["roomName"]): return e["timestamp"]

        return None


    def removeFilter(self, ipAddress: str = "", forRoom: str = "", *, exactName: str | None = None) -> None:

        if (exactName):

            self.kuistiInstance.firewall.removeFilter(exactName)

            # Poista suodatussääntö tietokannasta.
            self.kuistiInstance.db.removeFilter(exactName)

        else:

            for role in self.roles:
                for idx, _ in enumerate(self.kuistiInstance.firewall.filtersets[role]):

                    filterNames = self.kuistiInstance.firewall.removeFilter(searchPhrase=f'{self.identifier} {ipAddress} {forRoom} {role}:{idx}')

                    for filterName in filterNames:
                        self.kuistiInstance.db.removeFilter(filterName)

                    #filterIpAddress = "any" if (len(ipAddress) == 0) else ipAddress
                    #filterRoom = "any" if (len(forRoom) == 0) else forRoom
                    #filters = self.searchFilter(filterRoom, deviceIp=filterIpAddress)

                    #if (filters):
                    #    for filterInfo in filters:

                            # Poista suodatussääntö tietokannasta.
                    #        self.kuistiInstance.db.removeFilter(filterInfo["filterName"])


    def removeRoom(self, roomName: str) -> None:

        formattedRoomName = f'{self.kuistiInstance.roomPrefix}{roomName}'

        roomDn = self.kuistiInstance.ldapConnection.getObjectDn(

            self.kuistiInstance.environmentConf["ldap"]["ditSearchBase"],
            f'(&(objectClass=group)({self.kuistiInstance.environmentConf["ldap"]["roomDitAttr"]}={formattedRoomName}))'

        )

        if (not roomDn): raise error.KuistiNoRoomsFound

        # Poista käyttäjän läsnäolomerkintä.
        self.kuistiInstance.db.removeUserFromRoom(self.identifier, roomName)


    def denyLogon(self, rooms: list[str]) -> None:

        for room in rooms:

            roomInfo = self.getRoomInfo(room)
            if (not roomInfo): raise error.KuistiUserNotInRoom

            userInGroup = self.kuistiInstance.ldapConnection.checkGroupMembership(

                self.kuistiInstance.environmentConf["ldap"]["ditSearchBase"],
                roomInfo["roomDn"],
                self.dn

            )

            if (userInGroup):
                modificationSuccess = self.kuistiInstance.ldapConnection.modify(roomInfo["roomDn"], {"member": [(MODIFY_DELETE, [self.dn])]})

                if (not(modificationSuccess)): raise ValueError("Ryhmäjäsenyyksien muokkaus epäonnistui."); exit(1)


    def pathTaken(self, forRoom: str) -> bool:

        count = 0
        routeToRoom = self.kuistiInstance.getRoute(forRoom)
        routeLen = len(routeToRoom)

        for rn in routeToRoom:
            if (self.isInRoom(rn)): count += 1

        return (count == routeLen)

    
    def activate(self):

        self.kuistiInstance.db.addUser(self.identifier, self.dn, self.roles)

    
    def deactivate(self):

        self.kuistiInstance.db.removeUser(self.identifier)