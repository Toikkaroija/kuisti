from .base import Database



class Dict(Database):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.database["activeUsers"] = []
        self.database["rooms"] = []
        self.database["filters"] = []


    @Database.queue
    def addUser(self, userId: str, dn: str, roles: list[str]) -> None:
        
        self.database["activeUsers"].append({"userId": userId, "dn": dn, "roles": roles})

    
    @Database.queue
    def addFilter(self, userId: str, role: str, filterName: str, roomName: str, timestamp: str, deviceName: str, deviceIp: str, autoLocked: bool = False, renewalAmount: int = 0, filterConf: str = "") -> dict:

        newFilter = {"userId": userId, "role": role, "filterName": filterName, "roomName": roomName, "deviceName": deviceName, "deviceIp": deviceIp, "timestamp": timestamp, "autoLocked": autoLocked, "renewalAmount": renewalAmount, "filterConf": filterConf}
        self.database["filters"].append(newFilter)

        return newFilter
    

    @Database.queue
    def addUserToRoom(self, userId: str, roomName: str, roomDn: str, timestamp: str, logonAllowed: bool = False) -> dict:

        newRoomEntry = {"userId": userId, "roomName": roomName, "roomDn": roomDn, "timestamp": timestamp, "logonAllowed": logonAllowed}
        self.database["rooms"].append(newRoomEntry)

        return newRoomEntry
    

    @Database.queue
    def getUserInfo(self, userId: str) -> dict | None:

        for e in self.database["activeUsers"]:
            if (userId == e["userId"]):
                return e
        
        return None


    @Database.queue
    def getFilterInfo(self, userId: str = "any", filterName: str = "any") -> list[dict]:

        filters = []

        for e in self.database["filters"]:
            if ((userId == "any") or (userId == e["userId"])):
                if ((filterName == "any") or (filterName == e["filterName"])):
                    filters.append(e)

        return filters
    

    @Database.queue
    def searchFilter(self, userId: str, roomName: str = "any", deviceName: str = "any", deviceIp: str = "any") -> list[dict]:

        filters = []

        for e in self.database["filters"]:
            if (userId == e["userId"]):
                if ((roomName == e["roomName"]) or (roomName == "any")):
                    if ((deviceName == e["deviceName"]) or (deviceName == "any")):
                        if ((deviceIp == e["deviceIp"]) or (deviceIp == "any")):
                            filters.append(e)

        return filters
    

    @Database.queue
    def getUserAttendance(self, userId: str, room: str = "any") -> list[dict]:

        rooms = []

        for e in self.database["rooms"]:
            if (userId == e["userId"]):
                if ((room == "any") or (room == e["roomName"])):
                    rooms.append(e)

        return rooms
    

    @Database.queue
    def removeFilter(self, filterName: str) -> None:

        for e in enumerate(self.database["filters"]):
            if (filterName == e[1]["filterName"]):

                self.database["filters"].pop(e[0])
                return


    @Database.queue
    def removeUser(self, userId: str) -> None:

        for e in enumerate(self.database["activeUsers"]):
            if (userId == e[1]["userId"]):

                self.database["activeUsers"].pop(e[0])
                return
            

    @Database.queue
    def removeUserFromRoom(self, userId: str, roomName: str) -> None:

        for e in enumerate(self.database["rooms"]):
            if (userId == e[1]["userId"] and roomName == e[1]["roomName"]):

                self.database["rooms"].pop(e[0])
                return
            

    @Database.queue
    def updateFilterAutolock(self, filterName: str, autoLocked: bool = True) -> None:

        for e in enumerate(self.database["filters"]):
            if (filterName == e[1]["filterName"]):

                self.database["filters"][e[0]]["autoLocked"] = autoLocked
                return
    

    @Database.queue
    def updateFilterTs(self, filterName: str, timestamp: str) -> dict:

        for e in enumerate(self.database["filters"]):
            if (filterName == e[1]["filterName"]):

                self.database["filters"][e[0]]["timestamp"] = timestamp
                return self.database["filters"][e[0]]
            

    @Database.queue
    def updateFilterInfo(self, filterName: str, updatedInfo: dict) -> dict:

        for e in enumerate(self.database["filters"]):
            if (filterName == e[1]["filterName"]):

                for k, v in updatedInfo.items():
                    self.database["filters"][e[0]][k] = v
                
                return self.database["filters"][e[0]]
            

    @Database.queue
    def updateRoomTs(self, userId: str, roomName: str, timestamp: str) -> dict:

        for e in enumerate(self.database["rooms"]):
            if ((userId == e[1]["userId"]) and (roomName == e[1]["roomName"])):

                self.database["rooms"][e[0]]["timestamp"] = timestamp
                return self.database["rooms"][e[0]]
            

    @Database.queue
    def updateRoomLogon(self, userId: str, roomName: str, logonAllowed: bool = False) -> dict:

        for e in enumerate(self.database["rooms"]):
            if ((userId == e[1]["userId"]) and (roomName == e[1]["roomName"])):

                self.database["rooms"][e[0]]["logonAllowed"] = logonAllowed
                return self.database["rooms"][e[0]]