from abc import ABC, abstractmethod
#from multiprocessing import Manager
from queue import Queue
from threading import Thread
from typing import Callable



class Database(ABC):

    def __init__(self, database = None):
        
        self.database = database
        self._queue = Queue()
        self._workerThread = Thread(target=self._worker)
        self._workerThread.start()


    def queue(func: Callable):
        def inner(self, *args, **kwargs):

            retVal = []
        
            self._queue.put((func, self, args, kwargs, retVal))
            self._queue.join()

            return retVal[0]

        return inner

    
    def _worker(self) -> None:

        while True:

            task, dbInstance, args, kwargs, retVal = self._queue.get()
            retVal.append(task(dbInstance, *args, **kwargs))
            self._queue.task_done()


    @abstractmethod
    def addUser(self, userId: str, dn: str) -> None:
        pass

    
    @abstractmethod
    def addFilter(self, userId: str, role: str, filterName: str, roomName: str, timestamp: str, deviceName: str, deviceIp: str, autoLocked: bool = False, renewalAmount: int = 0, filterConf: str = "") -> dict:
        pass


    @abstractmethod
    def addUserToRoom(self, userId: str, roomName: str, roomDn: str, timestamp: str, logonAllowed: bool = False) -> dict:
        pass


    @abstractmethod
    def getFilterInfo(self, userId: str = "any", filterName: str = "any") -> list[str]:
        pass


    @abstractmethod
    def searchFilter(self, userId: str, roomName: str = "any", deviceName: str = "any", deviceIp: str = "any") -> list[dict]:
        pass
    

    @abstractmethod
    def getUserInfo(self, userId: str) -> dict | None:
        pass
    

    @abstractmethod
    def getUserAttendance(self, userId: str, room: str = "any") -> list[dict]:
        pass
    

    @abstractmethod
    def removeFilter(self, filterName: str) -> None:
        pass


    @abstractmethod
    def removeUser(self, userId: str) -> None:
        pass


    @abstractmethod
    def removeUserFromRoom(self, userId: str, roomName: str) -> None:
        pass


    @abstractmethod
    def updateFilterAutolock(self, filterName: str, autoLocked: bool = True) -> None:
        pass


    @abstractmethod
    def updateFilterTs(self, filterName: str, timestamp: str) -> dict:
        pass


    @abstractmethod
    def updateFilterInfo(self, filterName: str, updatedInfo: dict) -> dict:
        pass


    @abstractmethod
    def updateRoomTs(self, userId: str, roomName: str, timestamp: str) -> dict:
        pass


    @abstractmethod
    def updateRoomLogon(self, userId: str, roomName: str, logonAllowed: bool = False) -> dict:
        pass