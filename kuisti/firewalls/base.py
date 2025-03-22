from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generator
import logging



if (TYPE_CHECKING):
    from ..kuisti import Kuisti, User, loadConfig



class Firewall(ABC):

    def __init__(self, kuistiInstance: Kuisti, ipAddress: str, filtersetsPath: str):

        self.kuistiInstance = kuistiInstance
        self.logger = logging.getLogger("firewall")
        self.ipAddress = ipAddress
        self.filtersets = self.kuistiInstance.loadConfig([filtersetsPath])


    @abstractmethod
    def createFilter(self, filterName: str, ipAddress: str, filterConf: dict) -> None:
        pass


    @abstractmethod
    def generateFilterName(self, userId: str, roomName: str, ipAddress: str, userRole: str, filterIdx: int) -> str:
        pass


    @abstractmethod
    def getInfoFromName(self, filterName: str) -> dict:
        pass


    @abstractmethod
    def removeFilter(self, filterName: str = "", searchPhrase: str = "") -> list[str]:
        pass


    @abstractmethod
    def applyChanges(self):
        pass

    
    @abstractmethod
    def toggleFilter(self, ruleUuid: str, *, enabled=False):
        pass

    
    @abstractmethod
    def searchFilter(self, searchPhrase: str) -> str:
        pass

    
    @abstractmethod
    def getStates(self, ipAddress: str, filterConf: dict, *, returnValues: list[str] = ['id']) -> Generator[str]:

        """
        Funktio palauttaa oletuksena iteraattorin, joka antaa (generoi) funktion kutsujalle searchPhrase-arvoon
        linkitettyjen tilatietojen ID:t. Jos kutsuja on määrittänyt returnValues-listaan omia avaimia, kutsujalle 
        generoidaan sanakirja, joka sisältää pyydetyt avaimet ja arvot.
        """

        pass

    
    @abstractmethod
    def deleteStates(self, stateIds, *, returnCount=False) -> None:
        pass


    @abstractmethod
    def getInterface(self, ipAddress: str) -> str:
        pass