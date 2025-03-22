from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING



if (TYPE_CHECKING):
    from ..kuisti import Kuisti



class LogHandler(ABC):

    def __init__(self, kuistiInstance: Kuisti):

        super().__init__()
        self.kuistiInstance = kuistiInstance
        self.logConf = kuistiInstance.logConf
        self.logger = kuistiInstance.logger


    @abstractmethod
    def formatLog(logEntry: dict) -> dict:
        pass


    @abstractmethod
    def parseLog(self, line: str) -> dict:
        pass


    @abstractmethod
    def handleLog(self, logEntry: dict) -> None:
        pass