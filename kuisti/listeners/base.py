from __future__ import annotations
from ..log import LOGGING_BASE_CONF
from ..firewalls.base import Firewall
from .. import error
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from socketserver import BaseRequestHandler
from socketserver import TCPServer as TcpServer
from socketserver import UDPServer as UdpServer
from logging import Logger
from time import sleep
import logging, logging.config



# Estää rekursiivisen import-komennon suorituksen. Lisätietoja: https://adamj.eu/tech/2021/05/13/python-type-hiix-circular-imports/
if (TYPE_CHECKING):
    from ..kuisti import Kuisti, Inspector

logging.config.dictConfig(LOGGING_BASE_CONF)



class Listener(ABC):

    def __init__(self, kuistiInstance: Kuisti, protocol: str = "tcp") -> None:

        self.kuistiInstance = kuistiInstance
        self.protocol = protocol
        self._logger = kuistiInstance.logger


    def __socketError(self, logger: Logger):

        logger.error("Konfiguroitua porttia ei voida ottaa käyttöön. Yritetään uudelleen 30 sekunnin kuluttua...")
        sleep(30)
        logger.error("Yritetään uudelleen...")


    def _start(self, ipAddress: str, port: int, handler: type[EventHandler], logger: Logger | None = None) -> None:

        logger = self._logger if (logger is None) else logger

        @error.handler(OSError, logger, self.__socketError, exceptFuncArgs=[logger], retryCount=5)
        def _():

            if (self.protocol == "tcp"):

                with TcpServer((ipAddress, port), handler) as tcpServer:
                    tcpServer.serve_forever()

            elif (self.protocol == "udp"):

                with UdpServer((ipAddress, port), handler) as udpServer:
                    udpServer.serve_forever()

        _()


    @abstractmethod
    def start(self) -> None:
        pass



class EventHandler(BaseRequestHandler):

    def __init__(self, kuistiInstance: Kuisti, firewall: Firewall, inspector: Inspector, logger: Logger, request, client_address, server):

        self.kuistiInstance = kuistiInstance
        self.firewall = firewall
        self.inspector = inspector
        self.logger = logger
        super().__init__(request, client_address, server)

        
    def handle(self) -> None:
        pass            