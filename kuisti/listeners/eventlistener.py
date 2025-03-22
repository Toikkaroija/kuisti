from __future__ import annotations
from ..user import User
from .base import Listener, EventHandler
from json import loads, dumps
from functools import partial
from socket import timeout
from datetime import datetime, timezone
from socketserver import TCPServer as TcpServer
from socketserver import UDPServer as UdpServer
from typing import TYPE_CHECKING
from logging import Logger
import logging, logging.config



# Estää rekursiivisen import-komennon suorituksen. Lisätietoja: https://adamj.eu/tech/2021/05/13/python-type-hiix-circular-imports/
if (TYPE_CHECKING):
    from ..kuisti import Kuisti, Firewall, Inspector



class TcpEventHandler(EventHandler):

    def __init__(self, kuistiInstance: Kuisti, firewall: Firewall, inspector: Inspector, logger: Logger, request, client_address, server):

        super().__init__(kuistiInstance, firewall, inspector, logger, request, client_address, server)


    def handle(self) -> None:

        self.request.settimeout(60)

        try:
            rcvdData = self.request.recv(1024).decode("utf-8")

        except timeout:
            return

        EventListener.handleEvent(self, loads(rcvdData))



class UdpEventHandler(EventHandler):

    def __init__(self, kuistiInstance: Kuisti, firewall: Firewall, inspector: Inspector, logger: Logger, request, client_address, server):

        super().__init__(kuistiInstance, firewall, inspector, logger, request, client_address, server)


    def handle(self) -> None:

        EventListener.handleEvent(self, loads(self.request[0]))



class EventListener(Listener):
        
    def __init__(self, firewall: Firewall, inspector: Inspector, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.firewall = firewall
        self.inspector = inspector
        self.logger = logging.getLogger("eventListener")


    @staticmethod
    def handleEvent(handlerInstance: EventHandler, data: dict) -> None:

        #data = loads(self.request[0])
        #hmac = data.pop("hmac")

        userName = data['user']
        hostname = data["hostname"]
        ipAddress = data['Ipv4Address']
        event = data['event']

        changesPending = False
        roomName = handlerInstance.kuistiInstance.getRoomName(ipAddress).lower()
        user = User(handlerInstance.kuistiInstance, userName)

        if (user.isInRoom(roomName)):
            if (event == "loggedIn"):

                filterTs = None

                if (handlerInstance.firewall):

                    filters = user.searchFilter(roomName, hostname, ipAddress)

                    if (filters):
                        filterTs = filters[0]["timestamp"]

                if (filterTs != "paused"):
                    handlerInstance.logger.info(f'Käyttäjä "{user.identifier}" kirjautui sisään työasemalle "{ipAddress}".')

                    if (handlerInstance.firewall):

                        user.addFilter(roomName, datetime.now(timezone.utc).timestamp() * 1000, hostname, ipAddress)
                        changesPending = True

            elif (event == "loggedOut"):

                handlerInstance.logger.info(f'Käyttäjä "{user.identifier}" kirjautui ulos työasemalta "{ipAddress}".')

                if (handlerInstance.firewall):

                    user.removeFilter(ipAddress=ipAddress, forRoom=roomName)
                    changesPending = True

            elif (event == "lockedAuto"):

                handlerInstance.logger.info(f'Käyttäjän "{user.identifier}" työasema "{ipAddress}" lukittiin automaattisesti (näytönsäästäjä).')

                if (handlerInstance.firewall):
                    user.updateFilterAutolock(roomName, ipAddress, autoLocked=True)

            elif (event == "lockedManual"):

                handlerInstance.logger.info(f'Käyttäjä "{user.identifier}" lukitsi työaseman "{ipAddress}".')

                if (handlerInstance.firewall):
                    filters = user.searchFilter(roomName, hostname, ipAddress)

                    if (filters):
                        for filterInfo in filters:

                            if (not user.isFilterAutolocked(filterInfo["filterName"])):
                                handlerInstance.inspector.updateTimeout(user, ipAddress, timeoutType='rule', roomName=roomName, paused=True)

                            break

                for rn in handlerInstance.kuistiInstance.getRoute(roomName):
                    handlerInstance.inspector.updateTimeout(user, ipAddress, timeoutType='room', roomName=rn, paused=True)

            elif (event == "unlocked"):

                handlerInstance.logger.info(f'Käyttäjä "{user.identifier}" avasi työaseman "{ipAddress}" lukituksen.')

                if (handlerInstance.firewall):
                    filters = user.searchFilter(roomName, hostname, ipAddress)

                    if (filters):
                        for filterInfo in filters:

                            handlerInstance.inspector.updateTimeout(user, ipAddress, timeoutType='rule', roomName=roomName, paused=False)
                            user.updateFilterAutolock(filterInfo["filterName"], ipAddress, autoLocked=False)

                for rn in handlerInstance.kuistiInstance.getRoute(roomName):
                    handlerInstance.inspector.updateTimeout(user, ipAddress, timeoutType='room', roomName=rn, paused=False)

            else:
                handlerInstance.logger.warning(f"Käyttäjän '{userName}' tila on tuntematon. Pudotetaan paketti. Vastaanotettu status: {event}")

        else:
            handlerInstance.logger.warning(f'Käyttäjä "{userName}" ei ole tunnistautunut alueelle "{roomName}", pudotetaan paketti. Vastaanotettu status: {event}')

        if (changesPending): handlerInstance.firewall.applyChanges()


    def start(self) -> None:

        if (self.protocol == "tcp"):

            tcpHandler = partial(TcpEventHandler, self.kuistiInstance, self.firewall, self.inspector, self.logger)

            self._start(

                self.kuistiInstance.environmentConf["common"]["localIpAddress"],
                self.kuistiInstance.environmentConf["common"]["localEventListenerPort"],
                tcpHandler,
                self.logger

            )

        elif (self.protocol == "udp"):

            udpHandler = partial(UdpEventHandler, self.kuistiInstance, self.firewall, self.inspector, self.logger)

            self._start(

                self.kuistiInstance.environmentConf["common"]["localIpAddress"],
                self.kuistiInstance.environmentConf["common"]["localEventListenerPort"],
                udpHandler,
                self.logger

            )                                                                                                            