from __future__ import annotations
from .base import Listener
from functools import partial
from socket import timeout
from socketserver import BaseRequestHandler
from logging import Logger
import logging



class TcpExtLogHandler(BaseRequestHandler):

        def __init__(self, fileLogger: Logger, request, client_address, server):

            self.fileLogger = fileLogger
            super().__init__(request, client_address, server)


        def handle(self) -> None:

            self.request.settimeout(15)

            try:
                rcvdData = self.request.recv(1024).decode("utf-8").strip()

            except timeout:
                return

            self.fileLogger.info(rcvdData)



class UdpExtLogHandler(BaseRequestHandler):

        def __init__(self, fileLogger: Logger, request, client_address, server):

            self.fileLogger = fileLogger
            super().__init__(request, client_address, server)


        def handle(self) -> None:

            self.fileLogger.info(self.request[0].decode("utf-8").strip())



class ExtSystemListener(Listener):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        #self.extSystemLog = extSystemLog
        self.consoleLogger = logging.getLogger("extSystemLogConsole")
        self.fileLogger = logging.getLogger("extSystemLogFile")


    def start(self) -> None:

        if (self.protocol == "tcp"):

            tcpHandler = partial(TcpExtLogHandler, self.fileLogger)

            self._start(

                self.kuistiInstance.environmentConf["common"]["localIpAddress"],
                self.kuistiInstance.environmentConf["common"]["localExtSystemListenerPort"],
                tcpHandler,
                self.consoleLogger

            )

        elif (self.protocol == "udp"):

            udpHandler = partial(UdpExtLogHandler, self.fileLogger)

            self._start(

                self.kuistiInstance.environmentConf["common"]["localIpAddress"],
                self.kuistiInstance.environmentConf["common"]["localExtSystemListenerPort"],
                udpHandler,
                self.consoleLogger

            )                        
