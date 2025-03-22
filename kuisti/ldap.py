from __future__ import annotations
from . import error
from .log import LOGGING_BASE_CONF
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError
from gssapi.raw.exceptions import ExpiredCredentialsError
from gssapi.raw.misc import GSSError
from re import sub as reSub
from os import system
from socket import gethostbyname_ex, gethostbyaddr, create_connection
from json import load
from typing import TYPE_CHECKING, Callable
import logging.config



# Estää rekursiivisen import-komennon suorituksen. Lisätietoja: https://adamj.eu/tech/2021/05/13/python-type-hiix-circular-imports/
if (TYPE_CHECKING):
    from .kuisti import Kuisti



def loadConfig(configFiles):

    dicts = []

    for fileName in configFiles:
        with open(fileName, "r") as file:

            dicts.append(load(file))

    if (len(dicts) == 1):
        return dicts[0]

    return dicts



logging.config.dictConfig(LOGGING_BASE_CONF)



class LdapConnection(Connection):

    def __init__(self, kuistiInstance: Kuisti, domain: str, secureConn: bool = True, *args, **kwargs):

        self.logger = kuistiInstance.logger
        self.server = None
        self.secureConn = secureConn
        self.domain = domain
        self._initArgs = [kuistiInstance, domain, secureConn, *args]
        self._initKwargs = {**kwargs}
        self._useActiveDcFqdn(domain)

        @error.handler((ExpiredCredentialsError, GSSError), self.logger, self._getTgt, loopUntilSuccessDefinedErr=True, raiseDefinedErr=False)
        def _(self, server, *args, **kwargs):

            super().__init__(server, *args, **kwargs)


        #_(self, self.server, client_strategy=SYNC, authentication=SASL, sasl_mechanism=KERBEROS, user=environmentConf["ldap"]["serviceUser"], auto_bind=True, receive_timeout=10)
        _(self, self.server, *args, **kwargs)


    @staticmethod
    def _ldapOperation(instance: LdapConnection, func: Callable, *args, **kwargs):
        
        @error.handler((ExpiredCredentialsError, GSSError, LDAPSocketOpenError), instance.logger, instance._getTgt, 
                       instance.__init__, defaulErrFuncArgs=instance._initArgs, defaultErrFuncKwargs=instance._initKwargs, loopUntilSuccessDefinedErr=False, 
                       raiseDefinedErr=False, raiseDefaultErr=True, retryCount=5)
        def _():
            func(*args, **kwargs)
        
        _()


    def _useActiveDcFqdn(self, domain: str) -> str:

        for ipAddr in gethostbyname_ex(domain)[2]:
            try:

                create_connection((ipAddr, 389), timeout=5)
                self.server = Server(gethostbyaddr(ipAddr)[0], use_ssl=self.secureConn)
                self.logger.info(f"Käytössä oleva toimialuepalvelin: {self.server}")
                break

            except OSError:
                continue


    # TGT:n uusimiseen liittyvä prosessi eroteltu tulevaa varten, jos esim. TGT hankitaan vaihtoehtoisia reittejä pitkin.
    def _getTgt(self):

        self.logger.info("TGT ei saatavilla, uusitaan TGT...")
        system(f"kinit {self.user} -k -t ./kuisti_krb5.keytab")
        self.logger.info("TGT uusittu.")


    def checkGroupMembership(self, searchBase: str, groupDn: str, userDn: str = None, getAllMembers = False) -> (list[str] | bool):

        self._ldapOperation(
            
            self,
            self.search,
            searchBase,
            f"(&(objectClass=group)(distinguishedName={groupDn}))",
            attributes=["member"]
            
        )

        if ((len(self.entries) > 0) and self.entries[0].member.value):
            
            # Kokoa lista käyttäjänimistä (DN), jos kaikki jäsenet tulee palauttaa.
            if (getAllMembers):
                
                if (type(self.entries[0].member.value) == list): return self.entries[0].member.value
                return [self.entries[0].member.value]

            if (userDn in self.entries[0].member.value): return True
            return False

        return False


    # Haettavat attribuutit syötetään samalla tavalla kuin search-metodille (attributes=["attr1", "attr2", ...]).
    def getObjectAttr(self, *args, returnAll=False, **kwargs):

        self._ldapOperation(self, self.search, *args, **kwargs)

        if (len(self.entries) > 0):

            if (returnAll):

                attributes = {}

                for entry in self.entries:

                    attributes[entry.entry_dn] = entry.entry_attributes_as_dict

                return attributes

            return self.entries[0].entry_attributes_as_dict
        
        return None


    def getObjectDn(self, *args, returnAll=False, **kwargs) -> list[str] | str | None:

        #@error.handler((ExpiredCredentialsError, GSSError), self.logger, self._getTgt, self.__init__, defaulErrFuncArgs=[self, self.domain], loopUntilSuccessDefinedErr=True, raiseDefinedErr=False, raiseDefaultErr=True)
        #def _(self, *args, **kwargs):

        #    self.search(*args, **kwargs, attributes=["distinguishedName"])


        #_(self, *args, **kwargs)

        self._ldapOperation(self, self.search, *args, attributes=["distinguishedName"], **kwargs)

        if (len(self.entries) > 0):

            if (returnAll):

                dnList = []

                for entry in self.entries:

                    dnList.append(entry["distinguishedName"].value)

                return dnList

            return self.entries[0]["distinguishedName"].value
        
        return None
    

    def formatToDitAttr(self, string: str, formattingOptions: dict):

        return reSub(formattingOptions["pattern"], formattingOptions["repl"], string)