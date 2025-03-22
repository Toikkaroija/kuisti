from __future__ import annotations
from .. import error
from .base import Firewall
from json import loads
from re import match as reMatch
from requests import Session
from requests.exceptions import ConnectionError
from ipaddress import ip_address, IPv4Interface
from socket import gethostbyname
from typing import TYPE_CHECKING, Generator



if (TYPE_CHECKING):
    from ..kuisti import Kuisti

FILTER_NAME_MAX_SIZE = 255



class Opnsense(Firewall):

    def __init__(self, kuistiInstance: Kuisti, ipAddress: str, filtersetsPath: str, apiKey: str, apiSecret: str):

        super().__init__(kuistiInstance, ipAddress, filtersetsPath)
        self.apiKey = apiKey
        self.apiSecret = apiSecret
        self.url = f'https://{self.ipAddress}/api'
        self.connect()
        #self.rules = {}


    def _get(self, *args, **kwargs):

        @error.handler((ConnectionError, TimeoutError), self.logger, self.connect, raiseDefinedErr=False, retryCount=5)
        def _():
            return self.session.get(*args, **kwargs)
        
        return _()
    

    def _post(self, *args, **kwargs):

        @error.handler((ConnectionError, TimeoutError), self.logger, self.connect, raiseDefinedErr=False, retryCount=5)
        def _():
            return self.session.post(*args, **kwargs)
        
        return _()


    def connect(self) -> None:

        self.session = Session()
        self.session.auth = (self.apiKey, self.apiSecret)
        self.session.verify = False


    def createFilter(self, filterName: str, ipAddress: str, filterConf: dict) -> None:

        interfaces = self.getInterface(ipAddress)

        action = "block" if ("action" not in filterConf.keys()) else filterConf["action"]
        dstPort = "" if (filterConf["dstPort"] == "*") else filterConf["dstPort"]
        ipVersion = "inet" if (filterConf["ipVersion"] == "4") else "inet6"
        protocol = "any" if (filterConf["protocol"] == "*") else filterConf["protocol"].upper()

        if (reMatch(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[12]\d|\d)$', filterConf["dstAddr"])):
            dstAddr = filterConf["dstAddr"]

        elif (filterConf["dstAddr"] != '*'):
            dstAddr = gethostbyname(filterConf["dstAddr"])

        else:
            dstAddr = "any"

        newFilter = {

            "rule": {

                "action": action,
                "description": filterName,
                "source_net": f'{ipAddress}/32',
                "interface": f'{",".join(interfaces)}',
                "destination_net": dstAddr,
                "destination_port": dstPort,
                "ipprotocol": ipVersion,
                "protocol": protocol,
                "sequence": int(filterConf["sequence"])

            }

        }

        postResult = self._post(

            f'{self.url}/firewall/filter/addRule',
            json=newFilter

        )
        
        if (postResult.status_code == 200 and loads(postResult.text)['result'] == 'saved'):

            self.kuistiInstance.firewall.applyChanges()
            self.logger.info(f'Luotu suodatussääntö: "{filterName}".')
            
        else:
            self.logger.error(f"{postResult.text}")


    def generateFilterName(self, userId: str, roomName: str, ipAddress: str, userRole: str, filterIdx: int) -> str:

        ret = f'kuisti_{userId}:{roomName}:{ipAddress}:{userRole}:{filterIdx}'

        if (len(ret) > FILTER_NAME_MAX_SIZE): ret = ret[:FILTER_NAME_MAX_SIZE]

        return ret
    

    def getInfoFromName(self, filterName: str) -> dict:

        filterInfo = filterName.split('_')[1].split(':')

        return {
            
            "userId": filterInfo[0],
            "roomName": filterInfo[1],
            "ipAddress": filterInfo[2],
            "userRole": filterInfo[3],
            "filterIdx": filterInfo[4]

        }
    

    def removeFilter(self, filterName: str = "", searchPhrase: str = "") -> list[str]:

        ret = []
        searchPhrase = filterName if (len(filterName) > 0) else searchPhrase
        searchResult = self.kuistiInstance.firewall.searchFilter(searchPhrase)

        if (searchResult.status_code == 200):
            searchResultParsed = loads(searchResult.text)

            # Poistetaan sääntö, jos haettu sääntö on olemassa.
            if (len(searchResultParsed['rows']) != 0):

                for row in searchResultParsed['rows']:

                    filterUuid = row['uuid']
                    filterName = row["description"]
                    filterInfo = self.getInfoFromName(filterName)
                    ret.append(filterName)
                    filterConf = loads(self.kuistiInstance.db.getFilterInfo(filterName=filterName)[0]["filterConf"])
                    self.kuistiInstance.firewall.toggleFilter(filterUuid, enabled=False)
                    self.kuistiInstance.firewall.applyChanges()
                    #self.logger.info(f'Deaktivoitu sääntö {filterDesc}.')

                    postResult = self._post(

                        f'{self.url}/firewall/filter/delRule/{filterUuid}'

                    )

                    if (postResult.status_code == 200 and loads(postResult.text)['result'] == 'deleted'):

                        self.kuistiInstance.firewall.applyChanges()
                        self.logger.info(f'Poistettu suodatussääntö "{filterName}".')
                        stateIds = self.getStates(filterInfo["ipAddress"], filterConf)
                        self.logger.info(f'Poistetaan sääntöön linkitettyjä tilamerkintöjä...')
                        statesCount = self.deleteStates(stateIds, returnCount=True)
                        self.logger.info(f'Poistettu {statesCount} kpl sääntöön linkitettyä tilamerkintää.')

                    else:

                        self.logger.error(postResult.text)
                
        return ret


    def applyChanges(self):

        postResult = self._post(

            f'{self.url}/firewall/filter/apply'

        )

        if (postResult.status_code != 200):
            self.logger.error(postResult.text)

    
    def toggleFilter(self, ruleUuid, *, enabled=False):

        if (enabled):
            ruleStatus = 1

        else:
            ruleStatus = 0

        postResult = self._post(

            f'{self.url}/firewall/filter/toggleRule/{ruleUuid}/{ruleStatus}'

        )

        if (postResult.status_code != 200):
            print(f"Virhe: {postResult.text}")


    def searchFilter(self, searchPhrase: str) -> str:

        searchResult = self._post(

            f'{self.url}/firewall/filter/search_rule',
            json={"searchPhrase": searchPhrase}

        )

        return searchResult


    def getFilterIndex(self, ipAddress: str, roomName: str = "", userId: str = "", userRole: str = "", filterIdx: str = "") -> str:

        postResult = self._post(

            f'{self.url}/diagnostics/firewall/query_states',
            json={
                
                "current": 1,
                "rowCount": -1,
                "searchPhrase": ipAddress
                
            }

        )

        if (postResult.status_code == 200):

            filterName = self.generateFilterName(userId, roomName, ipAddress, userRole, filterIdx)
            activeStates = loads(postResult.text)
            
            for state in activeStates['rows']:
                if (('rule' in state) and (filterName == state["descr"])):

                    return state["rule"]

                else:
                    continue
                
        else:
            self.logger.error(f"{postResult.text}")

    
    def getStates(self, ipAddress: str, filterConf: dict, *, returnValues: list[str] = ['id']) -> Generator[str | dict]:

        postResult = self._post(

            f'{self.url}/diagnostics/firewall/query_states',
            json={

                "current": 1,
                "rowCount": -1,
                "searchPhrase": ipAddress
                
            }

        )

        #filterName = self.generateFilterName(userId, roomName, ipAddress, userRole, filterIdx)

        if (postResult.status_code == 200):

            activeStates = loads(postResult.text)

            ipVersion = "ipv4" if (filterConf["ipVersion"] == "4") else "ipv6"
            protocol = filterConf["protocol"].lower()

            dstPort = str(filterConf["dstPort"])
            dstPort = dstPort.split('-') if ((dstPort == '*') or ('-' in dstPort)) else [dstPort, int(dstPort) + 1]

            if (reMatch(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/(3[0-2]|[12]\d|\d)$', filterConf["dstAddr"])):
                dstAddr = IPv4Interface(filterConf["dstAddr"])

            elif (filterConf["dstAddr"] != '*'):
                dstAddr = IPv4Interface(f'{gethostbyname(filterConf["dstAddr"])}/32')

            else:
                dstAddr = '*'

            if (len(returnValues) == 1 and returnValues[0] == 'id'):
                for state in activeStates['rows']:

                    if ("rule" not in state): continue
                    if (ipVersion != state["ipproto"]): continue
                    if (protocol != state["proto"]): continue

                    if (('*' in dstPort) or (state["dst_port"] in dstPort)):
                        if ((dstAddr == '*') or (state["dst_addr"] == dstAddr)):
                            if ((state["nat_addr"] == ipAddress) or (state["src_addr"] == ipAddress)):
                            
                                stateId = state['id'].replace('\\', '')
                                yield stateId

            else:

                stateInfo = {}

                for state in activeStates['rows']:

                    if ("rule" not in state): continue
                    if (ipVersion != state["ipproto"]): continue
                    if (protocol != state["proto"]): continue

                    if (('*' in dstPort) or (state["dst_port"] in dstPort)):
                        if ((dstAddr == '*') or (state["dst_addr"] == dstAddr)):
                            if ((state["nat_addr"] == ipAddress) or (state["src_addr"] == ipAddress)):
                            
                                for returnValue in returnValues:
                                    stateInfo[returnValue] = state[returnValue].replace('\\', '')

                                yield stateInfo

                    else:
                        continue
                    
        else: 
            self.logger.error(f"{postResult.text}")


    def deleteStates(self, stateIds, *, returnCount=False):

        statesCount = 0

        for stateId in stateIds:

            postResult = self._post(

                f'{self.url}/diagnostics/firewall/del_state/{stateId}'

            )

            if (postResult.status_code == 200):
                statesCount += 1

            else:
                self.logger.error(f"{postResult.text}")

        if (returnCount == True):
            return statesCount


    def getInterface(self, ipAddress: str) -> list[str]:

        interfaces = []

        searchResult = self._post(

            f'{self.url}/interfaces/overview/interfacesInfo'

        )

        if (searchResult.status_code == 200):

            data = loads(searchResult.text)

            for info in data["rows"]:

                try:
                    if (ip_address(ipAddress) in IPv4Interface(info["addr4"]).network):
                        interfaces.append(info["identifier"])

                except KeyError:
                    pass

        else:
            self.logger.error(f"Cannot get interface: {searchResult.text}")

        return interfaces
