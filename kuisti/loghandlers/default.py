from .base import LogHandler
from ..user import User
from ..error import KuistiNoRoomsFound
from re import search as reSearch
from re import sub as reSub



class DefaultLogHandler(LogHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


    def formatLog(self, system: str, logEntry: dict) -> dict:

        formattedEntry = {}
        formattingOptions = self.logConf[system]["formatting"]

        try:
            for k, v in logEntry.items():
                if (k in formattingOptions.keys()):

                    formattedEntry[k] = {"parsed": v}
                    formattedEntry[k]["formatted"] = reSub(formattingOptions[k]["pattern"], formattingOptions[k]["repl"], v)

        except:
            return {}

        return formattedEntry


    def parseLog(self, line: str) -> dict:

        logEntry = {}

        for system, conf in self.logConf.items():

            logEntry[system] = {}

            for key, rules in conf["detection"].items():

                try:
                    logEntry[system][key] = reSearch(rules["regexp"], line).group(rules["matchInGroup"])

                except:
                    logEntry[system][key] = None

        return logEntry
    

    def handleLog(self, logEntry: dict) -> None:

        for system, entry in logEntry.items():

            # Haetaan tarvittavat arvot lokimerkinnästä.
            formattedEntry = self.formatLog(system, entry)

            if (not formattedEntry):
                continue

            user = User(self.kuistiInstance, formattedEntry["user"]["formatted"].lower())
            roomName = formattedEntry["room"]["formatted"].lower()
            routeToRoom = self.kuistiInstance.getRoute(roomName)

            if (entry['directionIn']):

                self.logger.info(f'Käyttäjä "{user.identifier}" saapui huoneeseen "{roomName}" ({system}).')

                if (not user.isPresent()):
                    user.activate()

                if (not user.isInRoom(roomName)):

                    try:
                        user.addRoom(roomName)

                    except KuistiNoRoomsFound as err:

                        self.logger.warning(err)
                        continue


                if (routeToRoom and not user.isLogonAllowed(roomName)):
                    if (user.pathTaken(roomName)):

                        user.allowLogon([roomName])
                        self.logger.info(f'Sallittu käyttäjän "{user.identifier}" kirjautuminen huoneen "{roomName}" työasemille.')

            elif (entry['directionOut']):

                if (user.isPresent()):

                    self.logger.info(f'Käyttäjä "{user.identifier}" poistui huoneesta "{roomName}" ({system}).')

                    if ((user.isInRoom(roomName)) and (user.getRoomTimestamp(roomName) != "paused")):

                        if (routeToRoom):

                            user.denyLogon([roomName])
                            self.logger.info(f'Estetty käyttäjän "{user.identifier}" kirjautuminen huoneen "{roomName}" työasemille.')

                            if (self.kuistiInstance.firewall):

                                user.removeFilter(forRoom=roomName)
                                self.logger.info(f'Poistettu käyttäjän "{user.identifier}" suodatussäännöt huoneen "{roomName}" työasemilta.')

                        else:
                            
                            for name, route in self.kuistiInstance.getRoute("any").items():
                                if ((roomName in route) and user.isInRoom(name)):

                                    user.denyLogon([name])
                                    self.logger.info(f'Estetty käyttäjän "{user.identifier}" kirjautuminen huoneen "{name}" työasemille.')

                                    if (self.kuistiInstance.firewall):

                                        user.removeFilter(forRoom=name)
                                        self.logger.info(f'Poistettu käyttäjän "{user.identifier}" suodatussäännöt huoneen "{name}" työasemilta.')
                                    
                                    for rn in route:
                                        if (rn == roomName): continue

                                        try:

                                            user.removeRoom(rn)
                                            self.logger.info(f'Poistettu käyttäjä "{user.identifier}" huoneesta "{rn}".')

                                        except KuistiNoRoomsFound as err:
                                            self.logger.warning(err)

                        user.removeRoom(roomName)

                    if (not user.isInRoom("any")):

                        if (self.kuistiInstance.firewall):

                            user.removeFilter()
                            self.logger.info(f'Poistettu kaikki käyttäjän "{user.identifier}" suodatussäännöt.')

                        user.deactivate()

                else:
                    self.logger.warning(f'Yritetty poistaa käyttäjä "{user.identifier}" aktiivisten käyttäjien listalta. Käyttäjä ei ole kulunvalvonnan lokin mukaan paikalla.')

            else:
                self.logger.warning("Vastaanotettu lokimerkintä ei vastannut mitään konfiguroiduista vaihtoehdoista. Jätetään loki käsittelemättä.")