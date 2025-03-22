from kuisti.kuisti import Kuisti
from kuisti.loghandlers.default import DefaultLogHandler
from kuisti.firewalls.opnsense import Opnsense
import urllib3



if (__name__ == "__main__"):

    # ----- ALUSTUS -----

    # Hiljennetään varoitukset, jottei urllib ulise self-signed sertifikaatista.
    urllib3.disable_warnings()

    kuisti = Kuisti("log_detection.json", "environment.json")
    logHandler = DefaultLogHandler(kuisti)
    firewall = Opnsense(kuisti, **kuisti.environmentConf["firewalls"]["fw01"])
    #firewall = None

    # ----- PÄÄOHJELMA -----

    kuisti.start(logHandler, firewall)