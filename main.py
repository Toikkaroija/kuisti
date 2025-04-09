from kuisti.kuisti import Kuisti
from kuisti.loghandlers.default import DefaultLogHandler
from kuisti.firewalls.opnsense import Opnsense
import urllib3



# Example driver code for Kuisti.

if (__name__ == "__main__"):

    # ----- INIT -----

    # Disable warnings for self-signed certificates.
    urllib3.disable_warnings()

    kuisti = Kuisti("log_detection.json", "environment.json")
    logHandler = DefaultLogHandler(kuisti)

    # Set firewall to None, if you do not want to use a firewall with Kuisti.
    firewall = Opnsense(kuisti, **kuisti.environmentConf["firewalls"]["fw01"])
    #firewall = None

    # ----- MAIN -----

    kuisti.start(logHandler, firewall)