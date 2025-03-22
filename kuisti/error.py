from .log import LOGGING_BASE_CONF
from logging import Logger
from typing import Callable
import logging.config



logging.config.dictConfig(LOGGING_BASE_CONF)



class KuistiNoRoomsFound(Exception):
    
    def __init__(self, *args):
        super().__init__(*args)



class KuistiUserNotInRoom(Exception):
    
    def __init__(self, *args):
        super().__init__(*args)



class KuistiLdapModificationError(Exception):
    
    def __init__(self, *args):
        super().__init__(*args)



class KuistiNetworkNotFound(Exception):
    
    def __init__(self, *args):
        super().__init__(*args)



# https://blog.miguelgrinberg.com/post/the-ultimate-guide-to-python-decorators-part-iii-decorators-with-arguments

def handler(errors: tuple | Exception, logger: Logger, exceptFunc: Callable = (lambda: None), defaultErrorAction: Callable = (lambda: None), exceptFuncArgs: list = [], exceptFuncKwargs: dict = {}, defaulErrFuncArgs: list = [], defaultErrFuncKwargs: dict = {}, loopUntilSuccessDefinedErr=False, loopUntilSuccessDefaultErr=False, printErros=True, raiseDefinedErr=True, raiseDefaultErr=True, retryCount: int = 1):

    def innerDecorator(func):

        def wrapper(*args, **kwargs):

            retriesDone = 0

            while True:
                try:

                    return func(*args, **kwargs)

                except errors as err:

                    if (printErros): logger.error(err)

                    if (retriesDone < retryCount):

                        exceptFunc(*exceptFuncArgs, **exceptFuncKwargs)
                        retriesDone += 1
                        continue
                    
                    if (raiseDefinedErr): raise RuntimeError(err)
                    if (not(loopUntilSuccessDefinedErr)): break

                except Exception as err:

                    if (printErros): logger.error(err)

                    if (retriesDone < retryCount):

                        defaultErrorAction(*defaulErrFuncArgs, **defaultErrFuncKwargs)
                        retriesDone += 1
                        continue

                    if (raiseDefaultErr): raise RuntimeError(err)
                    if (not(loopUntilSuccessDefaultErr)): break

        return wrapper
    
    return innerDecorator