LOGGING_BASE_CONF = {

    "version": 1,
    "disable_existing_loggers": False,

    "root": {

        "handlers": ["kuistiLog"],
        "level": "INFO"

    },

    "loggers": {

        "kuisti": {

            "handlers": ["console"],
            "level": "INFO",

        },

        "firewall": {

            "handlers": ["console"],
            "level": "INFO",

        },

        "inspector": {

            "handlers": ["console"],
            "level": "INFO",

        },

        "eventListener": {

            "handlers": ["console"],
            "level": "INFO",

        },

        "extSystemLogConsole": {

            "handlers": ["console"],
            "level": "ERROR",

        },

        "extSystemLogFile": {

            "handlers": ["extSystemLog"],
            "level": "INFO",

        }


    },

    "handlers": {

        "console": {

            "formatter": "simple",
            "class": "logging.StreamHandler",
            "level": "INFO"

        },

        "kuistiLog": {

            "formatter": "simple",
            "class": "logging.FileHandler",
            "level": "INFO",
            "filename": "kuisti.log"

        },

        "extSystemLog": {

            "formatter": "simple",
            "class": "logging.FileHandler",
            "level": "INFO",
            "filename": "ext_system.log"

        }

    },

    "formatters": {

        "simple": {

            "format": "%(asctime)s (%(name)s) %(levelname)s: %(message)s"

        }

    }

}