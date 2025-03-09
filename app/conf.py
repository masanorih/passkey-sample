import os
import logging

mode = os.getenv("APP_MODE", "test")


# fmt:off
conf = {
    "LOGLEVEL": logging.DEBUG,
    "SECRET_KEY": os.getenv("SECRET_KEY", "secret_key"),
}
# fmt:on
