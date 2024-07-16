import os
from KlapProtocol import KlapProtocol

username = os.getenv("username")
password = os.getenv("password")
url = os.getenv("url")
klap = KlapProtocol(username, password , url)
klap.getLightState()
klap.execute_request()
