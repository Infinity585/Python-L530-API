import requests
import hashlib
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os
import hashlib



class KlapProtocol:
    def __init__(self, username , password, url):
        self.session = requests.Session()
        
        #Used for handshaking,
        self.url = url
        self.auth_hash = self.sha256(
            self.sha1(username.encode()) + 
            self.sha1(password.encode())
        )
        with open('byte.bin', 'rb') as f:
            self.local_seed = f.read()
        
        
        #Used for enycrption and decryption
        self.local_hash = None
        self.sig = None
        self.key = None
        self.iv = None
        self.seq = None
        
        
        self.handshake()

    def sha1(self, value):
        return hashlib.sha1(value).digest()

    def sha256(self, value):
        return hashlib.sha256(value).digest()


    
    def iv_seq(self, seq):
        iv_seq = self.iv + seq.to_bytes(4, byteorder='big')
        return iv_seq

    def setupEncryption(self):
        # Getting key from local hash
        hash = hashlib.sha256(b'lsk' + self.local_hash).digest()
        self.key = hash[:16]
        # Getting singature from local hash
        hash = hashlib.sha256(b'ldk' + self.local_hash).digest()
        self.sig = hash[:28]

        # Getting iv and sequence from local hash
        hash = hashlib.sha256(b'iv' + self.local_hash).digest()
        self.iv = hash[:12]
        self.seq = int.from_bytes(hash[-4:], byteorder='big')

    def handshake(self):
        self.session.cookies.clear()
        url = self.url
        #Hand Shake 1
        print(f"{url}/handshake1")
        response = self.session.post(f"{url}/handshake1", data=self.local_seed)
        remote_seed = response.content[:16]


        #Hand Shake 2
        
        payload = self.sha256(remote_seed + self.local_seed + self.auth_hash)

        response = self.session.post(f"{url}/handshake2", data=payload)

        # Local Hash for encyption.
        self.local_hash = self.local_seed + remote_seed + self.auth_hash

        self.setupEncryption()

  
    def encrypt(self, data):
        self.seq += 1
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv_seq(self.seq)), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        cipher_bytes = encryptor.update(padded_data) + encryptor.finalize()

        signature = self.sha256(self.sig + self.seq.to_bytes(4, byteorder='big') + cipher_bytes)

        result = signature + cipher_bytes

        return result, self.seq

    def decrypt(self, seq, cipher_bytes):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv_seq(seq)), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_bytes = decryptor.update(cipher_bytes[32:]) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_bytes) + unpadder.finalize()

        return decrypted.decode()




    

    
      

    def getLightState(self):
        request_dict = {
            "method": "get_device_info",
        }
        
        request_string = json.dumps(request_dict)
        print(request_string)
        payload, seq = self.encrypt(request_string)

        response =self.session.post(f"{self.url}/request?seq={seq}", data=payload)
        response_body = response.content


        response_decrypted = self.decrypt(seq, response_body)
        print(f"Device responded with: {response_decrypted}")
        return json.loads(response_decrypted)["result"]["device_on"]


    def execute_request(self, ):

        current_state = self.getLightState()

        request_dict = {
           "method": "set_device_info",
           "params": {
                "device_on":  not current_state ,
                "brightness":100,
                "hue":0,
                "color_temp": 2700,
                "saturation": 100,

            }
        }

       
        
        request_string = json.dumps(request_dict)
        payload, seq = self.encrypt(request_string)

        response =self.session.post(f"{self.url}/request?seq={seq}", data=payload)
        response_body = response.content


        response_decrypted = self.decrypt(seq, response_body)
        print(f"Device responded with: {response_decrypted}")


        inner_response = json.loads(response_decrypted)
        print(f"Device inner response: {inner_response}")


