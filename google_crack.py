import os
import json
import base64
import win32crypt
from Crypto.Cipher import AES

def GoogleUtcToUnixTimestamp(google_utc_microseconds, return_microseconds=False):
    google_seconds = int(google_utc_microseconds / 1000000)
    unix_timestamp = google_seconds - 11644480800
    if (return_microseconds):
        unix_timestamp *= 1000000
        unix_timestamp += (google_utc_microseconds % 1000000)
    return unix_timestamp

def GetDecryptedKey():
    path = r'%LocalAppData%\Google\Chrome\User Data\Local State'
    path = os.path.expandvars(path)
    with open(path, 'r') as file:
        encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key)
    encrypted_key = encrypted_key[5:]
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return decrypted_key

def DecryptCookie(encrypted_cookie, decrypted_key):
    #data = bytes.fromhex(encrypted_cookie)
    data = encrypted_cookie
    nonce = data[3:3+12]
    ciphertext = data[3+12:-16]
    tag = data[-16:]
    cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    plaintext = plaintext.decode('utf-8')
    return plaintext