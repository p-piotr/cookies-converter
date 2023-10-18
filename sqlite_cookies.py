import os
import sqlite3
import shutil
import google_crack

def GetCookiesTable(db_file=r'%LocalAppData%\Google\Chrome\User Data\Profile 3\Network\Cookies'):
    db_file = os.path.expandvars(db_file)
    con = sqlite3.connect(db_file)
    cur = con.cursor()
    raw_cookies = [a for a in cur.execute("SELECT * FROM cookies")]
    cookie_table = [
        {
            'creation_utc': a[0],
            'host_key': a[1],
            'top_frame_site_key': a[2],
            'name': a[3],
            'value': a[4],
            'encrypted_value': a[5],
            'path': a[6],
            'expires_utc': a[7],
            'is_secure': a[8],
            'is_httponly': a[9],
            'last_access_utc': a[10],
            'has_expires': a[11],
            'is_persistent': a[12],
            'priority': a[13],
            'samesite': a[14],
            'source_scheme': a[15],
            'source_port': a[16],
            'is_same_party': a[17],
            'last_upadte_utc': a[18]
        } 
        for a in raw_cookies]
    con.close()
    return cookie_table

def ClearDatabase(con, table):
    cur = con.cursor()
    cur.execute('DELETE FROM {};'.format(table))
    con.commit()

def GetOriginAttributes(top_frame_site_key):
    if len(top_frame_site_key) == 0:
        return ''
    return '^partitionKey=%28{}%29'.format(top_frame_site_key.replace('://', '%2C'))

#print(datetime.datetime.fromtimestamp(GoogleUtcToUnixTimestamp(13330270840195373)).strftime('%Y-%m-%d %H:%M:%S'))
#google_db_file = os.path.expandvars(r'%LocalAppData%\Google\Chrome\User Data\Profile 3\Network\Cookies')
google_decrypted_key = google_crack.GetDecryptedKey()

firefox_db_template_file = r'C:\Users\piotr\Desktop\cookies.sqlite'
shutil.copyfile(r'C:\Users\piotr\AppData\Roaming\Mozilla\Firefox\Profiles\jj44l1kp.default-release\cookies.sqlite', 
                firefox_db_template_file)

#create empty firefox template database
fcon = sqlite3.connect(firefox_db_template_file)
fcur = fcon.cursor()
fcur.execute('DELETE FROM moz_cookies;')
fcon.commit()

cookies = GetCookiesTable()

for i, cookie in enumerate(cookies):
    sql_query = "INSERT INTO moz_cookies(id, originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite, rawSameSite, schemeMap) VALUES({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});".format(
        i,
        "'{}'".format(GetOriginAttributes(cookie['top_frame_site_key'])),
        "'{}'".format(cookie['name']),
        "'{}'".format(google_crack.DecryptCookie(cookie['encrypted_value'], google_decrypted_key).replace('\'', '\'\'')), #escape single qu
        "'{}'".format(cookie['host_key']),
        "'{}'".format(cookie['path']),
        google_crack.GoogleUtcToUnixTimestamp(cookie['expires_utc']),
        google_crack.GoogleUtcToUnixTimestamp(cookie['last_access_utc'], return_microseconds=True),
        google_crack.GoogleUtcToUnixTimestamp(cookie['creation_utc'], return_microseconds=True),
        cookie['is_secure'],
        cookie['is_httponly'],
        0,
        cookie['samesite'] + 1,
        cookie['samesite'] + 1,
        2
    )
    print(sql_query)
    fcur.execute(sql_query)
fcon.commit()
fcon.close()