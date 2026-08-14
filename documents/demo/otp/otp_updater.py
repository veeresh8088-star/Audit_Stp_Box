import pyotp
import time

secret = "ADMI2FASHRDSECRT"
totp = pyotp.TOTP(secret)

while True:
    try:
        code = totp.now()
        with open("otp.html", "w") as f:
            f.write(f"<html><head><meta http-equiv='refresh' content='2'></head><body><h1 id='otp'>{code}</h1></body></html>")
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(5)
