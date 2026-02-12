import RPi.GPIO as GPIO
from time import sleep
import os

# Ignore warnings for now
GPIO.setwarnings(False)

# Use GPIO pin numbering (BCM mode)
GPIO.setmode(GPIO.BCM)

# Set the desired GPIO pin as an output pin and set initial value to low (off)
RST_PIN = 10
SW_PIN = 9
GPIO.setup(RST_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(SW_PIN, GPIO.OUT, initial=GPIO.LOW)

print("Starting flash process!!! Do not stop early let it finish completely!!!")

try:
    print("--- Putting Board in Flash State ---")
    #print("Pulling RESET LOW")
    GPIO.output(RST_PIN, GPIO.HIGH)
    
    sleep(1)
    
    #print("Pulling Flash Switch LOW")
    GPIO.output(SW_PIN, GPIO.HIGH)
    
    sleep(1)
    
    #print("Pulling RESET HIGH")
    GPIO.output(RST_PIN, GPIO.LOW)

    sleep(1)
    
    #print("Pulling Flash Switch RESET HIGH")
    GPIO.output(SW_PIN, GPIO.LOW)
    print("--- Running UVX commands right now to flash board ---")
    sleep(1)
    #os.system("./uvx_flash.sh")
    print("--- Erasing Existing Firmware ---")
    os.system("uvx ectf hw /dev/ttyACM2 erase")
    sleep(3)
    print("--- Flashing New Firmware ---")
    os.system("uvx ectf hw /dev/ttyACM2 flash ./build/hsm.bin -n hsm")
    sleep(3)
    print("--- Sending Start Command ---")
    os.system("uvx ectf hw /dev/ttyACM2 start")
    print("--- Board Should Now Be Flashed With New Firmware ---")

except KeyboardInterrupt:
    print("!!!FLASH FAILED PING COLE TO FIX!!!")
    GPIO.cleanup()

GPIO.cleanup()
