import RPi.GPIO as GPIO
from time import sleep
import os

# Ignore warnings for now
GPIO.setwarnings(False)

# Use GPIO pin numbering (BCM mode)
GPIO.setmode(GPIO.BCM)

# Set the desired GPIO pin as an output pin and set initial value to low (off)
RST_PIN = 17
SW_PIN = 27
GPIO.setup(RST_PIN, GPIO.OUT, initial=GPIO.LOW)
GPIO.setup(SW_PIN, GPIO.OUT, initial=GPIO.LOW)

print("LED blinking started. Press Ctrl+C to stop.")


try:
    print("Pulling RESET LOW")
    GPIO.output(RST_PIN, GPIO.HIGH)
    
    sleep(1)
    
    print("Pulling Flash Switch LOW")
    GPIO.output(SW_PIN, GPIO.HIGH)
    
    sleep(1)
    
    print("Pulling RESET HIGH")
    GPIO.output(RST_PIN, GPIO.LOW)

    sleep(1)
    
    print("Pulling Flash Switch RESET HIGH")
    GPIO.output(SW_PIN, GPIO.LOW)
    print("Running UVX command right now to flash board....")
    sleep(1)
    #os.system("./uvx_flash.sh")
    print("Erasing Existing Firmware")
    os.system("uvx ectf hw /dev/ttyACM0 erase")
    sleep(3)
    print("Flashing New Firmware")
    os.system("uvx ectf hw /dev/ttyACM0 flash ./build/hsm.bin -n hsm")
    sleep(3)
    print("Sending Start Command")
    os.system("uvx ectf hw /dev/ttyACM0 start")

except KeyboardInterrupt:
    print("Issue turning on GPIO.")
    GPIO.cleanup()

GPIO.cleanup()
