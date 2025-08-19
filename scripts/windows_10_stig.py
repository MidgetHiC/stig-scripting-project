# add comments
import platform, os, psutil

def format_drive(drive_letter: str):
    # look up what psutil.disk_partitions does
    for partition in psutil.disk_partitions(all=True):
        # look up what partion.mountpoint does
        if partition.mountpoint.upper() == drive_letter.upper():
            # look up what partition.fstype does
            if partition.fstype.upper() != "NTFS":
                print(f"{drive_letter} is NOT a NTFS drive", end="| ")
                return
            
    print(f"{drive_letter} is a NTFS drive", end="| ")

def encrypt_drive(drive: str, pin: str):
    print(f"Beginning BitLocker encryption on {drive}", end="... ")
    print(f"successfully encrypted {drive} with pin: {pin}", end="| ")  

def win_10_stigs():
    # look up what platform.platform() does
    print(f"Beginning Windows 10 STIG on {platform.platform()}")
    if platform.platform() == 'Windows-11-10.0.26100-SP0':
        print("Welcome to GTRI STIG Scripter.")

        pin = ""
        while (not pin.isdigit()) or len(str(pin)) < 6:
            pin = input("Enter your pin (6 digit minimum): ")
            if not pin.isdigit(): 
                print(f"ERROR: INVALID PIN: Pin should only contain numbers, you typed {pin}. Try again.")
            elif len(pin) < 6:
                print(f"ERROR: INVALID PIN: Pin should be minimum 6 digits, you typed {pin}. Try again.")

        drives = os.listdrives()
        for i in range(1, len(drives) + 1):
            format_drive(drives[i - 1])
            encrypt_drive(drives[i - 1], pin)
            print()
    else:
        print("ERROR: NOT WINDOWS: Please run this script on a Windows machine.")

win_10_stigs()