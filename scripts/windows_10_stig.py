# add comments test
import platform, os, psutil

def format_drive(drive_letter: str):
    # look up what psutil.disk_partitions does
    for partition in psutil.disk_partitions(all=False):
        # look up what partion.mountpoint does
        if partition.mountpoint.upper() == drive_letter.upper():
            # look up what partition.fstype does
            if partition.fstype.upper() != "NTFS":
                print(f"{drive_letter} is NOT a NTFS drive, it is a {partition.fstype} drive.")
                if partition.fstype.upper() != "CDFS" and  partition.fstype.upper() != "UDF":
                    user_selection = input(f"Would you like to format {drive_letter}? (yes/no): ").lower()
                    while user_selection != "yes" and user_selection != "no":
                        print("Invalid input. Please try again.")
                        user_selection = input(f"Would you like to format {drive_letter}? (yes/no): ").lower()
                    
                    if user_selection == "no":
                        print(f"You chose not to format drive {drive_letter}. Be aware this introduces security vulnerabilities to your system.")
                    else:
                        print(f"Attempting to formatting {drive_letter} to NTFS...")

                        format_command = f"format {drive_letter[0]}: /FS:NTFS /Q /Y"
                        print(f"Command: {format_command}")

                        return_code = os.system(format_command)
                        if return_code == 0: 
                            print(f"{drive_letter} NTFS formatted sucessfully.")
                            return format_drive(drive_letter)
                        else:
                            print(f"Failed to format {drive_letter} to NTFS.")

                return False
            
    print(f"{drive_letter} is a NTFS drive", end="| ")
    return True

def encrypt_drive(drive: str, pin: str):
    print(f"Beginning BitLocker encryption on {drive}", end="... ")
    print(f"successfully encrypted {drive} with pin: {pin}", end="| ")  

def win_10_stigs():
    # look up what platform.platform() does
    print(f"Beginning Windows 10 STIG on {platform.system()}.")
    if platform.system() == 'Windows':
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
            if (format_drive(drives[i - 1])):
                encrypt_drive(drives[i - 1], pin)
                print()
    else:
        print("ERROR: NOT WINDOWS: Please run this script on a Windows machine.")

win_10_stigs()