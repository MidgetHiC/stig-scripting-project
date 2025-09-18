# add comments test
import platform, os, psutil, subprocess, winreg

def format_drive(drive_letter):
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
            
    print(f"{drive_letter} is a NTFS drive")
    return True

def enable_bitlocker(drive_letter, pin):
    print(f"🔒 Beginning BitLocker encryption on {drive_letter}:...")
    try:
        enable_cmd = (
            f"powershell.exe Enable-BitLocker -MountPoint '{drive_letter[:-1]}'"
        )

        encryption_result = subprocess.run(
            enable_cmd,
            capture_output = True,
            text = True,
            check = True,
            shell = True
        )

        print(f"✅ BitLocker enabled successfully on {drive_letter}.")
    except subprocess.CalledProcessError as e:
        print("❌ Failed to enable BitLocker.")
        print("Error:", e.stderr)

def win_10_stigs():
    # look up what platform.platform() does
    print(f"Beginning Windows 10 STIG on {platform.system()}.")
    if platform.system() == 'Windows':
        print("Welcome to GTRI STIG Scripter.")

        drives = os.listdrives()
        for i in range(1, len(drives) + 1):
            if (format_drive(drives[i - 1])):
                enable_bitlocker(drives[i - 1], pin)
    else:
        print("ERROR: NOT WINDOWS: Please run this script on a Windows machine.")

win_10_stigs()