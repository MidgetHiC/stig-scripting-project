# Windows 10 & 11 STIG Automation Tool ⚙️

This is a **PowerShell-based STIG (Security Technical Implementation Guide) automation tool** designed to enhance the security and compliance of standalone Windows 10 and Windows 11 systems. This script automatically applies numerous configuration changes to meet Department of Defense (DoD) STIG/SRG requirements and hardened security baselines.

-----

## ⚠️ Warning and Disclaimer

**SECURITY SCRIPTS MAKE SYSTEM CHANGES\!**

This script makes extensive modifications to your operating system's configuration. It is intended for use in environments where STIG compliance is required.

  * **Review and Test:** You **must** review the script contents and thoroughly test the automation in a non-production environment before running it on any critical system.
  * **Backup:** Create a full system backup or restore point before execution.
  * **Standalone Systems:** This script is primarily designed for **standalone** systems not managed by Group Policy Objects (GPO) or other domain-level management tools.
  * **Non-100% Compliance:** While this tool automates a vast majority of configuration changes, achieving 100% compliance may still require manual documentation and system-specific administrative tasks.

-----

## Prerequisites

  * **Operating System:** Windows 10 or Windows 11 (Enterprise or Professional editions are generally required for full STIG compliance).
  * **Privileges:** The script must be run with **Administrator privileges**.
  * **PowerShell:** PowerShell 5.1 or newer.
  * **Pre-execution:** It is highly recommended to have the system fully updated and **BitLocker suspended** or disabled before the first run.

-----

## Usage

The main automation script is named `secure-standalone.ps1`. All supporting files from this repository must be present in the same directory as the script when executed.

### 1\. Execute with Default Parameters

Running the script without any parameters will apply all available STIG configurations (most parameters default to `$true`).

```powershell
.\secure-standalone.ps1
```

### 2\. Custom Execution

The script typically supports parameters to selectively enable or disable certain STIG/application configurations (e.g., specific browsers, applications, or components).

**Example: Run the script but skip the STIG for Microsoft Defender:**

```powershell
.\secure-standalone.ps1 -defender $false
```

**Example: Run the script but skip STIG configuration for both Windows Firewall and Chrome:**

```powershell
.\secure-standalone.ps1 -firewall $false -chrome $false
```

-----

## 💡 File Structure

The project structure is designed to keep the main execution logic simple while modularizing the STIG implementation. The main script must be run from the root directory.

| File/Folder | Description |
| :--- | :--- |
| `secure-standalone.ps1` | **The main execution script.** |
| `Files/` | Contains required GPOS, auditing configuration, and LGOP executable and documentation for script execution. |
| `README.md` | This document. |

-----

## Attribution and Reference

A significant portion of the logic and code is derived from the work in the following repository. This tool is an updated, derivative work designed to implement similar STIG hardening concepts.

**Reference Repository:**
`https://github.com/simeononsecurity/Standalone-Windows-STIG-Script`

-----