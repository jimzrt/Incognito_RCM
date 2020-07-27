Incognito_RCM
=
Incognito_RCM is a bare metal Nintendo Switch payload that derives encryption keys for de- and encrypting PRODINFO partition (sysnand and emummc) and wiping personal information from your Nintendo Switch as to go online while worrying slightly less about a ban.
It has a builtin backup and restore functionality.

It is heavily based on [Lockpick_RCM](https://github.com/shchmue/Lockpick_RCM) and takes inspiration from [incognito](https://github.com/blawar/incognito).

Massive Thanks to CTCaer, shchmue and blawar!

This project is in early stage, so have a nand backup!!

Patch note
=
*Scandal-UK: I have maintained this project with code from projects by CTCaer and schmue. I have added bug fixes and updates.*

*NOTE: Atmosphere now contains this feature, although it is unknown if it gets cached anywhere before Atmosphere overwrites it - to get it going you just need to follow the instructions in [the Wiki](https://github.com/Scandal-UK/Incognito_RCM/wiki).*

Usage
=
* Launch Incoginito_RCM.bin using your favorite payload injector
* Use menu to make a backup! (Will be written to `sd:/prodinfo_sysnand.bin` and `sd:/prodinfo_emunand.bin` respectively)
* Choose either Incognito (sysNAND) or Incognito (emuMMC) to wipe personal information
* If you ever want to revert, choose restore menu points

Screenshots
=

Main            |  Incognito
:-------------------------:|:-------------------------:
![](/res/main.png)  |  ![](/res/incognito.png)

Backup            |  Restore
:-------------------------:|:-------------------------:
![](/res/backup.png)  |  ![](/res/restore.png)

Building
=
Install [devkitARM](https://devkitpro.org/) and run `make`.

Known Issues
=
* Chainloading from SX will hang immediately due to quirks in their hwinit code, please launch payload directly

Disclaimers
=
* This application does not remove all personal information from your Switch, and should not be treated as a true preventative measure against getting banned.

* ALWAYS have a NAND backup. I am not responsible for any bricks or bans. Use at your own risk, as this is an experimental program.

* This application backs up your PRODINFO to the SD card. You should keep this backup in a more secure location, and not leave it on the SD card where it could be subject to corruption or be read by malicious applications.
