# Simple KeyLogger KMDF Driver.
> The driver was prepared for the subject System Software. 
> 
## Table of contents
* [About The Project](#about-the-project)
* [Technologies](#technologies)
* [Getting Started](#getting-started)
* [Contact](#contact)

## About The Project
The subject of the project was the implementation of a driver that records the keys pressed by the user. Keylogger was created for Windows 10 based on the keyboard driver filter code provided by Microsoft [kbfiltr](https://github.com/microsoft/Windows-driver-samples/tree/master/input/kbfiltr). The name of the file to which the scancodes of the pressed keys are saved is permanently entered in the code. Access to the file from the application application level has been limited while the keylogger is running. To see the driver working, uninstall it first.

## Technologies
* C  

## Getting Started
Clone the repository  
`git clone https://github.com/RozaliaSolecka/Keylogger.git`  
  
Open project in your favourite IDE. 
  
Visual Studio 2019:
See: https://visualstudio.microsoft.com/pl/vs/

For installation guide, see instructions on the [kbfiltr's page](https://github.com/Microsoft/Windows-driver-samples/tree/master/input/kbfiltr) page


## Contact
Rozalia Solecka - rozaliasolecka@gmail.com
