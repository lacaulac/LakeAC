# Lake AC Alpha

Abandoned WIP of a client-side anti-cheat.

## Overview of the different modules

### Launcher process

- HandleWatch.dll
  - Watches out for potential external hacks and inspect them closely using the FrenchGuy module. It's also responsible for the heartbeat so that it takes more than just unloading the modules to take down the AC.

### Game process

- HookBlade.dll
  - Prevents most injection methods from working and constantly checks if the blocks weren't altered by a third party.
- InjectWatch.dll
  - Catches unauthorized running code and stops its thread.
- GameMemoryWatch.dll
  - Configured  by the game's developer in order to watch over certain variables that shouldn't be modified under certain circumstances (eg: Solo cheat variables during competitive gameplay).

### Suspect processes

- FrenchGuy.dll
  - Blocks suspect behaviour toward the game (RPM/WPM, VirtualProtectEx, VirtualAllocEx, CreateRemoteThread, etc...)

## What's next?

- There's currently no identification or ban system whatsoever, only blocking suspicious behaviours and closing the suspicious program and/or the game when there's nothing we can prevent.
