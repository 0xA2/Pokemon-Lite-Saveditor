# Pokemon-Lite-S4VEditor
Savefile editor for the NDS Pokemon 4th generation games 

---------------

### Current Features

- Editing player name
- Editing species of lead pokemon
- Editing ability of lead pokemon

---------------

### Notes 

- Tested on Debian 10 using [DeSmuME  - DS Emulator](http://desmume.com/)

---------------

### Usage
```bash
$ python saveditor.py -h
usage: saveditor.py [-h] -v VERSION -f FILE [-n NAME] [-p PKM] [-a ABILITY]

Edit trainer name, lead pokemon species or ability

optional arguments:
  -h, --help            show this help message and exit
  -v VERSION, --version VERSION
                        Game version. Options:['diamond', 'pearl', 'platinum',
                        'heartgold', 'soulsilver']
  -f FILE, --file FILE  Name of the save file to be edited
  -n NAME, --name NAME  New trainer name
  -p PKM, --pkm PKM     Pokemon name. Example:'Pikachu'
  -a ABILITY, --ability ABILITY
                        Name of new ability. Example:'Static'
```

---------------

### TODO

- Item editing
- Move editing
- EV and IV editing
- Shininess editing




