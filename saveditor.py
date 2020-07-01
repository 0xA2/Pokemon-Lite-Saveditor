import argparse
import binascii
import sys


#### block adresses ####

small_block_1 = 0x00000
big_block_1 = 0xcf2c
small_block_2 = 0x40000
big_block_2 = 0x4cf2c



#### small block offsets for each version ####

diamond = pearl = {"trainer_name_offset":0x64,
						 "small_block_checksum_offset":0xc0ec,
						 "checksum_value_offset":0xc0fe,

						 # Party PKM block offset
						 "lead_PKM_offset":0x98,
			  		 	}

platinum = {"trainer_name_offset":0x68, # 0x68 - 0x77
				"small_block_checksum_offset":0xcf18,
				"checksum_value_offset":0xcf2a, # 0xcf2a - 0xcf2b

				# Party PKM block offset
				"lead_PKM_offset":0xa0, # 0xa0 - 0x18c
			  }

heartgold = soulsilver = {"trainer_name_offset":0x64,
								  "small_block_checksum_offset":0xf618,
							     "checksum_value_offset":0xf626,

				   			  # Party PKM block offset
								  "lead_PKM_offset":0x98,
			  					 }

versions = {'diamond':diamond,'pearl':pearl,'platinum':platinum,'heartgold':heartgold,'soulsilver':soulsilver}

#### Party PKM offsets ####

pokemon = {	# Unencrypted PKM block offsets
				"pv_offset": 0x00, # 0x00 - 0x03
				"disable_PKM_checksum_offset":0x04, # 0x04 - 0x05 (set bits 0 and 1 skips this checksum?)
				"PKM_checksum_offset":0x06, # 0x06 - 0x07

				# Encrypted PKM block offsets

				# Block A (0)
				"species_id":0x08, # 0x08 - 0x09
				"held_item":0x0a, # 0x0a - 0x0b
				"ability":0x15,

				# Block B (1)
				"moveset":0x00, # 0x00 - 0x07
				"move_pp":0x08, # 0x08 - 0x0b
				"move_ppups":0x0c, # 0x0c - 0x0f
				"IVs":0x10, # 0x10 - 0x13 (fist 29 bits control IV values, set all for max IVs; bit 30 -> isEgg flag?; bit 31 -> isNicknamed flag?)

				# Block C (2)
				"nickname":0x08 # 0x08 - 0x1d

				}



#### Small Block checksum ####

def updateChecksum(data,dataToUpdate,blockNumber,version):

	# Precomputed lookup table
	table = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
				0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
				0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
				0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
				0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
				0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
				0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
				0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
				0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
				0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
				0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
				0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
				0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
				0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
				0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
				0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
				0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
				0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
				0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
				0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
				0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
				0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
				0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
				0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
				0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
				0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
				0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
				0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
				0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
				0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
				0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
				0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0]

	sum = 0xffff
	print ("Computing checksum...")
	for i in range(0,len(dataToUpdate)):
		sum = (sum << 8)^table[int(bin(dataToUpdate[i])[2:][-8:],2)^int(bin(sum >> 8)[2:][-8:],2)]

	if blockNumber == 1:
		data[small_block_1+version["checksum_value_offset"]] = int(bin(sum)[2:][-8:],2)
		data[small_block_1+version["checksum_value_offset"]+1] = int(bin(sum >> 8)[2:][-8:],2)
	elif blockNumber == 2:
		data[small_block_2+version["checksum_value_offset"]] = int(bin(sum)[2:][-8:],2)
		data[small_block_2+version["checksum_value_offset"]+1] = int(bin(sum >> 8)[2:][-8:],2)
	else:
		return "Failed to compute checksum"


#### PKM structure crypto ####

def updatePKMChecksum(data, dataToUpdate, version):
	sum = 0
	for i in range(0,len(dataToUpdate),2):
		sum += (dataToUpdate[i+1] << 8) + dataToUpdate[i]

	data[small_block_1 + version["lead_PKM_offset"] + pokemon["PKM_checksum_offset"]] = int(bin(sum)[2:][-8:],2)
	data[small_block_1 + version["lead_PKM_offset"] + pokemon["PKM_checksum_offset"]+1] = int(bin(sum >> 8)[2:][-8:],2)
	data[small_block_2 + version["lead_PKM_offset"] + pokemon["PKM_checksum_offset"]] = int(bin(sum)[2:][-8:],2)
	data[small_block_2 + version["lead_PKM_offset"] + pokemon["PKM_checksum_offset"]+1] = int(bin(sum >> 8)[2:][-8:],2)

def getPV(data,version):
	pv_bytes = data[(small_block_2+version["lead_PKM_offset"]):(small_block_2+version["lead_PKM_offset"]+4)]
	return (pv_bytes[3] << 24)+(pv_bytes[2] << 16)+(pv_bytes[1] << 8)+pv_bytes[0]


def getBlockOffsets(pv):
	orderTable = {
						 # A offset -> index 0; B offset -> index 1; C offset -> index 2; D offset -> index 3
						 0:[0,32,64,96], #ABCD
						 1:[0,32,96,64], #ABDC
						 2:[0,64,32,96], #ACBD
						 3:[0,96,32,64], #ACDB
						 4:[0,64,96,32], #ADBC
						 5:[0,96,64,32], #ADCB
						 6:[32,0,64,96], #BACD
						 7:[32,0,96,64], #BADC
						 8:[64,0,32,96], #BCAD
						 9:[96,0,32,64], #BCDA
						10:[64,0,96,32], #BDAC
						11:[96,0,64,32], #BDCA
						12:[32,64,0,96], #CABD
						13:[32,96,0,64], #CADB
						14:[64,32,0,96], #CBAD
						15:[96,32,0,64], #CBDA
						16:[64,96,0,32], #CDAB
						17:[96,64,0,32], #CDBA
						18:[32,64,96,0], #DABC
						19:[32,96,64,0], #DACB
						20:[64,32,96,0], #DBAC
						21:[96,32,64,0], #DBCA
						22:[64,96,64,0], #DCAB
						23:[96,64,32,0]  #DCBA
					 }

	return orderTable[((pv & 0x3e000) >> 0xd) % 24]

def PRNG(data,seed,block_number,version):
	if block_number == 1:
		for i in range(0,128,2):
			seed = (0x41C64E6D * seed) + 0x00006073
			data[(small_block_1+version["lead_PKM_offset"]+0x08)+i] ^= int(bin(seed >> 16)[2:][-8:],2)
			data[(small_block_1+version["lead_PKM_offset"]+0x08)+i+1] ^= int(bin(seed >> 24)[2:][-8:],2)
	elif block_number == 2:
		for i in range(0,128,2):
			seed = (0x41C64E6D * seed) + 0x00006073
			data[(small_block_2+version["lead_PKM_offset"]+0x08)+i] ^= int(bin(seed >> 16)[2:][-8:],2)
			data[(small_block_2+version["lead_PKM_offset"]+0x08)+i+1] ^= int(bin(seed >> 24)[2:][-8:],2)
	else:
		return "Trying to decrypt nonexistent block"


#### Character encoding/decoding functions ####

def toGameEncode(c):
	encoding = {'0': 33, '1': 34, '2': 35, '3': 36, '4': 37, '5': 38, '6': 39, '7': 40, '8': 41, '9': 42, 'A': 43, 'B': 44, 'C': 45, 'D': 46, 'E': 47, 'F': 48, 'G': 49, 'H': 50, 'I': 51, 'J': 52, 'K': 53, 'L': 54, 'M': 55, 'N': 56, 'O': 57, 'P': 58, 'Q': 59, 'R': 60, 'S': 61, 'T': 62, 'U': 63, 'V': 64, 'W': 65, 'X': 66, 'Y': 67, 'Z': 68, 'a': 69, 'b': 70, 'c': 71, 'd': 72, 'e': 73, 'f': 74, 'g': 75, 'h': 76, 'i': 77, 'j': 78, 'k': 79, 'l': 80, 'm': 81, 'n': 82, 'o': 83, 'p': 84, 'q': 85, 'r': 86, 's': 87, 't': 88, 'u': 89, 'v': 90, 'w': 91, 'x': 92, 'y': 93, 'z': 94}
	return encoding[c]

def fromGameEncode(n):
	encoding = {33: '0', 34: '1', 35: '2', 36: '3', 37: '4', 38: '5', 39: '6', 40: '7', 41: '8', 42: '9', 43: 'A', 44: 'B', 45: 'C', 46: 'D', 47: 'E', 48: 'F', 49: 'G', 50: 'H', 51: 'I', 52: 'J', 53: 'K', 54: 'L', 55: 'M', 56: 'N', 57: 'O', 58: 'P', 59: 'Q', 60: 'R', 61: 'S', 62: 'T', 63: 'U', 64: 'V', 65: 'W', 66: 'X', 67: 'Y', 68: 'Z', 69: 'a', 70: 'b', 71: 'c', 72: 'd', 73: 'e', 74: 'f', 75: 'g', 76: 'h', 77: 'i', 78: 'j', 79: 'k', 80: 'l', 81: 'm', 82: 'n', 83: 'o', 84: 'p', 85: 'q', 86: 'r', 87: 's', 88: 't', 89: 'u', 90: 'v', 91: 'w', 92: 'x', 93: 'y', 94: 'z'}
	return encoding[n]



#### Player editing funtions ####

def changePlayerName(newname, data, version):
	if len(newname) > 7:
		print ("Invalid name\nMake sure the deisred name is 7 characters long and consists of only alphanumerics.")
		sys.exit(1)

	try:
		for i in range(0,16):
			data[small_block_2+version["trainer_name_offset"]+i] = 0
		for i in range(0,len(newname)*2,2):
			data[small_block_2+version["trainer_name_offset"]+i] = toGameEncode(newname[i//2])
			data[small_block_2+version["trainer_name_offset"]+i+1] = 1

		data[small_block_2+version["trainer_name_offset"]+len(newname)*2] = 0xff
		data[small_block_2+version["trainer_name_offset"]+len(newname)*2+1] = 0xff

	except:
		print ("Invalid name!\nMake sure the deisred name is 7 characters long and consists of only alphanumerics.")
		sys.exit(1)


#### PKM editing functions ####

def editSpecies(data,PKMName,blockOffsets,version):
	pokedex = {
		"Bulbasaur"	:[1, 0],
		"Ivysaur"	:[2, 0],
		"Venusaur"	:[3, 0],
		"Charmander":[4, 0],
		"Charmeleon":[5, 0],
		"Charizard"	:[6, 0],
		"Squirtle"	:[7, 0],
		"Wartortle"	:[8, 0],
		"Blastoise"	:[9, 0],
		"Caterpie"	:[10, 0],
		"Metapod"	:[11, 0],
		"Butterfree":[12, 0],
		"Weedle"		:[13, 0],
		"Kakuna"		:[14, 0],
		"Beedrill"	:[15, 0],
		"Pidgey"		:[16, 0],
		"Pidgeotto"	:[17, 0],
		"Pidgeot"	:[18, 0],
		"Rattata"	:[19, 0],
		"Raticate" 	:[20, 0],
		"Spearow"	:[21, 0],
		"Fearow"		:[22, 0],
		"Ekans"		:[23, 0],
		"Arbok"		:[24, 0],
		"Pikachu"	:[25, 0],
		"Raichu"		:[26, 0],
		"Sandshrew"	:[27, 0],
		"Sandslash"	:[28, 0],
		"NidoranF"	:[29, 0],
		"Nidorina"	:[30, 0],
		"Nidoqueen"	:[31, 0],
		"NidoranM"	:[32, 0],
		"Nidorino"	:[33, 0],
		"Nidoking"	:[34, 0],
		"Clefairy"	:[35, 0],
		"Clefable"	:[36, 0],
		"Vulpix"		:[37, 0],
		"Ninetales"	:[38, 0],
		"Jigglypuff":[39, 0],
		"Wigglytuff":[40, 0],
		"Zubat"		:[41, 0],
		"Golbat"		:[42, 0],
		"Oddish"		:[43, 0],
		"Gloom"		:[44, 0],
		"Vileplume"	:[45, 0],
		"Paras"		:[46, 0],
		"Parasect"	:[47, 0],
		"Venonat"	:[48, 0],
		"Venomoth"	:[49, 0],
		"Diglett"	:[50, 0],
		"Dugtrio"	:[51, 0],
		"Meowth"		:[52, 0],
		"Persian"	:[53, 0],
		"Psyduck"	:[54, 0],
		"Golduck"	:[55, 0],
		"Mankey"		:[56, 0],
		"Primeape"	:[57, 0],
		"Growlithe"	:[58, 0],
		"Arcanine"	:[59, 0],
		"Poliwag"	:[60, 0],
		"Poliwhirl"	:[61, 0],
		"Poliwrath"	:[62, 0],
		"Abra"		:[63, 0],
		"Kadabra"	:[64, 0],
		"Alakazam"	:[65, 0],
		"Machop"		:[66, 0],
		"Machoke"	:[67, 0],
		"Machamp"	:[68, 0],
		"Bellsprout":[69, 0],
		"Weepinbell":[70, 0],
		"Victreebel":[71, 0],
		"Tentacool"	:[72, 0],
		"Tentacruel":[73, 0],
		"Geodude"	:[74, 0],
		"Graveler"	:[75, 0],
		"Golem"		:[76, 0],
		"Ponyta"		:[77, 0],
		"Rapidash"	:[78, 0],
		"Slowpoke"	:[79, 0],
		"Slowbro"	:[80, 0],
		"Magnemite"	:[81, 0],
		"Magneton"	:[82, 0],
		"Farfetch'd":[83, 0],
		"Doduo"		:[84, 0],
		"Dodrio"		:[85, 0],
		"Seel"		:[86, 0],
		"Dewgong"	:[87, 0],
		"Grimer"		:[88, 0],
		"Muk"			:[89, 0],
		"Shellder"	:[90, 0],
		"Cloyster"	:[91, 0],
		"Gastly"		:[92, 0],
		"Haunter"	:[93, 0],
		"Gengar"		:[94, 0],
		"Onix"		:[95, 0],
		"Drowzee"	:[96, 0],
		"Hypno"		:[97, 0],
		"Krabby"		:[98, 0],
		"Kingler"	:[99, 0],
		"Voltorb"	:[100, 0],
		"Electrode"	:[101, 0],
		"Exeggcute"	:[102, 0],
		"Exeggutor"	:[103, 0],
		"Cubone"		:[104, 0],
		"Marowak"	:[105, 0],
		"Hitmonlee"	:[106, 0],
		"Hitmonchan":[107, 0],
		"Lickitung"	:[108, 0],
		"Koffing"	:[109, 0],
		"Weezing"	:[110, 0],
		"Rhyhorn"	:[111, 0],
		"Rhydon"		:[112, 0],
		"Chansey"	:[113, 0],
		"Tangela"	:[114, 0],
		"Kangaskhan":[115, 0],
		"Horsea"		:[116, 0],
		"Seadra"		:[117, 0],
		"Goldeen"	:[118, 0],
		"Seaking"	:[119, 0],
		"Staryu"		:[120, 0],
		"Starmie"	:[121, 0],
		"Mr. Mime"	:[122, 0],
		"Scyther"	:[123, 0],
		"Jynx"		:[124, 0],
		"Electabuzz":[125, 0],
		"Magmar"		:[126, 0],
		"Pinsir"		:[127, 0],
		"Tauros"		:[128, 0],
		"Magikarp"	:[129, 0],
		"Gyarados"	:[130, 0],
		"Lapras"		:[131, 0],
		"Ditto"		:[132, 0],
		"Eevee"		:[133, 0],
		"Vaporeon"	:[134, 0],
		"Jolteon"	:[135, 0],
		"Flareon"	:[136, 0],
		"Porygon"	:[137, 0],
		"Omanyte"	:[138, 0],
		"Omastar"	:[139, 0],
		"Kabuto"		:[140, 0],
		"Kabutops"	:[141, 0],
		"Aerodactyl":[142, 0],
		"Snorlax"	:[143, 0],
		"Articuno"	:[144, 0],
		"Zapdos"		:[145, 0],
		"Moltres"	:[146, 0],
		"Dratini"	:[147, 0],
		"Dragonair"	:[148, 0],
		"Dragonite"	:[149, 0],
		"Mewtwo"		:[150, 0],
		"Mew"			:[151, 0],
		"Chikorita"	:[152, 0],
		"Bayleef"	:[153, 0],
		"Meganium"	:[154, 0],
		"Cyndaquil"	:[155, 0],
		"Quilava"	:[156, 0],
		"Typhlosion":[157, 0],
		"Totodile"	:[158, 0],
		"Croconaw"	:[159, 0],
		"Feraligatr":[160, 0],
		"Sentret"	:[161, 0],
		"Furret"		:[162, 0],
		"Hoothoot"	:[163, 0],
		"Noctowl"	:[164, 0],
		"Ledyba"		:[165, 0],
		"Ledian"		:[166, 0],
		"Spinarak"	:[167, 0],
		"Ariados"	:[168, 0],
		"Crobat"		:[169, 0],
		"Chinchou"	:[170, 0],
		"Lanturn"	:[171, 0],
		"Pichu"		:[172, 0],
		"Cleffa"		:[173, 0],
		"Igglybuff"	:[174, 0],
		"Togepi"		:[175, 0],
		"Togetic"	:[176, 0],
		"Natu"		:[177, 0],
		"Xatu"		:[178, 0],
		"Mareep"		:[179, 0],
		"Flaaffy"	:[180, 0],
		"Ampharos "	:[181, 0],
		"Bellossom"	:[182, 0],
		"Marill"		:[183, 0],
		"Azumarill"	:[184, 0],
		"Sudowoodo"	:[185, 0],
		"Politoed"	:[186, 0],
		"Hoppip"		:[187, 0],
		"Skiploom"	:[188, 0],
		"Jumpluff"	:[189, 0],
		"Aipom"		:[190, 0],
		"Sunkern"	:[191, 0],
		"Sunflora"	:[192, 0],
		"Yanma"		:[193, 0],
		"Wooper"		:[194, 0],
		"Quagsire"	:[195, 0],
		"Espeon"		:[196, 0],
		"Umbreon"	:[197, 0],
		"Murkrow"	:[198, 0],
		"Slowking"	:[199, 0],
		"Misdreavus":[200, 0],
		"Unown"		:[201, 0],
		"Wobbuffet"	:[202, 0],
		"Girafarig"	:[203, 0],
		"Pineco"		:[204, 0],
		"Forretress":[205, 0],
		"Dunsparce"	:[206, 0],
		"Gligar"		:[207, 0],
		"Steelix"	:[208, 0],
		"Snubbull"	:[209, 0],
		"Granbull"	:[210, 0],
		"Qwilfish"	:[211, 0],
		"Scizor"		:[212, 0],
		"Shuckle"	:[213, 0],
		"Heracross"	:[214, 0],
		"Sneasel"	:[215, 0],
		"Teddiursa"	:[216, 0],
		"Ursaring"	:[217, 0],
		"Slugma"		:[218, 0],
		"Magcargo"	:[219, 0],
		"Swinub"		:[220, 0],
		"Piloswine"	:[221, 0],
		"Corsola"	:[222, 0],
		"Remoraid"	:[223, 0],
		"Octillery"	:[224, 0],
		"Delibird"	:[225, 0],
		"Mantine"	:[226, 0],
		"Skarmory"	:[227, 0],
		"Houndour"	:[228, 0],
		"Houndoom"	:[229, 0],
		"Kingdra"	:[230, 0],
		"Phanpy"		:[231, 0],
		"Donphan"	:[232, 0],
		"Porygon2"	:[233, 0],
		"Stantler"	:[234, 0],
		"Smeargle"	:[235, 0],
		"Tyrogue"	:[236, 0],
		"Hitmontop"	:[237, 0],
		"Smoochum"	:[238, 0],
		"Elekid"		:[239, 0],
		"Magby"		:[240, 0],
		"Miltank"	:[241, 0],
		"Blissey"	:[242, 0],
		"Raikou"		:[243, 0],
		"Entei"		:[244, 0],
		"Suicune"	:[245, 0],
		"Larvitar"	:[246, 0],
		"Pupitar"	:[247, 0],
		"Tyranitar"	:[248, 0],
		"Lugia"		:[249, 0],
		"Ho-Oh"		:[250, 0],
		"Celebi"		:[251, 0],
		"Treecko"	:[252, 0],
		"Grovyle"	:[253, 0],
		"Sceptile"	:[254, 0],
		"Torchic"	:[255, 0],
		"Combusken"	:[256, 1],
		"Blaziken"	:[257, 1],
		"Mudkip"		:[258, 1],
		"Marshtomp"	:[259, 1],
		"Swampert"	:[260, 1],
		"Poochyena"	:[261, 1],
		"Mightyena"	:[262, 1],
		"Zigzagoon"	:[263, 1],
		"Linoone"	:[264, 1],
		"Wurmple"	:[265, 1],
		"Silcoon"	:[266, 1],
		"Beautifly"	:[267, 1],
		"Cascoon"	:[268, 1],
		"Dustox"		:[269, 1],
		"Lotad"		:[270, 1],
		"Lombre"		:[271, 1],
		"Ludicolo"	:[272, 1],
		"Seedot"		:[273, 1],
		"Nuzleaf"	:[274, 1],
		"Shiftry"	:[275, 1],
		"Taillow"	:[276, 1],
		"Swellow"	:[277, 1],
		"Wingull"	:[278, 1],
		"Pelipper"	:[279, 1],
		"Ralts"		:[280, 1],
		"Kirlia"		:[281, 1],
		"Gardevoir"	:[282, 1],
		"Surskit"	:[283, 1],
		"Masquerain":[284, 1],
		"Shroomish"	:[285, 1],
		"Breloom"	:[286, 1],
		"Slakoth"	:[287, 1],
		"Vigoroth"	:[288, 1],
		"Slaking"	:[289, 1],
		"Nincada"	:[290, 1],
		"Ninjask"	:[291, 1],
		"Shedinja"	:[292, 1],
		"Whismur"	:[293, 1],
		"Loudred"	:[294, 1],
		"Exploud"	:[295, 1],
		"Makuhita"	:[296, 1],
		"Hariyama"	:[297, 1],
		"Azurill"	:[298, 1],
		"Nosepass"	:[299, 1],
		"Skitty"		:[300, 1],
		"Delcatty"	:[301, 1],
		"Sableye"	:[302, 1],
		"Mawile"		:[303, 1],
		"Aron"		:[304, 1],
		"Lairon"		:[305, 1],
		"Aggron"		:[306, 1],
		"Meditite"	:[307, 1],
		"Medicham"	:[308, 1],
		"Electrike"	:[309, 1],
		"Manectric"	:[310, 1],
		"Plusle"		:[311, 1],
		"Minun"		:[312, 1],
		"Volbeat"	:[313, 1],
		"Illumise"	:[314, 1],
		"Roselia"	:[315, 1],
		"Gulpin"		:[316, 1],
		"Swalot"		:[317, 1],
		"Carvanha"	:[318, 1],
		"Sharpedo"	:[319, 1],
		"Wailmer"	:[320, 1],
		"Wailord"	:[321, 1],
		"Numel"		:[322, 1],
		"Camerupt"	:[323, 1],
		"Torkoal"	:[324, 1],
		"Spoink"		:[325, 1],
		"Grumpig"	:[326, 1],
		"Spinda"		:[327, 1],
		"Trapinch"	:[328, 1],
		"Vibrava"	:[329, 1],
		"Flygon"		:[330, 1],
		"Cacnea"		:[331, 1],
		"Cacturne"	:[332, 1],
		"Swablu"		:[333, 1],
		"Altaria"	:[334, 1],
		"Zangoose"	:[335, 1],
		"Seviper"	:[336, 1],
		"Lunatone"	:[337, 1],
		"Solrock"	:[338, 1],
		"Barboach"	:[339, 1],
		"Whiscash"	:[340, 1],
		"Corphish"	:[341, 1],
		"Crawdaunt"	:[342, 1],
		"Baltoy"		:[343, 1],
		"Claydol"	:[344, 1],
		"Lileep"		:[345, 1],
		"Cradily"	:[346, 1],
		"Anorith"	:[347, 1],
		"Armaldo"	:[348, 1],
		"Feebas"		:[349, 1],
		"Milotic"	:[350, 1],
		"Castform"	:[351, 1],
		"Kecleon"	:[352, 1],
		"Shuppet"	:[353, 1],
		"Banette"	:[354, 1],
		"Duskull"	:[355, 1],
		"Dusclops"	:[356, 1],
		"Tropius"	:[357, 1],
		"Chimecho"	:[358, 1],
		"Absol"		:[359, 1],
		"Wynaut"		:[360, 1],
		"Snorunt "	:[361, 1],
		"Glalie"		:[362, 1],
		"Spheal"		:[363, 1],
		"Sealeo"		:[364, 1],
		"Walrein"	:[365, 1],
		"Clamperl"	:[366, 1],
		"Huntail"	:[367, 1],
		"Gorebyss"	:[368, 1],
		"Relicanth"	:[369, 1],
		"Luvdisc"	:[370, 1],
		"Bagon"		:[371, 1],
		"Shelgon"	:[372, 1],
		"Salamence"	:[373, 1],
		"Beldum"		:[374, 1],
		"Metang"		:[375, 1],
		"Metagross"	:[376, 1],
		"Regirock"	:[377, 1],
		"Regice"		:[378, 1],
		"Registeel"	:[379, 1],
		"Latias"		:[380, 1],
		"Latios"		:[381, 1],
		"Kyogre"		:[382, 1],
		"Groudon"	:[383, 1],
		"Rayquaza"	:[384, 1],
		"Jirachi"	:[385, 1],
		"Deoxys"		:[386, 1],
		"Turtwig"	:[387, 1],
		"Grotle"		:[388, 1],
		"Torterra"	:[389, 1],
		"Chimchar"	:[390, 1],
		"Monferno"	:[391, 1],
		"Infernape"	:[392, 1],
		"Piplup"		:[393, 1],
		"Prinplup"	:[394, 1],
		"Empoleon"	:[395, 1],
		"Starly"		:[396, 1],
		"Staravia"	:[397, 1],
		"Staraptor"	:[398, 1],
		"Bidoof"		:[399, 1],
		"Bibarel"	:[400, 1],
		"Kricketot"	:[401, 1],
		"Kricketune":[402, 1],
		"Shinx"		:[403, 1],
		"Luxio"		:[404, 1],
		"Luxray"		:[405, 1],
		"Budew"		:[406, 1],
		"Roserade"	:[407, 1],
		"Cranidos"	:[408, 1],
		"Rampardos"	:[409, 1],
		"Shieldon"	:[410, 1],
		"Bastiodon"	:[411, 1],
		"Burmy"		:[412, 1],
		"Wormadam"	:[413, 1],
		"Mothim"		:[414, 1],
		"Combee"		:[415, 1],
		"Vespiquen"	:[416, 1],
		"Pachirisu"	:[417, 1],
		"Buizel"		:[418, 1],
		"Floatzel"	:[419, 1],
		"Cherubi"	:[420, 1],
		"Cherrim"	:[421, 1],
		"Shellos"	:[422, 1],
		"Gastrodon"	:[423, 1],
		"Ambipom"	:[424, 1],
		"Drifloon"	:[425, 1],
		"Drifblim"	:[426, 1],
		"Buneary"	:[427, 1],
		"Lopunny"	:[428, 1],
		"Mismagius"	:[429, 1],
		"Honchkrow"	:[430, 1],
		"Glameow"	:[431, 1],
		"Purugly"	:[432, 1],
		"Chingling"	:[433, 1],
		"Stunky"		:[434, 1],
		"Skuntank"	:[435, 1],
		"Bronzor"	:[436, 1],
		"Bronzong"	:[437, 1],
		"Bonsly"		:[438, 1],
		"Mime Jr."	:[439, 1],
		"Happiny"	:[440, 1],
		"Chatot"		:[441, 1],
		"Spiritomb"	:[442, 1],
		"Gible"		:[443, 1],
		"Gabite"		:[444, 1],
		"Garchomp"	:[445, 1],
		"Munchlax"	:[446, 1],
		"Riolu"		:[447, 1],
		"Lucario"	:[448, 1],
		"Hippopotas":[449, 1],
		"Hippowdon"	:[450, 1],
		"Skorupi"	:[451, 1],
		"Drapion"	:[452, 1],
		"Croagunk"	:[453, 1],
		"Toxicroak"	:[454, 1],
		"Carnivine"	:[455, 1],
		"Finneon"	:[456, 1],
		"Lumineon"	:[457, 1],
		"Mantyke"	:[458, 1],
		"Snover"		:[459, 1],
		"Abomasnow"	:[460, 1],
		"Weavile"	:[461, 1],
		"Magnezone"	:[462, 1],
		"Lickilicky":[463, 1],
		"Rhyperior"	:[464, 1],
		"Tangrowth"	:[465, 1],
		"Electivire":[466, 1],
		"Magmortar"	:[467, 1],
		"Togekiss"	:[468, 1],
		"Yanmega"	:[469, 1],
		"Leafeon"	:[470, 1],
		"Glaceon"	:[471, 1],
		"Gliscor"	:[472, 1],
		"Mamoswine"	:[473, 1],
		"Porygon-Z"	:[474, 1],
		"Gallade"	:[475, 1],
		"Probopass"	:[476, 1],
		"Dusknoir"	:[477, 1],
		"Froslass"	:[478, 1],
		"Rotom"		:[479, 1],
		"Uxie"		:[480, 1],
		"Mesprit"	:[481, 1],
		"Azelf"		:[482, 1],
		"Dialga"		:[483, 1],
		"Palkia"		:[484, 1],
		"Heatran"	:[485, 1],
		"Regigigas"	:[486, 1],
		"Giratina"	:[487, 1],
		"Cresselia"	:[488, 1],
		"Phione"		:[489, 1],
		"Manaphy"	:[490, 1],
		"Darkrai"	:[491, 1],
		"Shaymin"	:[492, 1],
		"Arceus"		:[493, 1]
	}
	if not (PKMName in pokedex):
		print ("Unable to find Pokemon with the name: " + PKMName)
		sys.exit(1)

	PKM_checksum_1 =  (int(binascii.hexlify(data[(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
	PKM_checksum_2 =  (int(binascii.hexlify(data[(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
	PRNG(data,PKM_checksum_1,1,version)
	PRNG(data,PKM_checksum_2,2,version)

	try:

		# Update PKM species
		data[small_block_1+version["lead_PKM_offset"]+blockOffsets[0]+pokemon["species_id"]] = int(bin(pokedex[PKMName][0])[2:][-8:],2)
		data[small_block_1+version["lead_PKM_offset"]+blockOffsets[0]+pokemon["species_id"]+1] = pokedex[PKMName][1]
		data[small_block_2+version["lead_PKM_offset"]+blockOffsets[0]+pokemon["species_id"]] = int(bin(pokedex[PKMName][0])[2:][-8:],2)
		data[small_block_2+version["lead_PKM_offset"]+blockOffsets[0]+pokemon["species_id"]+1] = pokedex[PKMName][1]

		# Update PKM name
		newname = PKMName.upper()
		for i in range(0,22):
			data[small_block_1+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+i] = 0
			data[small_block_2+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+i] = 0

		for i in range(0,len(newname)*2,2):
			data[small_block_1+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+i] = toGameEncode(newname[i//2])
			data[small_block_1+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+i+1] = 1
			data[small_block_2+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+i] = toGameEncode(newname[i//2])
			data[small_block_2+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+i+1] = 1

		data[small_block_1+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+len(newname)*2] = 0xff
		data[small_block_1+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+len(newname)*2+1] = 0xff
		data[small_block_2+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+len(newname)*2] = 0xff
		data[small_block_2+version["lead_PKM_offset"]+blockOffsets[2]+pokemon["nickname"]+len(newname)*2+1] = 0xff


		updatePKMChecksum(data,data[(small_block_1+version["lead_PKM_offset"]+0x08):(small_block_1+version["lead_PKM_offset"]+0x88)],version)
		updatePKMChecksum(data,data[(small_block_2+version["lead_PKM_offset"]+0x08):(small_block_2+version["lead_PKM_offset"]+0x88)],version)
		PKM_checksum = (int(binascii.hexlify(data[(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
		PKM_checksum = (int(binascii.hexlify(data[(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
		PRNG(data,PKM_checksum,1,version)
		PRNG(data,PKM_checksum,2,version)

	except:
		return "Failed to edit species"


def editAbility(data,newability,blockOffsets,version):
	abilityIndex = {
		"Adaptability":91,
		"Aftermath":106,
		"Air Lock":76,
		"Anger Point":83,
		"Anticipation":107,
		"Arena Trap":71,
		"Bad Dreams":123,
		"Battle Armor":4,
		"Blaze":66,
		"Chlorophyll":34,
		"Clear Body":29,
		"Cloud Nine":13,
		"Color Change":16,
		"Compound Eyes":14,
		"Cute Charm":56,
		"Damp":6,
		"Download":88,
		"Drizzle":2,
		"Drought":70,
		"Dry Skin":87,
		"Early Bird":48,
		"Effect Spore":27,
		"Filter":111,
		"Flame Body":49,
		"Flash Fire":18,
		"Flower Gift":122,
		"Forecast":59,
		"Forewarn":108,
		"Frisk":119,
		"Gluttony":82,
		"Guts":62,
		"Heatproof":85,
		"Honey Gather":118,
		"Huge Power":37,
		"Hustle":55,
		"Hydration":93,
		"Hyper Cutter":52,
		"Ice Body":115,
		"Illuminate":35,
		"Immunity":17,
		"Inner Focus":39,
		"Insomnia":15,
		"Intimidate":22,
		"Iron Fist":89,
		"Keen Eye":51,
		"Klutz":103,
		"Leaf Guard":102,
		"Levitate":26,
		"Lightning Rod":31,
		"Limber":7,
		"Liquid Ooze":64,
		"Magic Guard":98,
		"Magma Armor":40,
		"Magnet Pull":42,
		"Marvel Scale":63,
		"Minus":58,
		"Mold Breaker":104,
		"Motor Drive":78,
		"Multitype":121,
		"Natural Cure":30,
		"No Guard":99,
		"Normalize":96,
		"Oblivious":12,
		"Overgrow":65,
		"Own Tempo":20,
		"Pickup":53,
		"Plus":57,
		"Poison Heal":90,
		"Poison Point":38,
		"Pressure":46,
		"Pure Power":74,
		"Quick Feet":95,
		"Rain Dish":44,
		"Reckless":120,
		"Rivalry":79,
		"Rock Head":69,
		"Rough Skin":24,
		"Run Away":50,
		"Sand Stream":45,
		"Sand Veil":8,
		"Scrappy":113,
		"Serene Grace":32,
		"Shadow Tag":23,
		"Shed Skin":61,
		"Shell Armor":75,
		"Shield Dust":19,
		"Simple":86,
		"Skill Link":92,
		"Slow Start":112,
		"Sniper":97,
		"Snow Cloak":81,
		"Snow Warning":117,
		"Solar Power":94,
		"Solid Rock":116,
		"Soundproof":43,
		"Speed Boost":3,
		"Stall":100,
		"Static":9,
		"Steadfast":80,
		"Stench":1,
		"Sticky Hold":60,
		"Storm Drain":114,
		"Sturdy":5,
		"Suction Cups":21,
		"Super Luck":105,
		"Swarm":68,
		"Swift Swim":33,
		"Synchronize":28,
		"Tangled Feet":77,
		"Technician":101,
		"Thick Fat":47,
		"Tinted Lens":110,
		"Torrent":67,
		"Trace":36,
		"Truant":54,
		"Unaware":109,
		"Unburden":84,
		"Vital Spirit":72,
		"Volt Absorb":10,
		"Water Absorb":11,
		"Water Veil":41,
		"White Smoke":73,
		"Wonder Guard":25
	}

	if not (newability in abilityIndex):
		print ("Unable to find ability with the name: " + newability)
		sys.exit(1)

	try:

		PKM_checksum_1 =  (int(binascii.hexlify(data[(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
		PKM_checksum_2 =  (int(binascii.hexlify(data[(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
		PRNG(data,PKM_checksum_1,1,version)
		PRNG(data,PKM_checksum_2,2,version)
		data[small_block_1+version["lead_PKM_offset"]+blockOffsets[0]+pokemon["ability"]] = abilityIndex[newability] 
		data[small_block_2+version["lead_PKM_offset"]+blockOffsets[0]+pokemon["ability"]] = abilityIndex[newability] 
		updatePKMChecksum(data,data[(small_block_1+version["lead_PKM_offset"]+0x08):(small_block_1+version["lead_PKM_offset"]+0x88)],version)
		updatePKMChecksum(data,data[(small_block_2+version["lead_PKM_offset"]+0x08):(small_block_2+version["lead_PKM_offset"]+0x88)],version)
		PKM_checksum_1 = (int(binascii.hexlify(data[(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_1+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
		PKM_checksum_2 = (int(binascii.hexlify(data[(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]):(small_block_2+version["lead_PKM_offset"]+pokemon["PKM_checksum_offset"]+2)][::-1]),16))
		PRNG(data,PKM_checksum_1,1,version)
		PRNG(data,PKM_checksum_2,2,version)

	except:
		return "Failed to edit ability"

def main():

	parser = argparse.ArgumentParser(description = "Edit trainer name, lead pokemon species or ability")
	parser.add_argument("-v","--version",type=str,required=True,help="Game version. Options:['diamond', 'pearl', 'platinum', 'heartgold', 'soulsilver']" )
	parser.add_argument("-f","--file",type=str,required=True,help="Name of the save file to be edited")
	parser.add_argument("-n","--name",type=str,help="New trainer name")
	parser.add_argument("-p","--pkm",type=str,help="Pokemon name. Example:'Pikachu'")
	parser.add_argument("-a","--ability",type=str,help="Name of new ability. Example:'Static'")
	args = parser.parse_args()

	if not args.version in versions:
		print ("No matches for version named: " + args.version)
		sys.exit(1)

	version = versions[args.version]
	flag = 0

	with open(args.file, "rb") as input:
		sav = (bytearray(input.read()))

		if args.name:
			changePlayerName(args.name,sav,version)
			flag = 1

		if args.pkm:
			editSpecies(sav,args.pkm,getBlockOffsets(getPV(sav,version)),version)
			flag = 1

		if args.ability:
			editAbility(sav,args.ability,getBlockOffsets(getPV(sav,version)),version)
			flag = 1

		if flag:
			updateChecksum(sav,sav[small_block_1:small_block_1+(version["small_block_checksum_offset"])],1,version)
			updateChecksum(sav,sav[small_block_2:small_block_2+(version["small_block_checksum_offset"])],2,version)

	with open(args.file, "wb") as output:
		output.write(sav)

if __name__ == "__main__":
	main()
