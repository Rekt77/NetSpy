import binascii

def MAC_format(string):
	temp = list()
	for i in range(0,len(string),2):
		try:
			temp.append(string[i:i+2])
		except:
			break;
	return ":".join(temp)


def hexdump(byte_sequence):
    byte_sequence = byte_sequence.hex()
    buffer = [byte_sequence[i:i+2] for i in range(0,len(byte_sequence),2)]
    offset = 0
    while offset < len(buffer):
        if ((len(buffer) - offset) < 0x10) is True:
            data = buffer[offset:]
        else:
            data = buffer[offset:offset + 0x10]
 
        # Hex Dump
        for hex_dump in data:
            print(hex_dump, end=' ')
 
        if ((len(buffer) - offset) < 0x10) is True:
            print(' ' * (3 * (0x10 - len(data))), end='')
 
        print('  ', end='')
 
        # Ascii
        for ascii_dump in data:
            if ((int(ascii_dump,16) >= 0x20) is True) and ((int(ascii_dump,16) <= 0x7E) is True):
                print(chr(int(ascii_dump,16)), end='')
            else:
                print('.', end='')
 
        offset = offset + len(data)
        print('')
        
def HeaderDisplay(header_name,header_byte_sequence):
    print("[+] %s header Raw byte sequence"%header_name)
    hexdump(header_byte_sequence)
    print('')