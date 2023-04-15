import idaapi
import idc

# Constants for XOR string analysis
MAX_XOR_STR_LEN = 64
MAX_XOR_STR_COUNT = 256

class XorStringDecoder(idaapi.plugin_t):
    flags = 0
    comment = "XOR String Decoder"
    help = "XOR String Decoder"
    wanted_name = "XOR String Decoder"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("[XOR String Decoder] Starting...")

        # List of found XOR strings
        xor_strings = []

        # List of byte strings that were found in the program
        byte_strings = []

        # Search for all byte strings in the program
        for i in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(i)
            if not seg:
                continue

            ea = seg.start_ea
            end_ea = seg.end_ea
            while ea < end_ea:
                byte_string = idaapi.get_strlit_contents(ea, MAX_XOR_STR_LEN, idaapi.ASCSTR_C)
                if byte_string:
                    byte_strings.append(byte_string)
                    ea += len(byte_string) + 1
                else:
                    ea += 1

        # Analysis of found byte strings and search for xor strings
        for byte_string in byte_strings:
            if len(byte_string) < 4 or len(xor_strings) >= MAX_XOR_STR_COUNT:
                continue

            xor_string = ""
            key = 0x0

            # Looking for a key to deobfuscate a string
            for i in range(2, MAX_XOR_STR_LEN):
                k = ord(byte_string[0]) ^ ord(byte_string[i])
                valid_key = True
                for j in range(1, len(byte_string)):
                    if (j == i):
                        continue
                    if (ord(byte_string[j]) ^ k) != ord(byte_string[j-1]):
                        valid_key = False
                        break
                if valid_key:
                    key = k
                    break

            # If the key is found, deobfuscate the string
            if key:
                for b in byte_string:
                    xor_string += chr(ord(b) ^ key)
                xor_strings.append(xor_string)

        # Showing the found xor strings to the user
        if xor_strings:
            print("[XOR String Decoder] Found %d xor strings:" % len(xor_strings))
            for xor_string in xor_strings:
                print("[XOR String Decoder]   %s" % xor_string)
        else:
            print("[XOR String Decoder] No xor strings found.")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return XorStringDecoder()
