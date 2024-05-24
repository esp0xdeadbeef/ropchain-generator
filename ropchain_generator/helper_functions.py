


class HelperFunctions():
    def make_mask(self, bit_mask = 32):
        return 2 ** bit_mask - 1
    
    def calculate_bitwise_not(self, n, bit_mask = 32):
        return (~n & self.make_mask(bit_mask))

    def calculate_negation(self, n, bit_mask = 32):
        return (~n + 1) & self.make_mask(bit_mask)
    
    def calculate_addition(self, target, constant, bit_mask = 32):
        result = (target + constant) & self.make_mask(bit_mask)
        return result
    
    def overflow_integer_to_negative(self, hex_value, bit_mask = 32):
        int_value = int(hex_value, 16)
        if int_value >= (1 << (self.make_mask(bit_mask) - 1)):
            int_value -= (1 << self.make_mask(bit_mask))
        return str(int_value)


    # def calculate_addition_bytes(self, array_with_values_4_long:list, datatype = 'I', bit_mask = 32):
    #     import struct
    #     retval = 0
    #     # print(array_with_values_4_long)
    #     for i in array_with_values_4_long:
    #         curr_i = struct.unpack(datatype, i)[0]
    #         retval = (curr_i + retval) & self.make_mask(bit_mask)
    #         # print(retval)
    #         # print(retval, hex(curr_i + retval), self.make_mask(bit_mask), struct.pack(datatype, retval))
    #     # print(retval)
    #     return struct.pack(datatype, retval)

    def calculate_subtraction(self, target, constant, bit_mask = 32):
            result = (target - constant) & self.make_mask(bit_mask)
            return result

    def find_incremental_replacement_indices(self, offsets, step_size = 4):    
        # Sort the offsets to ensure sequential evaluation
        replacement_indices = self.find_replacement_indices(offsets, step_size)
        # Convert to incremental differences
        incremental_indices = [replacement_indices[0]] if replacement_indices else []
        incremental_indices += [replacement_indices[i] - replacement_indices[i-1] for i in range(1, len(replacement_indices))]

        return incremental_indices

    def find_replacement_indices(self, offsets, step_size = 4):
        # Sort the offsets to ensure sequential evaluation
        sorted_offsets = sorted(offsets)
        
        # Initialize the list to store start indices for replacement
        replacement_indices = []

        # Iterate through the range, incrementing by step_size, to cover each segment
        for i in range(0, sorted_offsets[-1] + 1, step_size):
            for offset in sorted_offsets:
                if i <= offset < i + step_size:
                    replacement_indices.append(i)
                    break  # Found the first bad byte in this segment, move to the next
        return replacement_indices

    def map_bad_chars(self, payload, badchars = [b"\x00"]):
        BADCHARS = b"".join(badchars)
        i = 0
        badIndex = []
        while i < len(payload):
            for c in BADCHARS:
                if payload[i] == c:
                    badIndex.append(i)
            i=i+1
        return badIndex

    def escape_all_characters(self, buffer):
        result = []
        for byte in buffer:
            result.append(f'\\x{byte:02x}')
        return ''.join(result)
    
    def escaped_print(self, buffer):
        print(self.escape_all_characters(buffer))
    

    def generate_bad_chars(self, bad_chars_array=[]):
        filterd = b""
        for i in range(0x00, 0x100):
            if not (i in b"".join(bad_chars_array)):
                filterd += chr(i).encode('latin-1')
        return filterd


    def unpack_ints(self, buffer:bytes):
        import struct
        length = str(int(len(buffer)/4))
        # print(length)
        return struct.unpack(length + 'I',buffer)
        
    def unpack_ints_to_hex(self, buffer:bytes):
        
        retval = []
        for i in self.unpack_ints(buffer):
            retval.append(hex(i))
        return retval

    def print_unpack_ints(self, buffer):
        # a = self.unpack_ints(buffer)
        # retval = []
        # for i in a:
        #     retval.append(hex(i))
        # print(" ".join(retval))
        retval = " ".join(self.unpack_ints_to_hex(buffer))
        print(retval)
        return retval

    def parse_gadgets_re(self, gadgets):
        import re
        gadgets = re.sub(r';(\s?)+\(\d+ found\)', '', gadgets)
        gadgets = re.sub(r'\s*;\s*', ';', gadgets).strip()
        return gadgets

    def replace_datatypes(self, line):
        """
        remove the datatype if needed
        """
        data_types = ["dword ", "word ", "byte "]
        for i in data_types:
            line = line.replace(i, "")
        return line

    def simulate_padd(self, format_for_struct, binary_data_in:list):
        import struct
        """
        format_for_struct = "4I"
        binary_data = [p32(0xdeadbeef) * 4, p32(0xdeadbeef) * 4]
        """
        import re
        m_obj = re.match(r'([@|=|<|>|!])*(\d+)(\w+)', format_for_struct)  # Use \d+ for one or more digits and \w+ for one or more word characters

        if m_obj:
            splits = int(m_obj.group(2))
        else:
            print('Failed reading the length. (simulate_padd)')
            splits = 1

        size = struct.calcsize(format_for_struct) * 8 # in bits
        mask = 2 ** int(size / splits) - 1
        retval = [0 for x in range(splits)]
        for j in binary_data_in:
            for counter, i in enumerate(struct.unpack_from(format_for_struct, j)):
                retval[counter] = ((retval[counter] & mask) + (i & mask)) & mask
        return struct.pack(format_for_struct, *retval)

    def hex_q(self, variable):
        '''
    xmm0 = struct.pack('4I', *[0xdeadbeef] * 4)
    print(hex_q(xmm0))
    # (r xmm0:uq) xmm0=deadbeefdeadbeef deadbeefdeadbeef
        '''
        import struct
        retval = ""
        amount_of_qs=str(int(len(variable) / 8))
        q = struct.unpack_from('<'+amount_of_qs+'Q', variable)[::-1]
        import inspect
        current_frame = inspect.currentframe()
        try:
            frame_locals = current_frame.f_back.f_locals
            var_name = [name for name, value in frame_locals.items() if value is variable][0]
            retval = f"# (r {var_name}:uq) {var_name}="
        except IndexError:
            retval = f"# (r unknownvar:uq) unknownvar="
        finally:
            del current_frame
        
        retval += " ".join([hex(i)[2:].zfill(16) for i in q])
        return retval

    def print_hex_q(self, variable):
        print(self.hex_q(variable))
