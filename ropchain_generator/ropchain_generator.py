#!/usr/bin/env python3
from . import gadget_processor
from . import helper_functions
import json



class RopChainGenerator(object):
    def __init__(self, gadget_file:str, check_gadgets:False, check_gadgets_ks:False, comment_failed_gadgets:False, offset_library = 0, x32 = True):
        self.check_gadgets_ks = check_gadgets_ks
        self.check_gadgets = check_gadgets
        self.comment_failed_gadgets = comment_failed_gadgets
        self.instruction_array = []
        self.online_ropchain = []
        self.used_instructions = {}
        self.CODE = ""
        self.offset_library = offset_library
        self.offset_from_esp = 0
        self.gadget_processor_obj = gadget_processor.GadgetProcessor(gadget_file)
        self.gadgets = self.gadget_processor_obj.gadgets
        self.helper_functions = helper_functions.HelperFunctions()
        self.x32 = x32
        if check_gadgets_ks:
            from keystone import Ks, KS_ARCH_X86
            if self.x32:
                from keystone import KS_MODE_32
                self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            if not(self.x32) and check_gadgets_ks:
                from keystone import KS_MODE_64
                self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    
    def set_offset_from_esp(self, offset_from_esp):
        self.offset_from_esp = int(offset_from_esp)

    def set_code_template(self, location:str):
        with open(location, 'r') as f:
            self.CODE = f.read()
    
    def init_code_template(self):
        from os import path
        if self.x32:
            asm_blueprint_file_location = path.join(path.dirname(__file__), "asm_blueprint.asm")
        else:
            asm_blueprint_file_location = path.join(path.dirname(__file__), "asm_blueprint_x64.asm")
        self.set_code_template(asm_blueprint_file_location)



    def set_instruction(self, instruction, amount = 1, replace_function_offline = "", replace_asm_offline = ""):
        """
        Use this to get the address of a specific instruction.
        """
        from struct import pack
        instruction = self.helper_functions.parse_gadgets_re(instruction)
        # i_o = Instruction(is_instruction=True)
        if replace_asm_offline == "" and replace_function_offline == "":
            self.cache_function(instruction)
        for i in range(amount):
            inst = Instruction(is_instruction=True, x32 = self.x32)
            function_name = self.clean_function_name(instruction)
            inst.set_instruction(function_name)
            if replace_function_offline != "":
                inst.function_name = replace_function_offline
            if replace_asm_offline != "":
                template_content = "\n  ; !!!! SPECIAL asm code, differs from online !!!\n"
                inst.instruction_or_data_template.template = template_content + replace_asm_offline
            elif replace_function_offline != "":
                template_content = ""
                template_content += "\n  ; !!!! SPECIAL FUNCTION, differs from online !!! pushing instruction to the stack:"
                template_content += "\n  xor $data_cpu_register, $data_cpu_register"
                template_content += "\n  add $data_cpu_register, $function_name" 
                if self.x32:
                    template_content += "\n  mov [ebp + $current_offset], $data_cpu_register"
                else:
                    template_content += "\n  mov [rbp + $current_offset], $data_cpu_register"
                inst.instruction_or_data_template.template = template_content

            self.instruction_array.append(inst)
                # print(inst.get_asm_stack())
        retval = self.gadgets[instruction]
        retval = amount * pack("<L", (int(retval, 16) + self.offset_library))
        self.online_ropchain.append(retval)
        return retval
        
    def set_data(self, data, amount = 1, replace_function_offline = "", replace_asm_offline = ""):
        from struct import pack
        
        for i in range(amount):
            if replace_function_offline != "" or replace_asm_offline != "":
                try:
                    self.set_instruction("FAKE INSTRUCTION", amount=amount, replace_function_offline=replace_function_offline, replace_asm_offline=replace_asm_offline)
                    self.instruction_array.append(inst)
                except KeyError:
                    pass
            else:
                inst = Instruction(is_instruction=False, x32 = self.x32)
                inst.set_data(data)
                self.instruction_array.append(inst)
        return amount * pack("<L", data)
    

    def cache_function(self, instruction):
        function_name = self.clean_function_name(instruction)
        if len(function_name) == 0:
            return
        opcodes = self.clean_opcodes_name(instruction)
        self.used_instructions[function_name] = opcodes
        
    def get_code(self):
        # remove the placeholders:
        retval = self.CODE.replace("FUNCTIONS_TO_REPLACE", "")
        retval = retval.replace("EBP_OFFSET_CALL_FUNCTION", "")
        return retval

    def clean_function_name(self, asm_string):
        """
        This will clean the illigal chars and replaces [0x12..] with "MEM_" 0x12.. "_ADDRESS" and instructions with ; to and
        """
        replace_list_for_function_name = [" ", ";", ",", "[", "]", "-", "+", "*", ":"]
        asm_string = asm_string.replace("[", "MEM_").replace("]", "_ADDRESS").replace(";", "_and_")
        for i in replace_list_for_function_name:
            asm_string = asm_string.replace(i, "_")
        while asm_string.find('__') != -1:
            asm_string = asm_string.replace('__', '_')
        return asm_string



    def get_good_registers(self, filtered_words = [
            ";leave;",
            "[fs:0x00000000]",
            "enter",
            "jmp ",
            "call ",
        ]):
        return self.gadget_processor_obj.gadget_finder_obj.get_good_registers(filtered_words)

    def get_good_registers_str(self, filtered_words = [
            ";leave;",
            "[fs:0x00000000]",
            "enter",
            "jmp ",
            "call ",
        ]):
        return json.dumps(self.get_good_registers(filtered_words), indent=4)


    def clean_opcodes_name(self, asm_string):
        """
        This function will convert the tags below to the corruspandong function in KeyStone Engine.
        it afterwards compiles it with the Ks enginge to check if the function is correct
        """
        special_ptr_instructions = [
            "rcr",
            "and",
            "fcomp",
            "mov",
            "cmp",
            "dec",
            "fadd",
            "fiadd",
            "fild",
            "fisub",
            "fmul",
            "fild",
            "fisub",
            "fmul",
            "fst",
            "not",
            "or",
            "rol",
            "ror",
            "sar",
            "shl",
        ]
        replace_hex_to_ints = [
            "sal", 
            "rol", 
            "sar", 
            "ror"
        ]
        result = []
        for line in asm_string.split(";"):
            line = line.replace("retn", "ret").replace(":0x00000000", "").strip()
            special_line = False
            for special_ptr_instruction in special_ptr_instructions:
                if special_ptr_instruction in line:
                    result.append(line.replace("[", "ptr ["))
                    special_line = True
                    break

            for replace_hex_to_int in replace_hex_to_ints:
                if replace_hex_to_int in line:
                    if not special_line:
                        asm_dest_and_instr = line.split(",")[0]
                        asm_value = line.split(",")[1]
                    else:
                        changed_line = result.pop(-1)
                        asm_dest_and_instr = changed_line.split(",")[0]
                        asm_value = changed_line.split(",")[1]
                    result.append(f"{asm_dest_and_instr}, {self.helper_functions.overflow_integer_to_negative(asm_value)}")
                    special_line = True
                    break

            if not special_line:
                result.append(self.helper_functions.replace_datatypes(line))
            
            if self.check_gadgets_ks:
                from keystone import KsError
                try:
                    self.ks.asm(result[-1])
                except KsError as e:
                    # print("here")
                    print(
                        f"{result[-1]} ; has errors (ks.asm cannot handle it, popping it), original statment:\n{line}"
                    )
                    a = result.pop(-1)
                    result.append("  ; " + a + " Error " + str(e))

        return "  " + "\n  ".join(result)

    def parse_user_supplied_gadgets(self, user_gadgets):
        used_gadgets = []
        for user_gadget in user_gadgets.split('\n'):
            user_gadget = self.parse_gadgets_re(user_gadget)
            if user_gadget == "":
                continue
            try:
                self.gadgets[user_gadget]
                used_gadgets.append(user_gadget)
            except KeyError as a:
                if not(self.comment_failed_gadgets):
                    raise SystemExit(f"Failed to parse:\n{user_gadget}\nif you want to ignore this error, use:\ncomment_failed_gadgets")
                used_gadgets.append(" ; " + user_gadget)
        return used_gadgets

    

    def offline_make_asm_code(self):
        if self.CODE == "":
            self.init_code_template()
        current_offset = 0
        for line in self.instruction_array:
            
            current_offset = line.set_current_offset(current_offset)
            # print(current_offset)
            self.CODE = self.CODE.replace(
                "EBP_OFFSET_CALL_FUNCTION",
                line.get_asm_stack() + "EBP_OFFSET_CALL_FUNCTION",
            )
        
        if self.offset_from_esp != 0:
            if self.x32:
                self.CODE = self.CODE.replace("EBP_OFFSET_CALL_FUNCTION", f"\n\n  add esp, {hex(self.offset_from_esp)}\nEBP_OFFSET_CALL_FUNCTION")
            else:
                self.CODE = self.CODE.replace("EBP_OFFSET_CALL_FUNCTION", f"\n\n  add rsp, {hex(self.offset_from_esp)}\nEBP_OFFSET_CALL_FUNCTION")


        for key, value in self.used_instructions.items():
            self.CODE = self.CODE.replace(
                "FUNCTIONS_TO_REPLACE", key + ":\n" + value + "\nFUNCTIONS_TO_REPLACE"
            )
        
        return self.CODE.replace("FUNCTIONS_TO_REPLACE", "").replace("EBP_OFFSET_CALL_FUNCTION", "")


class Instruction(object):
    def __init__(self, is_instruction, data_cpu_register = "ebx"):
        from string import Template
        self.data_cpu_register = data_cpu_register
        self.current_offset = 0
        self.used_space = 0
        self.is_instruction = is_instruction
        if self.x32:
            edi = "edi"
            ebp = "ebp"
        else:
            edi = "rdi"
            ebp = "rbp"

        template_content = ""
        if is_instruction:
            template_content += "\n  ; pushing instruction to the stack:"
            template_content += f"\n  mov $data_cpu_register, {edi}"
            template_content += "\n  add $data_cpu_register, $function_name" 
            template_content += f"\n  mov [{ebp} + $current_offset], $data_cpu_register"
        else:
            template_content += "\n  ; pushing data to the stack:"
            template_content += "\n  mov $data_cpu_register, $hex_data"
            template_content += f"\n  mov [{ebp} + $current_offset], $data_cpu_register"
        self.instruction_or_data_template = Template(template_content)

    def set_current_offset(self, offset):
        self.current_offset = abs(offset)
        return self.get_new_offset()

    def make_variables(self):
        self.variables = {
            'data_cpu_register': self.data_cpu_register,
            'current_offset': hex(self.current_offset),
        }
        if self.is_instruction:
            self.variables['function_name'] = self.function_name
        else:
            self.variables['hex_data'] = self.data

    def set_instruction(self, instruction, changed_instruction = ""):
        self.is_instruction = True
        self.parse_gadgets_re(instruction)
        self.parse_gadgets_re(changed_instruction)
        self.function_name = instruction
        self.used_space = 4
    
    def set_data(self, data=0x41414141):
        self.is_instruction = False
        # print(data)
        self.data = hex(int(data))
        self.used_space = int(len(self.data[2:]) / 2 + (len(self.data[2:]) % 2 > 0))
        return data
    
    def get_asm_stack(self):
        self.make_variables()
        # print(self.instruction_or_data_template.template)
        # print(self.variables)
        # print(self.is_instruction)
        retval = self.instruction_or_data_template.substitute(self.variables)
        return retval

    def get_new_offset(self):
        # print("usedd space:", self.used_space)
        return self.current_offset + self.used_space

    def parse_gadgets_re(self, gadgets):
        import re
        gadgets = re.sub(r';(\s?)+\(\d+ found\)', '', gadgets)
        gadgets = re.sub(r'\s*;\s*', ';', gadgets).strip()
        return gadgets

if __name__ == '__main__':
    print(r"""helper function, please use it as an import e.g.:
import rop_chain_generator
rg = rop_chain_generator.RopChainGenerator(
    '.\gadgets.json',  # generated by optain_json_from_rp++.py 
    check_gadgets=True, 
    check_gadgets_ks=True, 
    comment_failed_gadgets=False
)         
           """)