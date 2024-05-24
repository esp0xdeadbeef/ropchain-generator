#!/usr/bin/env python3

from string import Template
import re

class GadgetFinder:
    def __init__(self, gadgets):
        self.gadgets = gadgets  # Assuming gadgets is a dict provided during class instantiation

    def registers(self):
        re_only_register_arr = [
            r"(r|e)?ax|a[l|h]",                 # Matches rax, eax, ax, al, ah
            r"(r|e)?bx|b[l|h]",                 # Matches rbx, ebx, bx, bl, bh
            r"(r|e)?cx|c[l|h]",                 # Matches rcx, ecx, cx, cl, ch
            r"(r|e)?dx|d[l|h]",                 # Matches rdx, edx, dx, dl, dh
            r"(r|e)?si|sil",                    # Matches rsi, esi, si, sil
            r"(r|e)?di|dil",                    # Matches rdi, edi, di, dil
            r"(r|e)?bp|bpl",                    # Matches rbp, ebp, bp, bpl
            r"(r|e)?sp|spl",                    # Matches rsp, esp, sp, spl
            r"[cdefgs]s",                       # Matches segment registers ("cs", "ds", "es", "fs", "gs", "ss")
            r"cr[0-8]", r"dr[0-7]",               # Matches control and debug registers
            r"st\([0-7]\)",                      # Matches FPU stack registers
            r"mm[0-7]",                          # Matches MMX registers
            r"xmm[0-2]?[0-9]", r"xmm3[01]",       # Matches XMM registers
            r"ymm[0-2]?[0-9]", r"ymm3[01]",       # Matches YMM registers
            r"zmm[0-2]?[0-9]", r"zmm3[01]",       # Matches ZMM registers
            r"r(3[01]|[12][0-9]|[89])[dwb]?"     # Matches R8-R31
            r"(r|e)?ip"                         # Matches instruction pointer register
        ]

        re_only_register = "(" + '|'.join(re_only_register_arr) + ")"
        return re_only_register


    def generate_tiered_gadgets(self):
        re_only_register = self.registers()
        re_register_extended = fr"({re_only_register}|[re]?[abcd]x|[re]?sp|[re]?bp|[re]?si|[re]?di|[re]?[0-8]d)"
        
        re_only_register = self.registers()

        # Memory and address patterns
        re_memory_type = r"(qword|dword|word|byte)"
        re_hex_address = r"0x[a-fA-F\d]+"
        re_number_or_hex = r"[\da-fA-F+-x]*"

        # Brackets and numbers
        re_simple_bracket_start = r"\["
        re_simple_bracket_end = r"\]"
        re_simple_number = r"\d+"

        # Composite patterns
        re_register_extended = fr"(({re_memory_type}\s*{re_simple_bracket_start})?{re_only_register}{re_number_or_hex}({re_simple_bracket_end})?|{re_hex_address})"
        re_register_or_number = fr"({re_register_extended}|{re_simple_number})"

        base_patterns = [
            Template(r"xchg $re_register_or_number, $re_register_or_number"),
            Template(r"inc $re_register_or_number"),
            Template(r"dec $re_register_or_number"),
            Template(r"mov(\w)* $re_register_or_number, $re_register_or_number"),
            Template(r"push $re_register_or_number;pop $re_register_or_number"),
            Template(r"xor $re_register_or_number, $re_register_or_number"),
            Template(r"or $re_register_or_number, $re_register_or_number"),
            Template(r"neg $re_register_or_number"),
            Template(r"not $re_register_or_number"),
            Template(r"add $re_register_or_number, $re_register_or_number"),
            Template(r"sub $re_register_or_number, $re_register_or_number"),
            Template(r"(sal|sar|shl|shr) $re_register_or_number, $re_register_or_number"),
            Template(r"lea $re_register_or_number, $re_register_or_number"),
            Template(r"ro[rl] $re_register_or_number, $re_register_or_number"),
            Template(r"pushad"),
            Template(r"popad"),
            Template(r"pushf"),
            Template(r"popf"),
            Template(r"push $re_register_or_number"),
            Template(r"pop $re_register_or_number"),
            Template(r"adc $re_register_or_number, $re_register_or_number"),
            Template(r"sbb $re_register_or_number, $re_register_or_number"),
            Template(r"stc"),
            Template(r"clc"),
            Template(r"int3"),

        ]

        s_tier_gadgets = []
        a_tier_gadgets = []
        b_tier_gadgets = []
        c_tier_gadgets = []
        d_tier_gadgets = []
        e_tier_gadgets = []
        f_tier_gadgets = []

        re_only_register = re_only_register.replace(' ', r'(\s)+')
        re_register_extended = re_register_extended.replace(' ', r'(\s)+')
        ends_with = r'ret(n 0x[a-fA-F\d]+)?$'
        for template in base_patterns:
            s_tier_gadgets.append(template.substitute(re_register_or_number=re_only_register) + ";" + r"ret(n 0x[0]+)?$")
            a_tier_gadgets.append(template.substitute(re_register_or_number=re_register_or_number) + ";" + r"ret(n 0x[0]+)?$")
            b_tier_gadgets.append(template.substitute(re_register_or_number=re_register_or_number) + ";" + ends_with)
            c_tier_gadgets.append(template.substitute(re_register_or_number=re_register_extended) + ".*" + ends_with)
            d_tier_gadgets.append(template.substitute(re_register_or_number=re_register_extended) + ".*")
            e_tier_gadgets.append(template.substitute(re_register_or_number=".*" + re_register_extended) + ".*")
            f_tier_gadgets.append(".*" + template.substitute(re_register_or_number=".*" + re_register_extended) + ".*")

        return {
            "S-tier": s_tier_gadgets,
            "A-tier": a_tier_gadgets,
            "B-tier": b_tier_gadgets,
            "C-tier": c_tier_gadgets,
            "D-tier": d_tier_gadgets,
            "E-tier": e_tier_gadgets,
            "F-tier": f_tier_gadgets
        }

    def get_good_registers(self, filtered_words = [
            ";leave;",
            "[fs:0x00000000]",
            "jmp ",
            "call ",
        ]):
        import re
        tiered_gadgets = self.generate_tiered_gadgets()
        worthy_instructions = {}
        for tier_name, gadgets in tiered_gadgets.items():
            print(f"Processing {tier_name}")
            for regex in gadgets:
                values = []
                for gadget in self.gadgets.keys():
                    if any(blacklisted in gadget for blacklisted in filtered_words):
                        continue
                    if re.match(regex, gadget):
                        values.append(gadget)
                if len(values) != 0:
                    key_name = regex
                    worthy_instructions[tier_name + " " + key_name] = values
        return worthy_instructions


if __name__ == "__main__":
    import json
    with open('./gadgets.json') as f:
        a = GadgetFinder(json.loads(f.read()) )

    regs = json.dumps(a.get_good_registers(), indent=4)
    with open('usefull_gadgets_3.json', 'w') as f:
        f.write(regs)