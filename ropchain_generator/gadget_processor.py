#!/usr/bin/env python3

import json
import re
import argparse
from . import gadget_finder

class GadgetProcessor:
    def __init__(self, input_path, output_path = ""):
        write_output = not(not(output_path))
        self.input_path = input_path
        self.output_path = output_path
        self.gadgets = {}
        self.read_rp_pp_output()
        has_processed_gadgets = self.process_gadgets()
        self.gadget_finder_obj = gadget_finder.GadgetFinder(self.gadgets)
        if has_processed_gadgets and write_output:
            self.write_output(output_path)
        elif write_output:
            print("Failed to process gadgets.")
    
    def get_gadgets_as_dict(self):
        return self.gadgets
        

    def process_gadgets(self):
        if self.gadgets:
            return True
        raw_gadgets = self.read_rp_pp_output()
        if raw_gadgets:
            self.gadgets = self.parse_gadgets(raw_gadgets)
            return True
        return False

    def read_rp_pp_output(self):
        try:
            with open(self.input_path, 'rb') as f:
                raw_input_file_in = f.read()
                raw_input_file = raw_input_file_in.decode('utf-16le') if b'\x00' in raw_input_file_in[:200] else raw_input_file_in.decode('latin-1')
        except Exception as e:
            print(f"Failed to read file due to: {e}")
            return None
        try:
            self.gadgets = json.loads(raw_input_file)
        except json.decoder.JSONDecodeError:
            pass
        return raw_input_file

    def parse_gadgets_re(self, gadgets):
        gadgets = re.sub(r';(\s?)+\(\d+ found\)', '', gadgets)
        gadgets = re.sub(r'\s*;\s*', ';', gadgets)
        gadgets = re.sub(r'\s*,\s*', ', ', gadgets)
        gadgets = re.sub(r'[ \t]+', ' ', gadgets)
        return gadgets

    def parse_gadgets(self, gadgets_as_str):
        rop_gadgets_all = self.parse_gadgets_re(gadgets_as_str)
        parsed_gadgets = {}
        for current_line in rop_gadgets_all.split('\n'):
            if ':' in current_line:
                address, instruction = current_line.split(':', 1)
                try:
                    address = hex(int(address.strip(), 16))
                    instruction = instruction.strip()
                    parsed_gadgets[instruction] = address
                except ValueError:
                    continue
        return parsed_gadgets

    def write_output(self, output_path):
        try:
            with open(output_path, 'w') as file:
                json.dump(self.gadgets, file, indent=4)
            print("Gadgets processed and output saved to JSON file.")
        except Exception as e:
            print(f"Failed to write output due to: {e}")
        try:
            good_registers = json.dumps(self.gadget_finder_obj.get_good_registers(), indent=4)
            with open(output_path.replace('.', "_classified."), 'w') as f:
                f.write(good_registers)
        except Exception as e:
            print(f"Failed to write output due to: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''Gadget Parser and JSON Output Generator
Example use:
cd (working directory with gadgets_plus_plus_output.out)
python gadget_processor.py -p gadgets_plus_plus_output.out -o gadgets.json
''')
    parser.add_argument('-p', '--path-rp-pp-output', help='Input location (path) of the gadgets file.', required=True)
    parser.add_argument('-o', '--output', help='JSON output location', required=True)
    args = parser.parse_args()
    gp = GadgetProcessor(input_path=args.path_rp_pp_output, output_path=args.output)