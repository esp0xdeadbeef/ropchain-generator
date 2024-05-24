#!/usr/bin/env python3

"""
This script processes a given string for pwn purposes.

Original script by John Hammond:
https://gist.github.com/JohnHammond/f78a9d878585bad232cba060c1d79623

Edited by esp0xdeadbeef
"""

from pwn import *

class StringProcessor:
    def __init__(self, input_string, as_python_string=False):
        if not input_string:
            raise ValueError("Please provide a non-empty string.")
        
        self.string = input_string.encode()
        self.as_python_string = as_python_string
        self.full = "eax"
        self.half = "ax"
        self.little = "al"
        self.pieces = self._split_string()
    
    def _split_string(self):
        pieces = []
        for i in range(0, len(self.string), 4):
            chunk = self.string[i : i + 4]
            pieces.append((hex(unpack(chunk, "all")), chunk.decode("utf-8")))
        return pieces
    
    def _output_instruction(self, instruction, comment):
        if self.as_python_string:
            print(f'"{instruction};" # {comment}')
        else:
            print(f'{instruction} ; # {comment}')

    def process_string(self):
        counter = 0
        for each in self.pieces[::-1]:
            piece, value = each
            if len(piece) <= 10:
                register = self.full
            if len(piece) <= 6:
                self._output_instruction(f'xor {self.full}, {self.full}', f'zero out {self.full}')
                register = self.half
                self._output_instruction(f'mov {register}, {piece}', f'ensure nullbyte')
                self._output_instruction(f'push {self.full}', f"end of string '{value}' with nullbyte")
                counter += 1
                continue
            if len(piece) <= 4:
                self._output_instruction(f'xor {self.full}, {self.full}', f'zero out {self.full}')
                register = self.little
                self._output_instruction(f'mov {register}, {piece}', f'ensure nullbyte')
                self._output_instruction(f'push {self.full}', f"end of string '{value}' with nullbyte")
                counter += 1
                continue
            if counter == 0:
                self._output_instruction(f'xor {self.full}, {self.full}', f'zero out {self.full}')
                self._output_instruction(f'push {self.full}', 'ensure null byte')

            self._output_instruction(f'push {piece}', f"push '{value}' onto stack")
            counter += 1

def argparse_arguments():
    import argparse
    parser = argparse.ArgumentParser(description="Process a given string for pwn purposes.")
    parser.add_argument("string", type=str, help="Input string to process")
    parser.add_argument("--as-python-string", action='store_true', help="Output as a Python string format")
    args = parser.parse_args()

    processor = StringProcessor(args.string, args.as_python_string)
    processor.process_string()

if __name__ == "__main__":
    argparse_arguments()
