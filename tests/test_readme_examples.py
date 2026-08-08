import json
import os
import sys

print("=" * 60)
print("TEST 1: HelperFunctions")
print("=" * 60)
import ropchain_generator
hf = ropchain_generator.HelperFunctions()

# Test basic operations
assert hf.calculate_addition(10, 20) == 30, "addition failed"
assert hf.calculate_subtraction(30, 10) == 20, "subtraction failed"
print(f"  calculate_addition(10, 20) = {hf.calculate_addition(10, 20)}")
print(f"  calculate_subtraction(30, 10) = {hf.calculate_subtraction(30, 10)}")
print(f"  calculate_bitwise_not(0xFF, 32) = {hex(hf.calculate_bitwise_not(0xFF, 32))}")
print(f"  calculate_negation(5) = {hf.calculate_negation(5)}")

# Test overflow_integer_to_negative - takes hex string
print(f"  overflow_integer_to_negative('FFFFFFFF', 32) = {hf.overflow_integer_to_negative('FFFFFFFF', 32)}")
print(f"  overflow_integer_to_negative('7FFFFFFF', 32) = {hf.overflow_integer_to_negative('7FFFFFFF', 32)}")

# Test bad char mapping
badchars = hf.map_bad_chars(b"\x00\x41\x42\x00", [b"\x00"])
print(f"  map_bad_chars for null bytes = {badchars}")

# Test escape/print
escaped = hf.escape_all_characters(b"\x41\x42\x43")
print(f"  escape_all_characters = {escaped}")

# Test unpack_ints
result = hf.unpack_ints_to_hex(b"\xef\xbe\xad\xde\x41\x41\x41\x41")
print(f"  unpack_ints_to_hex = {result}")

print("  HelperFunctions: OK\n")

# ============================================================
print("=" * 60)
print("TEST 2: GadgetFinder (from README example)")
print("=" * 60)
from ropchain_generator import GadgetFinder

# As shown in README:
gf = GadgetFinder({"xor eax, eax;ret": 1})
good_regs = gf.get_good_registers()

# Should find "xor eax, eax;ret" in multiple tiers
for tier_name in ["S-tier", "A-tier", "B-tier", "C-tier", "D-tier", "E-tier", "F-tier"]:
    found = False
    for key, values in good_regs.items():
        if tier_name in key and len(values) > 0:
            found = True
            print(f"  {key}: {values}")
            break
    if not found:
        print(f"  {tier_name}: (no matches)")

assert len(good_regs) > 0, "Should have found some gadgets"
print("  GadgetFinder: OK\n")

# ============================================================
print("=" * 60)
print("TEST 3: GadgetProcessor")
print("=" * 60)
from ropchain_generator import GadgetProcessor

# Create a mock rp++ output file (simulating what rp-win-x86 produces)
mock_rp_output = """0x00401234: xor eax, eax;ret
0x00405678: pop ebx;ret
0x0040abcd: mov eax, [ebp+8];ret
0x00401200: push ebp;mov ebp, esp;ret
0x0040beef: inc eax;ret
"""
mock_file = "/tmp/mock_gadgets.txt"
with open(mock_file, "w") as f:
    f.write(mock_rp_output)

gp = GadgetProcessor(mock_file)
gadgets = gp.get_gadgets_as_dict()
print(f"  Parsed {len(gadgets)} gadgets:")
for instr, addr in gadgets.items():
    print(f"    {addr}: {instr}")

assert len(gadgets) == 5, f"Expected 5 gadgets, got {len(gadgets)}"
assert "xor eax, eax;ret" in gadgets
assert gadgets["inc eax;ret"] == "0x40beef"
print("  GadgetProcessor: OK\n")

# ============================================================
print("=" * 60)
print("TEST 4: RopChainGenerator")
print("=" * 60)
from ropchain_generator import RopChainGenerator

# Write gadgets to JSON file (as the constructor expects JSON)
gadgets_json_file = "/tmp/gadgets.json"
with open(gadgets_json_file, "w") as f:
    json.dump(gadgets, f)

# Test x32 mode
rgen = RopChainGenerator(
    gadget_file=gadgets_json_file,
    check_gadgets=True,
    check_gadgets_ks=False,  # skip keystone asm verification for speed
    comment_failed_gadgets=False,
    offset_library=0,
    x32=True
)

# Build a simple ROP chain: zero eax, set esp, place data
payload = b""
payload += rgen.set_instruction("xor eax, eax;ret")
payload += rgen.set_instruction("inc eax;ret")
payload += rgen.set_data(0xdeadbeef)

print(f"  ROP chain payload ({len(payload)} bytes): {payload.hex()}")

# Generate the offline ASM code
rgen.init_code_template()
asm_code = rgen.offline_make_asm_code()
print(f"  Generated ASM code ({len(asm_code)} chars)")
# Should contain the function labels
assert "xor_eax_eax_and_ret" in asm_code, "Missing xor gadget in ASM"
assert "inc_eax_and_ret" in asm_code, "Missing inc gadget in ASM"
assert "FUNCTIONS_TO_REPLACE" not in asm_code, "Template not fully substituted"
assert "EBP_OFFSET_CALL_FUNCTION" not in asm_code, "Offset placeholder not substituted"
print("  RopChainGenerator: OK\n")

# ============================================================
print("=" * 60)
print("TEST 5: HelperFunctions - simulate_padd")
print("=" * 60)
import struct
from pwn import p32
fmt = "4I"
# Each element must match the struct size (16 bytes for "4I")
data_in = [p32(1) * 4, p32(2) * 4, p32(3) * 4]
result = hf.simulate_padd(fmt, data_in)
print(f"  simulate_padd(4I, [1*4, 2*4, 3*4]) = {result.hex()}")
# Expected: 1+2+3 = 6 in each I slot
expected = struct.pack("4I", 6, 6, 6, 6)
assert result == expected, f"Expected {expected.hex()}, got {result.hex()}"
print("  simulate_padd: OK\n")

# ============================================================
print("=" * 60)
print("TEST 6: HelperFunctions - find_replacement_indices")
print("=" * 60)
offsets = [0, 5, 9, 14]
indices = hf.find_replacement_indices(offsets, step_size=4)
print(f"  find_replacement_indices({offsets}, step_size=4) = {indices}")
assert indices == [0, 4, 8, 12], f"Expected [0, 4, 8, 12], got {indices}"

inc_indices = hf.find_incremental_replacement_indices(offsets, step_size=4)
print(f"  find_incremental_replacement_indices({offsets}, step_size=4) = {inc_indices}")
print("  find_replacement_indices: OK\n")

# ============================================================
print("=" * 60)
print("TEST 7: generate_bad_chars")
print("=" * 60)
filtered = hf.generate_bad_chars([b"\x00", b"\x0a", b"\x0d"])
print(f"  generate_bad_chars (253 bytes expected): {len(filtered)} bytes")
assert len(filtered) == 253, f"Expected 253 good bytes, got {len(filtered)}"
print("  generate_bad_chars: OK\n")

# ============================================================
print("=" * 60)
print("TEST 8: HelperFunctions - hex_q")
print("=" * 60)
xmm0 = struct.pack("4I", *[0xdeadbeef] * 4)
result = hf.hex_q(xmm0)
print(f"  hex_q(xmm0) = {result}")
assert "deadbeef" in result, "hex_q should contain deadbeef"
print("  hex_q: OK\n")

print("=" * 60)
print("ALL TESTS PASSED")
print("=" * 60)
