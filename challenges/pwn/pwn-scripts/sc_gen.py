import sys
import os


if len(sys.argv) == 2:
    arg = sys.argv[1]
    # We assemble and link the object code
    os.system(f"nasm -f elf64 {arg}.nasm -o {arg}.o; ld {arg}.o -o {arg};\n")

    # Print out shellcode_str with stub for the user
    shellcode_str = os.popen(f"for i in $(objdump -d ./{arg} | grep '^ ' | cut -f2);do echo -n '\\x'$i; done; echo").read()
    shellcode_bytes = os.popen(f"for i in $(objdump -d ./{arg} | grep '^ ' | cut -f2);do echo -n $i; done; echo").read()
    print(f"[Generated Shellcode]: {shellcode_str}")
    print(f"[Shellcode length]: {len(bytes.fromhex(shellcode_bytes))} bytes")
    
    if "00" in shellcode_bytes:
        print("[Nullbytes in shellcode]: Yes")
    else:
        print("[Nullbytes in shellcode]: No")

elif len(sys.argv) == 3:
    arg = sys.argv[1]
    shellcode_str = os.popen(f"for i in $(objdump -d ./{arg} | grep '^ ' | cut -f2);do echo -n '\\x'$i; done; echo").read()
    shellcode_bytes = os.popen(f"for i in $(objdump -d ./{arg} | grep '^ ' | cut -f2);do echo -n $i; done; echo").read()
    print(f"[Shellcode]: {shellcode_str}")
    print(f"[Shellcode length]: {len(bytes.fromhex(shellcode_bytes))} bytes")
    
    if "00" in shellcode_bytes:
        print("[Nullbytes in shellcode]: Yes")
    else:
        print("[Nullbytes in shellcode]: No")

else:
    print("Please provide the name of the .asm file as the argument!\nAnd an additional argument to just display the shellcode_str.")
