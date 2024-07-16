    #exam 16/07/2021
    print(len(ciphertext)//AES.block_size)
    N = len(ciphertext)//AES.block_size
    initial_part = ciphertext[:(N-3)*AES.block_size]
    block_to_modify = bytearray(ciphertext[(N-3)*AES.block_size:(N-2)*AES.block_size])
    last_block = ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size]


    byte_index = AES.block_size - 1
    p = ''
    for i in range(16):
        c_number = block_to_modify[byte_index]
        for c_prime in range(256):
            block_to_modify[byte_index] = c_prime
            to_send = initial_part + block_to_modify + last_block
    
            server = remote(HOST, PORT)
            server.send(iv)
            server.send(to_send)
            response = server.recv(1024)
            server.close()
    
            if response == b'\x00\x00\x00\x00':            
                p_prime = c_prime ^ (i+1)
                p = p_prime ^ c_number + p
        for l in range(16-byte_index):
            block_to_modify[byte_index-l] = p_prime ^ (i + 2)
        byte_index -=1
