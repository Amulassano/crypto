#esame 19/07/2020
    print(len(ciphertext)//AES.block_size)
    N = len(ciphertext)//AES.block_size
    initial_part = ciphertext[:(N-2)*AES.block_size]
    block_to_modify = bytearray(ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size])
    last_block = ciphertext[(N-1)*AES.block_size:]


    byte_index = AES.block_size - 1
    c_15 = block_to_modify[byte_index]

    for c_prime_15 in range(256):
        block_to_modify[byte_index] = c_prime_15
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        # print(response)
        server.close()

        if response == b'OKPAD':
            print("c_prime_15="+str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 15
            p_15 = p_prime_15 ^ c_15
            print("p_prime_15=" + str(p_prime_15))
            print("p_15=" + str(p_15))

    print("---------------")

    c_second_15 = p_prime_15 ^ iv[-1]
    block_to_modify[byte_index] = c_second_15

    byte_index -=1
    c_14 = block_to_modify[byte_index]

    for c_prime_14 in range(256):
        block_to_modify[byte_index] = c_prime_14
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        server.close()

        if response == b'OKPAD':
            print("c_prime_14="+str(c_prime_14))
            p_prime_14 = c_prime_14 ^ 14
            p_14 = p_prime_14 ^ c_14
            print("p_prime_14=" + str(p_prime_14))
            print("p_14=" + str(p_14))

    print("---------------")
    c_second_14 = p_prime_14 ^ iv[-2]
    block_to_modify[byte_index] = c_second_14

    byte_index -=1
    c_13 = block_to_modify[byte_index]

    for c_prime_13 in range(256):
        block_to_modify[byte_index] = c_prime_13
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        server.close()

        if response == b'OKPAD':
            print("c_prime_13="+str(c_prime_13))
            p_prime_13 = c_prime_13 ^ 13
            p_13 = p_prime_13 ^ c_13
            print("p_prime_13=" + str(p_prime_13))
            print("p_13=" + str(p_13))
