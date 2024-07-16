if __name__ == '__main__':

    #E-C-E -> D-E-D
    #assuming we have ciphertext and plaintext, i will be our k1, l will be our k2
    for i in range(2^8):
        dec1 = shortkey8_dec(i,ciphertext)
        enc1 = shortkey8_enc(i, plaintext)
        for l in range(2^8):
            enc2 = shortkey8_enc8(l, dec1)
            if enc2 == enc1:
                print("Found the keys: ")
                print("k1:"+i)
                print("k2:"+l)
                exit()
