# Reference: William Stallings, "Cryptography and Network Security: Principles And Practice: Seventh Edition”, Pearson 2017

import numpy as np
from tqdm import tqdm
from constants import *

class AES:
    def __init__(self, key):

        # AES: initialization

        # These are global-variables
        # Reads The "S-box" & "Inverse S-Box"
        self.sbox = np.reshape(np.array(sbox, dtype= np.uint8), (16,16))
        self.inv_sbox = np.reshape(np.array(inv_sbox, dtype= np.uint8), (16,16))

        # These constant are used to perform multiplcation modulo "x^8 + x^4 + x^3 + x + 1"
        self.msb = np.uint8(128)
        self.add27 = np.uint8(27)

        # These constants are used to acces the "S-box"
        self.msn = np.uint8(0xf0) # msn = Most Significant Nibble
        self.lsn = np.uint8(0x0f)

        # These hash-tables shall contain column-vectors for efficient-encryption
        self.t1, self.t2, self.t3, self.t4 = {}, {}, {}, {}
        # These hash-tables shall contain column-vectors for efficient-decryption
        self.t5, self.t6, self.t7, self.t8 = {}, {}, {}, {}

        # Generates the aforementioned hash-tables
        self.generate_tables()

        # Generates Round-keys
        self.RoundKeys = self.generate_round_keys(key)

        print("AES: Initialization Complete")

    def generate_tables(self):
        # This function generates the hash-tables (t1 till t8) for efficient encryption & decryption

        (r, c) = self.sbox.shape
        for i in range(r):
            for j in range(c):
                (v1, v2, v3, v4) = self.generate_encryption_vectors(self.sbox[i, j])
                self.t1[self.sbox[i, j]] = v1
                self.t2[self.sbox[i, j]] = v2
                self.t3[self.sbox[i, j]] = v3
                self.t4[self.sbox[i, j]] = v4

        for i in range(r):
            for j in range(c):
                (v1, v2, v3, v4) = self.generate_decryption_vectors(self.inv_sbox[i, j])
                self.t5[self.inv_sbox[i, j]] = v1
                self.t6[self.inv_sbox[i, j]] = v2
                self.t7[self.inv_sbox[i, j]] = v3
                self.t8[self.inv_sbox[i, j]] = v4

    def generate_encryption_vectors(self, e):
        """
        1. This function creates column-vectors for encryption, for an input byte 'e'

        2. Each byte in the message or key represents a polynomial in GF(2^8)
            The irreduible polynomial is x^8 + x^4 + x^3 + x + 1

            These constants ensure that the multiplication of two bytes equals
            the multiplication of two polynomials in GF(2^8)
        """

        v1 = np.empty((4,), dtype=np.uint8)
        v2 = np.empty((4,), dtype=np.uint8)
        v3 = np.empty((4,), dtype=np.uint8)
        v4 = np.empty((4,), dtype=np.uint8)

        # creates v1
        v1[1:3] = e
        v1[0] = e << 1
        v1[3] = v1[0] ^ e
        # special case
        if e & self.msb:
            v1[0] ^= self.add27
            v1[3] ^= self.add27

        # creates v2, v3, v4
        v2[1:] = v1[:3]
        v2[0] = v1[3]
        v3[1:] = v2[:3]
        v3[0] = v2[3]
        v4[1:] = v3[:3]
        v4[0] = v3[3]

        return (v1, v2, v3, v4)

    def generate_decryption_vectors(self, h):
        """
        This function creates column-vectors for decryption, for an input byte 'h'
        Reference: https://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns
        """

        # Performs h*E
        e1 = h << 1 ^ h
        if h & self.msb:
            e1 ^= self.add27
        e2 = e1 << 1 ^ h
        if e1 & self.msb:
            e2 ^= self.add27
        E = (e2 << 1) & 0xff
        if e2 & self.msb:
            E ^= self.add27

        # Performs h*9
        n1 = h << 1
        if h & self.msb:
            n1 ^= self.add27
        n2 = n1 << 1
        if n1 & self.msb:
            n2 ^= self.add27
        nine = (n2 << 1 & 0xff) ^ h
        if n2 & self.msb:
            nine ^= self.add27

        # Performs h*B
        b1 = h << 1
        if h & self.msb:
            b1 ^= self.add27
        b2 = b1 << 1 ^ h
        if b1 & self.msb:
            b2 ^= self.add27
        B = (b2 << 1 & 0xff) ^ h
        if b2 & self.msb:
            B ^= self.add27

        # Performs h*D
        d1 = h << 1 ^ h
        if h & self.msb:
            d1 ^= self.add27
        d2 = d1 << 1
        if d1 & self.msb:
            d2 ^= self.add27
        D = (d2 << 1 & 0xff) ^ h
        if d2 & self.msb:
            D ^= self.add27

        # creates the column-vectors
        v1 = np.array([E, nine, D, B], dtype=np.uint8)
        v2 = np.array([B, E, nine, D], dtype=np.uint8)
        v3 = np.array([D, B, E, nine], dtype=np.uint8)
        v4 = np.array([nine, D, B, E], dtype=np.uint8)

        return (v1, v2, v3, v4)

    def generate_round_constants(self):
        """
        This function generates the array of round-constants for 128-bit AES
        Reference: Section 6.4: AES Key Expansion
        """
        # initialization
        RC = np.empty(shape=(10,), dtype=np.uint8)

        # generates "RC"
        RC[0] = 1
        for i in range(1, 10):
            RC[i] = RC[i-1] << 1
            if RC[i-1] & self.msb:
                RC[i] ^= self.add27

        # generates round-constants "Rcon"
        Rcon = np.zeros(shape=(4*10,), dtype=np.uint8)
        for i in range(0, 4*10, 4):
            Rcon[i] = RC[i//4]

        return Rcon

    def KeyExpansion(self, key):
        """
        This function expands 1 input-key (16 bytes) into 11 keys (176 bytes)
        Reference: Section 6.4: AES Key Expansion
        """

        # generates "Rcon"
        Rcon = self.generate_round_constants()

        # Instead of storing a "word", I store 4 bytes; 176 bytes = 44 words * 4 bytes
        w = np.empty(shape=(176,), dtype= np.uint8)

        # loads the input-key into first 4 words of the expanded-key
        w[:16] = key

        # This algorithm is used to expand the key
        for i in range(16, 176, 4):

            tmp = w[i-4:i]

            # Special case
            if i%16 == 0:

                # RotWord: Perform circular-left-shift (bytewise)
                TMP = np.empty_like(tmp)
                TMP[:3] = tmp[1:]
                TMP[3] = tmp[0]

                # SubWord
                for j in range(4):
                    c = self.lsn & TMP[j]
                    r = (self.msn & TMP[j]) >> 4
                    TMP[j] = self.sbox[r, c]

                # EXOR with "Rcon"
                # '*4' because each word in "Rcon" is distributed over 4 consecutive-bytes
                j = (i//16 -1) *4
                tmp = TMP ^ Rcon[j:j+4]

            w[i:i+4] = w[i-16:i-12] ^ tmp

        return np.reshape(w, (11, 16))

    # This function is used to "substitute" an input-byte 'e' using the "S-box"
    def SubBytes(self, e):

        c = self.lsn & e
        r = (self.msn & e) >> 4

        return self.sbox[r, c]

    # This function is used to "substitute" an input-byte 'e' using the "Inverse S-box"
    def invSubBytes(self, e):

        c = self.lsn & e
        r = (self.msn & e) >> 4

        return self.inv_sbox[r, c]

    def generate_round_keys(self, key):
        """
        This function
        1. accepts a NumPy-array 'key', which contains 16 unsigned 8-bit integers (16 bytes)
        2. generates the expanded-key (176 bytes)
        3. converts the expanded-keys into round-keys, i.e., (4, 4) matrices in column-major form
        """

        # generates 11 keys
        w = self.KeyExpansion(key)

        # converts the 1D keys to 2D matrices
        roundkeys = np.empty(shape= (11, 4, 4), dtype= np.uint8)
        for i in range(w.shape[0]):
            roundkeys[i, :, :] = np.reshape(w[i], (4, 4)).T

        return roundkeys

    def en_round(self, C, roundkey):
        """
        1. This function performs 1 encryption-round
        - It is valid for rounds 1 till 9
        2. The arguments are,
        - C = input-state
        - roundkey = round-key for round #i, where i in [1, 9]
        Reference: Section 6.6: Subsection: Implementation Aspects
        """

        # SubBytes
        S = np.vectorize(self.SubBytes)(C)

        # An efficient-implementation of ShiftRows & MixColumns
        for j in range(4):
            k, l, m = (j+1) % 4 , (j+2) % 4, (j+3) % 4

            # Access "column-vectors" in O(1) time
            v1 = self.t1.get(S[0, j])
            v2 = self.t2.get(S[1, k])
            v3 = self.t3.get(S[2, l])
            v4 = self.t4.get(S[3, m])

            # Stores [temporarily] the XORed-vector in row-major form
            C[j, :] = v1 ^ v2 ^ v3 ^ v4

        # AddRoundKey
        # C.T transposes C to column-major form [as required by AES]
        C = C.T ^ roundkey

        return C

    def en_round10(self, C, roundkey):
        # This function performs the 10th encryption-round

        #Substitute bytes
        S = np.vectorize(self.SubBytes)(C)

        # Shift Rows
        tmp = np.empty_like(S)
        tmp[0, :] = S[0]
        tmp[1, :3] = S[1, 1:]
        tmp[1, 3]  = S[1, 0]
        tmp[2, :2] = S[2, 2:]
        tmp[2, 2:] = S[2, :2]
        tmp[3, 0] = S[3, 3]
        tmp[3, 1:] = S[3, :3]

        # AddRoundKey
        C = tmp ^ roundkey

        return C

    def encryption_block(self, plaintext):
        """
        1. This function is used to encrypt a 128-bit plaintext
        2. The argument "plaintext" is a 1D vector of 16 bytes
        """

        # converts the 1D-input-vector to a 2D-matrix
        # Note: The input must be in column-major form, hence the "transposition"
        C = np.reshape(plaintext, (4,4)).T

        # AddRoundKey: Round 0
        C = C ^ self.RoundKeys[0]

        # Rounds 1 till 9
        for i in range(1, 10):
            C = self.en_round(C, self.RoundKeys[i])

        # Round 10
        C = self.en_round10(C, self.RoundKeys[10])

        # converts data to row-major form
        C = C.T

        # Cipher-text
        return np.reshape(C, (16, ))

    def de_round(self, C, roundkey):
        """
        1. This function performs 1 decryption-round
        - It is valid for rounds 1 till 9
        2. The arguments are,
        - C = input-state
        - roundkey = round-key for round #i, where i in [1, 9]
        Reference: Section 6.6: Subsection: Equivalent Inverse Cipher
        """

        # InvSubBytes
        S = np.vectorize(self.invSubBytes)(C)

        # An efficient-implementation of InvShiftRows & InvMixColumns
        for j in range(4):
            k, l, m = (j-1) % 4 , (j-2) % 4, (j-3) % 4

            # Access "column-vectors" in O(1) time
            v1 = self.t5.get(S[0, j] ^ roundkey[0, j])
            v2 = self.t6.get(S[1, k] ^ roundkey[1, j])
            v3 = self.t7.get(S[2, l] ^ roundkey[2, j])
            v4 = self.t8.get(S[3, m] ^ roundkey[3, j])

            # Store the XORed vector in row-major form [temporarily]
            C[j, :] = v1 ^ v2 ^ v3 ^ v4

        # AddRoundKey
        # C.T transposes C to column-major form [as required by AES]
        C = C.T

        return C

    def de_round10(self, C, roundkey):
        # This function performs the 10th decryption-round

        # InvSubBytes
        S = np.vectorize(self.invSubBytes)(C)

        # ShiftRows
        tmp = np.empty_like(S)
        tmp[0, :] = S[0]
        tmp[1, 1:] = S[1, :3]
        tmp[1, 0]  = S[1, 3]
        tmp[2, :2] = S[2, 2:]
        tmp[2, 2:] = S[2, :2]
        tmp[3, :3] = S[3, 1:]
        tmp[3, 3] = S[3, 0]

        # AddRoundKey
        C = tmp ^ roundkey

        return C

    def decryption_block(self, ciphertext):
        """
        1. This function is used to decrypt a 128-bit cipher
        2. The argument  'ciphertext' is a 1D vector of 16 bytes
        """

        # converts the 1D-input-vector to a 2D-matrix
        # Note: The input must be in column-major form, hence the "transposition"
        C = np.reshape(ciphertext, (4,4)).T

        # AddRoundKey: Round 0
        C = C ^ self.RoundKeys[10]

        # Rounds 1 till 9
        for i in reversed(range(1, 10)):
            C = self.de_round(C, self.RoundKeys[i])

        # Round 10
        # 'T' converts data to row-major form
        C = self.de_round10(C, self.RoundKeys[0]).T

        # plain-text
        return np.reshape(C, (16, ))

    def preprocess(self, img):
        """
        This function
        1. accepts a PIL Image object
        2. modifies the image's shape if its dimensions are not multiples of 16
        - a 'flag' is set to indicate this
        3. returns a NumPy-matrix (of the image)
        - and, the 'flag' with the original-dimensions
        """

        # initialization
        flag = False
        org_shape = None

        #
        l, b = img.size
        if l % 16 != 0 or b% 16 != 0:
            print("Alert: The input-image's dimensions are not a multiple of 16. Resizing it temporarily.\n")
            # set the flag
            flag = True

            # save the original-dimensions
            r, c = b, l
            org_shape = (r, c, 3)

            # Reshapes the image
            l = int(np.ceil(l/16)) *16
            b = int(np.ceil(b/16)) *16
            img = img.crop((0, 0, l, b))

        return np.array(img), (flag, org_shape)

    def encrypt_image(self, img):
        """
        This function,
        1. accepts a 'PIL Image object' as the input-image
        - the image must have 3 channels
        2. performs 128-bit encryption on the image
        3. returns the encrypted-image
        - It also returns the aforementioned 'flag' & the original-dimensions of the image
        """

        # Preprocess the image
        img, (flag, org_shape) = self.preprocess(img)
        shape = img.shape

        # Converts 2D image to 1D message
        plaintext = np.reshape(img, (-1, 3))

        # Encryption
        cipher = np.empty(shape= plaintext.shape, dtype= np.uint8)
        for c in range(3):
            print(f"Encrypting Channel {c+1}")
            for i in tqdm(range(0, plaintext.shape[0], 16)):
                cipher[i:i+16, c] = self.encryption_block(plaintext[i:i+16, c])

        print("Encryption complete",)
        return np.reshape(cipher, shape), (flag, org_shape)

    def decrypt_img(self, cipher, flag, org_shape):
        """
        This function,
        1. accepts an encrypted-image (as a NumPy-matrix)
        2. performs 128-bit decryption on the image
        3. returns the decrypted-image
        - in its original-dimenions (if it was modified)
        """

        #
        shape = cipher.shape

        # Decryption
        cipher = np.reshape(cipher, (-1, 3))
        plain = np.empty(shape= cipher.shape, dtype= np.uint8)
        for c in range(3):
            print(f"Decrypting Channel {c+1}")
            for i in tqdm(range(0, cipher.shape[0], 16)):
                plain[i:i+16, c] = self.decryption_block(cipher[i:i+16, c])

        print("Decryption complete",)

        # Restores the image's dimensions [back to the original]
        plain = np.reshape(plain, shape)
        if flag:
            plain = plain[:org_shape[0], :org_shape[1], :]

        return plain
