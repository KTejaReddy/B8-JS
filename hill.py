import numpy as np

KEY_MATRIX = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, mod):
    det = int(np.round(np.linalg.det(matrix))) % mod
    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        raise ValueError("Matrix is not invertible under mod 26")
    matrix_adj = np.round(det * np.linalg.inv(matrix)).astype(int) % mod
    return (det_inv * matrix_adj) % mod

def text_to_numbers(text):
    return [ord(c.upper()) - ord('A') for c in text if c.isalpha()]

def numbers_to_text(numbers):
    return ''.join(chr(n % 26 + ord('A')) for n in numbers)

def pad_text(text, block_size=3):
    while len(text) % block_size != 0:
        text += 'X'
    return text

def hill_encrypt(plaintext):
    if not plaintext:
        return ""
    
    clean_text = ''.join(c for c in plaintext if c.isalpha())
    if not clean_text:
        return ""
    
    clean_text = pad_text(clean_text.upper())
    numbers = text_to_numbers(clean_text)
    
    encrypted = []
    for i in range(0, len(numbers), 3):
        block = np.array(numbers[i:i+3])
        result = np.dot(KEY_MATRIX, block) % 26
        encrypted.extend(result.tolist())
    
    return numbers_to_text(encrypted)

def hill_decrypt(ciphertext):
    if not ciphertext:
        return ""
    
    clean_text = ''.join(c for c in ciphertext if c.isalpha())
    if not clean_text:
        return ""
    
    clean_text = pad_text(clean_text.upper())
    numbers = text_to_numbers(clean_text)
    
    key_inverse = matrix_mod_inverse(KEY_MATRIX, 26)
    
    decrypted = []
    for i in range(0, len(numbers), 3):
        block = np.array(numbers[i:i+3])
        result = np.dot(key_inverse, block) % 26
        decrypted.extend(result.astype(int).tolist())
    
    return numbers_to_text(decrypted)

def generate_key_stream(length, seed=None):
    if seed is None:
        seed = KEY_MATRIX.flatten().tolist()
    
    key_stream = []
    state = list(seed)
    
    for i in range(length):
        idx = i % len(state)
        val = (state[idx] * (i + 1) + sum(state)) % 256
        state[idx] = (state[idx] + val) % 256
        key_stream.append(val)
    
    return bytes(key_stream)

HEADER_PREFIX = b"HILLXOR:"
HEADER_LENGTH = 19
LEGACY_HEADER_PREFIX = b"HILLBIN:"
LEGACY_HEADER_PREFIX_STR = "HILLBIN:"
LEGACY_HILL_PREFIX = b"HILL:"
LEGACY_HILL_PREFIX_STR = "HILL:"

def encrypt_file_bytes(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    original_length = len(data)
    
    key_stream = generate_key_stream(len(data))
    
    encrypted_bytes = bytes([b ^ k for b, k in zip(data, key_stream)])
    
    header = f"HILLXOR:{original_length:010d}:".encode('utf-8')
    
    return header + encrypted_bytes

def decrypt_file_bytes(encrypted_data):
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    
    if encrypted_data.startswith(HEADER_PREFIX):
        try:
            length_str = encrypted_data[8:18].decode('utf-8')
            original_length = int(length_str)
            
            ciphertext = encrypted_data[HEADER_LENGTH:]
        except Exception as e:
            return encrypted_data
        
        key_stream = generate_key_stream(len(ciphertext))
        
        decrypted_bytes = bytes([b ^ k for b, k in zip(ciphertext, key_stream)])
        
        return decrypted_bytes[:original_length]
    
    if encrypted_data.startswith(LEGACY_HEADER_PREFIX):
        try:
            encrypted_str = encrypted_data.decode('utf-8')
            parts = encrypted_str.split(":", 3)
            original_length = int(parts[1])
            padding_count = int(parts[2])
            ciphertext = parts[3]
            
            numbers = text_to_numbers(ciphertext)
            key_inverse = matrix_mod_inverse(KEY_MATRIX, 26)
            
            decrypted = []
            for i in range(0, len(numbers), 3):
                block = np.array(numbers[i:i+3])
                result = np.dot(key_inverse, block) % 26
                decrypted.extend(result.astype(int).tolist())
            
            alpha_str = numbers_to_text(decrypted)
            if padding_count > 0:
                alpha_str = alpha_str[:-padding_count]
            
            result_bytes = bytearray()
            for i in range(0, len(alpha_str), 2):
                if i + 1 < len(alpha_str):
                    high = ord(alpha_str[i].upper()) - ord('A')
                    low = ord(alpha_str[i+1].upper()) - ord('A')
                    result_bytes.append(((high & 0x0F) << 4) | (low & 0x0F))
            
            return bytes(result_bytes[:original_length])
        except:
            pass
    
    if encrypted_data.startswith(LEGACY_HILL_PREFIX):
        try:
            encrypted_str = encrypted_data.decode('utf-8')
            parts = encrypted_str.split(":", 2)
            original_length = int(parts[1])
            ciphertext = parts[2]
            
            numbers = text_to_numbers(ciphertext)
            key_inverse = matrix_mod_inverse(KEY_MATRIX, 26)
            
            decrypted = []
            for i in range(0, len(numbers), 3):
                block = np.array(numbers[i:i+3])
                result = np.dot(key_inverse, block) % 26
                decrypted.extend(result.astype(int).tolist())
            
            alpha_str = numbers_to_text(decrypted)
            
            result_bytes = bytearray()
            for i in range(0, len(alpha_str), 2):
                if i + 1 < len(alpha_str):
                    high = ord(alpha_str[i].upper()) - ord('A')
                    low = ord(alpha_str[i+1].upper()) - ord('A')
                    result_bytes.append(((high & 0x0F) << 4) | (low & 0x0F))
            
            return bytes(result_bytes[:original_length])
        except:
            pass
    
    return encrypted_data

def encrypt_file_content(content):
    return encrypt_file_bytes(content)

def decrypt_file_content(encrypted_content):
    return decrypt_file_bytes(encrypted_content)
