from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import textwrap


# ================================================================
# Función para dividir el mensaje en bloques de 128 letras
# ================================================================
def split_text(message, block_size=128):
    blocks = textwrap.wrap(message, block_size, break_long_words=False)
    for i in range(len(blocks) - 1):
        if not blocks[i].endswith(' ') and not blocks[i+1].startswith(' '):
            last_space_index = blocks[i].rfind(' ')
            blocks[i+1] = blocks[i][last_space_index+1:] + ' ' + blocks[i+1]
            blocks[i] = blocks[i][:last_space_index]
    return blocks


# ================================================================
# Función para reconstruir el mensaje
# ================================================================
def reconstruct_text(blocks):
    reconstructed = ''
    for block in blocks:
        reconstructed += block if block.endswith(' ') or block.endswith('.') else block + ' '
    return reconstructed.strip()


# ================================================================
# Claves rsa
# ================================================================
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

original_message = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut justo libero, sodales at interdum in, euismod ut urna.Curabitur quis blandit orci. Vivamus tincidunt, mauris dictum tristique auctor, urna ex pellentesque risus, nec aliquam felis neque nec odio. Integer ut ante vitae nibh placerat vulputate at ac lorem. Quisque bibendum diam eu volutpat sodales. Morbi gravida at arcu et fermentum. Ut ut ultricies urna. Duis at dui aliquam, eleifend erat sit amet, rutrum ligula. Praesent nec suscipit odio. Pellentesque eu condimentum neque. In elementum fermentum diam eget consectetur. Ut consectetur, augue at pulvinar suscipit, eros neque accumsan orci, et mollis mi sapien sit amet urna. Curabitur vehicula imperdiet ligula. Proin lacinia odio non diam vehicula, id facilisis arcu facilisis. Sed eget libero vel nibh lacinia congue. Etiam sit amet aliquam turpis. Praesent libero nibh, mollis sed imperdiet quis, semper a sapien. Pellentesque congue varius lectus quis ultrices. Fusce ipsum orci, convallis ut malesuada id, porttitor vel dolor est"""
message_blocks = split_text(original_message)

# Cifrar cada bloque de texto
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_blocks = []
for block in message_blocks:
    encrypted_block = cipher_rsa.encrypt(block.encode('utf-8'))
    encrypted_blocks.append(encrypted_block)

# Descifrar cada bloque de texto
decrypt_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_blocks = []
for block in encrypted_blocks:
    decrypted_block = decrypt_rsa.decrypt(block).decode('utf-8')
    decrypted_blocks.append(decrypted_block)


# ================================================================
# Reconstruimos el mensaje
# ================================================================
reconstructed_message = reconstruct_text(decrypted_blocks)


# ================================================================
# Generar el hash
# ================================================================
hash_original_message = SHA256.new(original_message.encode('utf-8')).hexdigest()
hash_reconstructed_message = SHA256.new(reconstructed_message.encode('utf-8')).hexdigest()

print(f'Ejericio 1.-\n'
      f'Mensaje original: {original_message}\n'
      f'Mensaje reconstruido: {reconstructed_message}\n'
      f'Los mensajes son iguales: {original_message == reconstructed_message}\n'
      f'\n'
      f'Hash del mensaje original: {hash_original_message}\n'
      f'Hash del mensaje reconstruido: {hash_reconstructed_message}\n'
      f'Los hashes coinciden: {hash_original_message == hash_reconstructed_message}')
