import os
import socket
import logging
from aes_socket_utils import decrypt_aes_cbc, parse_key_packet, recv_exact

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_receiver():
    host = os.getenv('RECEIVER_HOST', '0.0.0.0')
    key_port = int(os.getenv('KEY_PORT', 6001))
    data_port = int(os.getenv('DATA_PORT', 6000))
    output_file = os.getenv('OUTPUT_FILE')

    key, iv = None, None

    # 1. Lắng nghe Kênh Khóa
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as key_sock:
        key_sock.bind((host, key_port))
        key_sock.listen(1)
        logging.info(f"Listening for Key on port {key_port}...")
        conn, addr = key_sock.accept()
        with conn:
            # Nhận 4 byte header độ dài key
            header = recv_exact(conn, 4)
            import struct
            key_len = struct.unpack('>I', header)[0]
            # Nhận tiếp key và iv (iv luôn 16 bytes)
            remaining_data = recv_exact(conn, key_len + 16)
            key, iv = parse_key_packet(header + remaining_data)
            logging.info(f"Received Key and IV from {addr}")

    # 2. Lắng nghe Kênh Dữ liệu
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_sock:
        data_sock.bind((host, data_port))
        data_sock.listen(1)
        logging.info(f"Listening for Data on port {data_port}...")
        conn, addr = data_sock.accept()
        with conn:
            header = recv_exact(conn, 4)
            cipher_len = struct.unpack('>I', header)[0]
            ciphertext = recv_exact(conn, cipher_len)
            
            # Giải mã
            plaintext = decrypt_aes_cbc(ciphertext, key, iv)
            result = plaintext.decode(errors='replace')
            logging.info(f"Decrypted message: {result}")

            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(result)
                logging.info(f"Saved output to {output_file}")

if __name__ == "__main__":
    run_receiver()