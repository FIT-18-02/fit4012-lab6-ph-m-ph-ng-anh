import os
import socket
import logging
from Crypto.Random import get_random_bytes
from aes_socket_utils import encrypt_aes_cbc, build_key_packet, build_data_packet

# Cấu hình Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_sender():
    # 1. Lấy cấu hình từ môi trường
    server_ip = os.getenv('SERVER_IP', '127.0.0.1')
    key_port = int(os.getenv('KEY_PORT', 6001))
    data_port = int(os.getenv('DATA_PORT', 6000))
    
    # Lấy nội dung tin nhắn
    message = os.getenv('MESSAGE', 'Hello from AES Sender')
    input_file = os.getenv('INPUT_FILE')
    if input_file and os.path.exists(input_file):
        with open(input_file, 'rb') as f:
            data_to_send = f.read()
    else:
        data_to_send = message.encode()

    # 2. Sinh Key (16 byte cho AES-128) và IV (16 byte)
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    logging.info(f"Generated Key: {key.hex()} | IV: {iv.hex()}")

    # 3. Kênh Khóa (KEY_PORT)
    try:
        with socket.create_connection((server_ip, key_port), timeout=5) as key_sock:
            key_packet = build_key_packet(key, iv)
            key_sock.sendall(key_packet)
            logging.info("Sent Key Packet successfully.")
    except Exception as e:
        logging.error(f"Error on Key Channel: {e}")
        return

    # 4. Mã hóa dữ liệu
    ciphertext = encrypt_aes_cbc(data_to_send, key, iv)
    logging.info(f"Ciphertext length: {len(ciphertext)} bytes")

    # 5. Kênh Dữ liệu (DATA_PORT)
    try:
        with socket.create_connection((server_ip, data_port), timeout=5) as data_sock:
            data_packet = build_data_packet(ciphertext)
            data_sock.sendall(data_packet)
            logging.info("Sent Data Packet successfully.")
    except Exception as e:
        logging.error(f"Error on Data Channel: {e}")

if __name__ == "__main__":
    run_sender()