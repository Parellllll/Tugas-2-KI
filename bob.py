
# bob.py
# Responder B - Bob
# Menerima session key dari Alice dan komunikasi dua arah

import socket
import json
import os
import threading
import struct
from aes_manual import encrypt, decrypt, key_from_ascii

BANNER = """
+------------------------------------------------------+
|               BOB  (Responder B)                     |
|         Keamanan Informasi - Tugas 2                 |
+------------------------------------------------------+
"""

BOB_PORT = 8002
session_key = None
session_lock = threading.Lock()
alice_sock_global = None


def send_msg(sock, data: bytes):
    sock.sendall(struct.pack('>I', len(data)) + data)


def recv_msg(sock) -> bytes:
    raw = recvall(sock, 4)
    if not raw:
        return b''
    return recvall(sock, struct.unpack('>I', raw)[0])


def recvall(sock, n) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf


def register_to_kdc(kdc_ip, kdc_port, master_key_bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((kdc_ip, kdc_port))
    msg = json.dumps({'type': 'REGISTER', 'id': 'Bob', 'key': master_key_bytes.hex()})
    send_msg(s, msg.encode())
    resp = json.loads(recv_msg(s).decode())
    s.close()
    if resp.get('type') == 'REGISTER_ACK':
        print(f"[Bob] Terdaftar di KDC dengan ID: {resp['id']}")
    else:
        print(f"[Bob] Gagal daftar ke KDC: {resp}")


def handle_alice(conn, addr, master_key_bytes):
    global session_key
    print(f"\n[Bob] Koneksi dari Alice: {addr}")

    try:
        raw3 = recv_msg(conn)
        msg3 = json.loads(raw3.decode())
        if msg3['type'] != 'STEP3':
            print("[Bob] Pesan tidak dikenali pada langkah 3")
            conn.close()
            return

        enc_for_b = bytes.fromhex(msg3['enc_for_b'])
        print(f"\n[Bob] === LANGKAH 3: Terima E(Kb,[Ks||IDA]) dari Alice ===")
        print(f"  E(Kb,[Ks||IDA]) (hex): {enc_for_b.hex()}")

        decrypted = decrypt(enc_for_b, master_key_bytes)
        Ks   = decrypted[0:16]
        id_a = decrypted[16:24].rstrip(b'\x00').decode()

        print(f"  Session Key Ks (hex): {Ks.hex()}")
        print(f"  IDA recovered       : {id_a}")

        N2 = os.urandom(8)
        enc_n2 = encrypt(N2, Ks)

        print(f"\n[Bob] === LANGKAH 4: Kirim E(Ks,N2) ke Alice ===")
        print(f"  N2         (hex): {N2.hex()}")
        print(f"  E(Ks,N2)   (hex): {enc_n2.hex()}")

        msg4 = json.dumps({'type': 'STEP4', 'enc_n2': enc_n2.hex()})
        send_msg(conn, msg4.encode())

        print(f"\n[Bob] === LANGKAH 5: Tunggu E(Ks,f(N2)) dari Alice ===")
        raw5 = recv_msg(conn)
        msg5 = json.loads(raw5.decode())
        enc_fn2 = bytes.fromhex(msg5['enc_fn2'])
        print(f"  E(Ks,f(N2)) (hex): {enc_fn2.hex()}")

        fn2_received = decrypt(enc_fn2, Ks)
        expected_fn2 = (int.from_bytes(N2, 'big') + 1).to_bytes(len(N2), 'big')

        if fn2_received == expected_fn2:
            print(f"  f(N2) cocok: {fn2_received.hex()} [OK]")
            print("\n[Bob] [OK] Autentikasi berhasil! Session Key Ks disepakati.")
            ack = json.dumps({'type': 'ACK', 'status': 'OK'})
            with session_lock:
                session_key = Ks
        else:
            print(f"  f(N2) TIDAK cocok! Received: {fn2_received.hex()}, Expected: {expected_fn2.hex()}")
            print("[Bob] [FAIL] Autentikasi GAGAL.")
            ack = json.dumps({'type': 'ACK', 'status': 'FAIL'})
            send_msg(conn, ack.encode())
            conn.close()
            return

        send_msg(conn, ack.encode())

        print(f"\n[Bob] Session Key aktif (hex): {Ks.hex()}")
        print("[Bob] Siap untuk komunikasi dua arah dengan Alice!\n")

        global alice_sock_global
        alice_sock_global = conn

        t_recv = threading.Thread(target=chat_recv, args=(conn,), daemon=True)
        t_recv.start()

        chat_send(conn)
        conn.close()

    except Exception as e:
        print(f"[Bob] Exception: {e}")
        conn.close()


def chat_recv(sock):
    global session_key
    while True:
        try:
            raw = recv_msg(sock)
            if not raw:
                print("\n[Bob] Koneksi ke Alice terputus.")
                break
            msg = json.loads(raw.decode())
            if msg['type'] == 'CHAT':
                ct_bytes = bytes.fromhex(msg['ciphertext'])
                with session_lock:
                    sk = session_key
                plaintext = decrypt(ct_bytes, sk).decode('utf-8', errors='replace')
                print(f"\n[Alice -> Bob  ] Ciphertext (hex): {ct_bytes.hex()}")
                print(f"                 Plaintext        : {plaintext}")
                print("[Bob] Pesan: ", end='', flush=True)
            elif msg['type'] == 'NEW_KEY':
                new_key = bytes.fromhex(msg['key'])
                with session_lock:
                    session_key = new_key
                print(f"\n[Bob] Session key diperbarui oleh Alice: {new_key.hex()}")
                print("[Bob] Pesan: ", end='', flush=True)
        except Exception as e:
            print(f"\n[Bob] Error receive: {e}")
            break


def chat_send(sock):
    global session_key
    print("[Bob] Ketik pesan, atau perintah:")
    print("  /key <ascii_key>  -> Ubah session key (maks 16 karakter)")
    print("  /quit             -> Keluar")
    while True:
        try:
            msg_input = input("[Bob] Pesan: ")
        except EOFError:
            break

        if not msg_input:
            continue

        if msg_input.startswith('/key '):
            new_key_ascii = msg_input[5:].strip()
            try:
                new_key = key_from_ascii(new_key_ascii)
                with session_lock:
                    session_key = new_key
                notify = json.dumps({'type': 'NEW_KEY', 'key': new_key.hex()})
                send_msg(sock, notify.encode())
                print(f"[Bob] Session key diubah: {new_key.hex()}")
            except ValueError as e:
                print(f"[Bob] Error key: {e}")
            continue

        if msg_input == '/quit':
            break

        with session_lock:
            sk = session_key

        ct = encrypt(msg_input.encode('utf-8'), sk)
        chat_msg = json.dumps({'type': 'CHAT', 'ciphertext': ct.hex()})
        send_msg(sock, chat_msg.encode())
        print(f"[Bob  -> Alice ] Plaintext        : {msg_input}")
        print(f"                 Ciphertext (hex) : {ct.hex()}")


def main():
    global session_key
    print(BANNER)

    kdc_ip   = input("KDC IP address   : ").strip()
    kdc_port = int(input(f"KDC port (default 9000): ").strip() or "9000")
    my_port  = int(input(f"Bob listen port (default {BOB_PORT}): ").strip() or str(BOB_PORT))
    my_ip    = input("Bob bind IP (kosong = 0.0.0.0): ").strip() or '0.0.0.0'

    ascii_key = input("Master Key ASCII Bob (maks 16 char): ").strip()
    try:
        master_key = key_from_ascii(ascii_key)
    except ValueError as e:
        print(f"[Bob] Error: {e}")
        return

    print(f"\n[Bob] Master Key Kb (hex): {master_key.hex()}")

    print("\n[Bob] Mendaftar ke KDC...")
    register_to_kdc(kdc_ip, kdc_port, master_key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((my_ip, my_port))
    srv.listen(5)
    print(f"\n[Bob] Mendengarkan koneksi dari Alice di {my_ip}:{my_port} ...")
    print("[Bob] Menunggu Alice memulai key distribution...\n")

    conn, addr = srv.accept()
    handle_alice(conn, addr, master_key)
    srv.close()


if __name__ == '__main__':
    main()
