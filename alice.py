
# alice.py
# Initiator A - Alice
# Melakukan key distribution dan komunikasi dua arah dengan Bob

import socket
import json
import os
import threading
import struct
import time
from aes_manual import encrypt, decrypt, key_from_ascii

BANNER = """
+------------------------------------------------------+
|              ALICE  (Initiator A)                    |
|         Keamanan Informasi - Tugas 2                 |
+------------------------------------------------------+
"""

ALICE_LISTEN_PORT = 8001
session_key = None
session_lock = threading.Lock()


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
    msg = json.dumps({'type': 'REGISTER', 'id': 'Alice', 'key': master_key_bytes.hex()})
    send_msg(s, msg.encode())
    resp = json.loads(recv_msg(s).decode())
    s.close()
    if resp.get('type') == 'REGISTER_ACK':
        print(f"[Alice] Terdaftar di KDC dengan ID: {resp['id']}")
    else:
        print(f"[Alice] Gagal daftar ke KDC: {resp}")


def kdc_key_request(kdc_ip, kdc_port, master_key_bytes):
    N1 = os.urandom(8)
    print(f"\n[Alice] === LANGKAH 1: Kirim ke KDC ===")
    print(f"  Pesan  : IDA='Alice' || IDB='Bob' || N1={N1.hex()}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((kdc_ip, kdc_port))
    req = json.dumps({
        'type': 'KEY_REQUEST',
        'id_a': 'Alice',
        'id_b': 'Bob',
        'n1': N1.hex()
    })
    send_msg(s, req.encode())
    raw_resp = recv_msg(s)
    s.close()

    resp = json.loads(raw_resp.decode())
    if resp.get('type') == 'ERROR':
        print(f"[Alice] KDC Error: {resp['msg']}")
        return None, None

    enc_for_a = bytes.fromhex(resp['enc_for_a'])
    enc_for_b = bytes.fromhex(resp['enc_for_b'])

    print(f"\n[Alice] === LANGKAH 2: Terima dari KDC ===")
    print(f"  E(Ka,[Ks||IDA||IDB||N1]) (hex): {enc_for_a.hex()}")
    print(f"  E(Kb,[Ks||IDA])          (hex): {enc_for_b.hex()}")

    decrypted = decrypt(enc_for_a, master_key_bytes)

    Ks   = decrypted[0:16]
    id_a = decrypted[16:24].rstrip(b'\x00').decode()
    id_b = decrypted[24:32].rstrip(b'\x00').decode()
    n1_r = decrypted[32:40]

    print(f"\n[Alice] Dekripsi E(Ka,...) berhasil:")
    print(f"  Session Key Ks (hex): {Ks.hex()}")
    print(f"  IDA recovered       : {id_a}")
    print(f"  IDB recovered       : {id_b}")
    print(f"  N1 cocok            : {n1_r == N1}")

    if n1_r != N1:
        print("[Alice] PERINGATAN: N1 tidak cocok! Kemungkinan replay attack.")
        return None, None

    return Ks, enc_for_b


def do_key_exchange(bob_ip, bob_port, Ks, enc_for_b):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((bob_ip, bob_port))

    print(f"\n[Alice] === LANGKAH 3: Kirim E(Kb,[Ks||IDA]) ke Bob ===")
    print(f"  E(Kb,[Ks||IDA]) (hex): {enc_for_b.hex()}")

    msg3 = json.dumps({'type': 'STEP3', 'enc_for_b': enc_for_b.hex()})
    send_msg(s, msg3.encode())

    print(f"\n[Alice] === LANGKAH 4: Tunggu E(Ks,N2) dari Bob ===")
    raw4 = recv_msg(s)
    msg4 = json.loads(raw4.decode())
    enc_n2 = bytes.fromhex(msg4['enc_n2'])
    print(f"  E(Ks,N2) diterima (hex): {enc_n2.hex()}")

    N2 = decrypt(enc_n2, Ks)
    print(f"  N2 setelah dekripsi (hex): {N2.hex()}")

    fn2 = (int.from_bytes(N2, 'big') + 1).to_bytes(len(N2), 'big')
    enc_fn2 = encrypt(fn2, Ks)

    print(f"\n[Alice] === LANGKAH 5: Kirim E(Ks,f(N2)) ke Bob ===")
    print(f"  f(N2) = N2+1 = {fn2.hex()}")
    print(f"  E(Ks,f(N2)) (hex): {enc_fn2.hex()}")

    msg5 = json.dumps({'type': 'STEP5', 'enc_fn2': enc_fn2.hex()})
    send_msg(s, msg5.encode())

    ack = json.loads(recv_msg(s).decode())
    if ack.get('status') == 'OK':
        print("\n[Alice] [OK] Autentikasi berhasil! Session Key Ks disepakati.")
    else:
        print("[Alice] [FAIL] Autentikasi GAGAL.")
        s.close()
        return None

    return s


def chat_recv(sock):
    global session_key
    while True:
        try:
            raw = recv_msg(sock)
            if not raw:
                print("\n[Alice] Koneksi ke Bob terputus.")
                break
            msg = json.loads(raw.decode())
            if msg['type'] == 'CHAT':
                ct_bytes = bytes.fromhex(msg['ciphertext'])
                with session_lock:
                    sk = session_key
                plaintext = decrypt(ct_bytes, sk).decode('utf-8', errors='replace')
                print(f"\n[Bob  -> Alice] Ciphertext (hex): {ct_bytes.hex()}")
                print(f"               Plaintext        : {plaintext}")
                print("[Alice] Pesan: ", end='', flush=True)
            elif msg['type'] == 'NEW_KEY':
                new_key = bytes.fromhex(msg['key'])
                with session_lock:
                    session_key = new_key
                print(f"\n[Alice] Session key diperbarui oleh Bob: {new_key.hex()}")
                print("[Alice] Pesan: ", end='', flush=True)
        except Exception as e:
            print(f"\n[Alice] Error receive: {e}")
            break


def chat_send(sock):
    global session_key
    print("\n[Alice] Mulai chat dengan Bob. Ketik pesan, atau perintah:")
    print("  /key <ascii_key>  -> Ubah session key (maks 16 karakter)")
    print("  /quit             -> Keluar")
    while True:
        try:
            msg_input = input("[Alice] Pesan: ")
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
                print(f"[Alice] Session key diubah: {new_key.hex()}")
            except ValueError as e:
                print(f"[Alice] Error key: {e}")
            continue

        if msg_input == '/quit':
            break

        with session_lock:
            sk = session_key

        ct = encrypt(msg_input.encode('utf-8'), sk)
        chat_msg = json.dumps({'type': 'CHAT', 'ciphertext': ct.hex()})
        send_msg(sock, chat_msg.encode())
        print(f"[Alice -> Bob  ] Plaintext        : {msg_input}")
        print(f"                 Ciphertext (hex) : {ct.hex()}")


def main():
    global session_key
    print(BANNER)

    kdc_ip  = input("KDC IP address   : ").strip()
    bob_ip  = input("Bob IP address   : ").strip()
    bob_port = int(input(f"Bob port (default 8002): ").strip() or "8002")
    kdc_port = int(input(f"KDC port (default 9000): ").strip() or "9000")

    ascii_key = input("Master Key ASCII Alice (maks 16 char): ").strip()
    try:
        master_key = key_from_ascii(ascii_key)
    except ValueError as e:
        print(f"[Alice] Error: {e}")
        return

    print(f"\n[Alice] Master Key Ka (hex): {master_key.hex()}")

    print("\n[Alice] Mendaftar ke KDC...")
    register_to_kdc(kdc_ip, kdc_port, master_key)

    input("\n[Alice] Tekan Enter untuk memulai Key Distribution (pastikan Bob sudah jalan)...")

    Ks, enc_for_b = kdc_key_request(kdc_ip, kdc_port, master_key)
    if Ks is None:
        print("[Alice] Key distribution gagal.")
        return

    session_key = Ks

    bob_sock = do_key_exchange(bob_ip, bob_port, Ks, enc_for_b)
    if bob_sock is None:
        print("[Alice] Key exchange dengan Bob gagal.")
        return

    print(f"\n[Alice] Session Key aktif (hex): {Ks.hex()}")
    print("[Alice] Siap untuk komunikasi dua arah dengan Bob!\n")

    t_recv = threading.Thread(target=chat_recv, args=(bob_sock,), daemon=True)
    t_recv.start()

    chat_send(bob_sock)
    bob_sock.close()
    print("[Alice] Selesai.")


if __name__ == '__main__':
    main()
