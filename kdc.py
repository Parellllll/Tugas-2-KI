
# kdc.py
# Key Distribution Center (KDC)
# Menangani distribusi session key antara Alice dan Bob

import socket
import json
import os
import threading
import struct
from aes_manual import encrypt, decrypt, key_from_ascii

BANNER = """
+------------------------------------------------------+
|         KEY DISTRIBUTION CENTER (KDC)                |
|         Keamanan Informasi - Tugas 2                 |
+------------------------------------------------------+
"""

KDC_PORT = 9000

master_keys = {}
lock = threading.Lock()


def send_msg(sock, data: bytes):
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)


def recv_msg(sock) -> bytes:
    raw_len = recvall(sock, 4)
    if not raw_len:
        return b''
    length = struct.unpack('>I', raw_len)[0]
    return recvall(sock, length)


def recvall(sock, n) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf


def handle_client(conn, addr):
    print(f"\n[KDC] Koneksi dari {addr}")
    try:
        raw = recv_msg(conn)
        if not raw:
            return
        request = json.loads(raw.decode())
        msg_type = request.get('type')

        if msg_type == 'KEY_REQUEST':
            id_a = request['id_a']
            id_b = request['id_b']
            n1   = bytes.fromhex(request['n1'])

            with lock:
                ka = master_keys.get(id_a)
                kb = master_keys.get(id_b)

            if ka is None or kb is None:
                missing = id_a if ka is None else id_b
                err = json.dumps({'type': 'ERROR', 'msg': f'ID {missing} tidak terdaftar di KDC'})
                send_msg(conn, err.encode())
                print(f"[KDC] ERROR: {missing} tidak terdaftar")
                return

            Ks = os.urandom(16)

            payload_for_a = (
                Ks +
                id_a.encode().ljust(8, b'\x00') +
                id_b.encode().ljust(8, b'\x00') +
                n1
            )
            payload_for_b = Ks + id_a.encode().ljust(8, b'\x00')

            enc_for_a = encrypt(payload_for_a, ka)
            enc_for_b = encrypt(payload_for_b, kb)

            response = {
                'type': 'KEY_RESPONSE',
                'enc_for_a': enc_for_a.hex(),
                'enc_for_b': enc_for_b.hex(),
                'Ks_preview': Ks.hex()
            }
            send_msg(conn, json.dumps(response).encode())

            print(f"[KDC] Session Key Ks dibuat untuk {id_a} <-> {id_b}")
            print(f"[KDC] Ks (hex) : {Ks.hex()}")
            print(f"[KDC] Kirim E(Ka,[Ks||IDA||IDB||N1]) || E(Kb,[Ks||IDA]) ke {id_a}")

        elif msg_type == 'REGISTER':
            entity_id  = request['id']
            master_key = bytes.fromhex(request['key'])
            with lock:
                master_keys[entity_id] = master_key
            ack = json.dumps({'type': 'REGISTER_ACK', 'id': entity_id})
            send_msg(conn, ack.encode())
            print(f"[KDC] Terdaftar: {entity_id} | Master Key (hex): {master_key.hex()}")

        else:
            err = json.dumps({'type': 'ERROR', 'msg': 'Pesan tidak dikenali'})
            send_msg(conn, err.encode())

    except Exception as e:
        print(f"[KDC] Exception: {e}")
    finally:
        conn.close()


def interactive_shell():
    while True:
        print("\n[KDC] Menu:")
        print("  1. Lihat daftar entitas terdaftar")
        print("  2. Tambah/Update master key entitas secara manual")
        print("  3. Keluar")
        choice = input("[KDC] Pilih: ").strip()

        if choice == '1':
            with lock:
                if not master_keys:
                    print("[KDC] Belum ada entitas terdaftar.")
                else:
                    for k, v in master_keys.items():
                        print(f"  {k:10s} -> Master Key (hex): {v.hex()}")

        elif choice == '2':
            eid = input("  ID entitas: ").strip()
            ascii_key = input("  Master Key ASCII (maks 16 karakter): ").strip()
            try:
                kb = key_from_ascii(ascii_key)
                with lock:
                    master_keys[eid] = kb
                print(f"  [OK] {eid} terdaftar dengan key: {kb.hex()}")
            except ValueError as e:
                print(f"  [ERROR] {e}")

        elif choice == '3':
            print("[KDC] Shutdown.")
            os._exit(0)


def main():
    print(BANNER)
    host = input("KDC IP (kosong = 0.0.0.0): ").strip() or '0.0.0.0'

    print("\n--- Setup Master Key Awal ---")
    print("Masukkan master key untuk Alice dan Bob (atau kosongkan untuk daftarkan via program).")
    for eid in ['Alice', 'Bob']:
        ascii_key = input(f"  Master Key ASCII untuk {eid} (maks 16 char, kosong = skip): ").strip()
        if ascii_key:
            try:
                kb = key_from_ascii(ascii_key)
                master_keys[eid] = kb
                print(f"  [{eid}] Key terdaftar: {kb.hex()}")
            except ValueError as e:
                print(f"  [ERROR] {e}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, KDC_PORT))
    srv.listen(10)
    print(f"\n[KDC] Mendengarkan di {host}:{KDC_PORT} ...")

    def accept_loop():
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

    t_accept = threading.Thread(target=accept_loop, daemon=True)
    t_accept.start()

    interactive_shell()


if __name__ == '__main__':
    main()
