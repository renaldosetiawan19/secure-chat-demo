# Secure Chat Demo (SC1)

> ⚠️ **Demo edukasi. Belum diaudit. JANGAN dipakai di produksi.**
> Gunakan library matang (mis. Signal Protocol, libsodium/age, TLS 1.3) untuk sistem nyata.

Demo protokol pesan aman sederhana dengan Python untuk mempelajari konsep kriptografi terapan.

## Komponen
| Fungsi | Primitif |
|---|---|
| Pertukaran kunci | X25519 (ephemeral) |
| Autentikasi identitas | Ed25519 (tanda tangan handshake) |
| Derivasi kunci | HKDF-SHA256 + transcript hash |
| Enkripsi pesan | AES-256-GCM, kunci per pesan dari hash ratchet |
| Verifikasi manual | Safety number (60 digit) |

Semua primitif berasal dari library [`cryptography`](https://cryptography.io); tidak ada algoritma buatan sendiri.

## Alur handshake
1. **Hello** (Alice → Bob): identitas, suite, ephemeral public key, nonce, ditandatangani IK Alice.
2. **Reply** (Bob → Alice): ephemeral public key, nonce, hash Hello, ditandatangani IK Bob.
3. **Pesan data** (Alice → Bob): AES-256-GCM dengan kunci per pesan. Tag valid di sisi Bob berfungsi sebagai **key confirmation implisit**.

Bob juga dapat menyimpan nonce Hello (`seen_nonces`) untuk menolak replay handshake.

## Menjalankan
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

python secure_chat_demo.py       # demo + eksperimen
pytest -q                        # unit test
```
Python 3.9+.

## Jaminan
- Kerahasiaan dan integritas pesan (AES-GCM, AAD terikat ke sesi, arah, dan counter).
- Forward secrecy antar sesi (ephemeral key dibuang setelah handshake).
- Anti replay/reorder dalam satu sesi (counter harus berurutan) dan anti replay handshake (cache nonce Hello).
- Anti MITM **jika** identity key (IK) sudah diverifikasi lewat safety number.
- Domain separation pada tanda tangan dan KDF.

## Batasan (disengaja, ini demo)
- **Tidak ada distribusi/verifikasi IK**: jika IK palsu dipercaya, handshake tetap sukses (lihat demo "IK palsu").
- **Tidak ada post-compromise security**: hanya hash ratchet, bukan Double Ratchet penuh. Bocornya chain key membuka semua pesan setelahnya.
- Tidak ada penanganan pesan hilang/out-of-order, rekey, atau penyembunyian metadata.
- Tidak ada transport jaringan; semua berjalan in-memory.
- Zeroization di Python tidak dapat dijamin (string `bytes` immutable, GC, salinan di memori).
- Belum ada audit keamanan independen.

## Lisensi
MIT. Lihat [LICENSE](LICENSE). Ganti `<NAMA ANDA>` di file tersebut sebelum upload.
