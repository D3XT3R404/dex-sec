"""
Aplikasi web latihan DEX-SEC — DELIBERATELY VULNERABLE.

HANYA untuk belajar. Jangan pernah menaruhnya di internet atau di server sungguhan.

Kerentanan yang sengaja ada:
    SQL Injection pada endpoint /search  (query dirangkai dari input pengguna)

Cara menjalankan:
    pip install flask
    python sandbox/vuln_web/app.py
    # buka http://127.0.0.1:8080 di browser

Lalu jalankan DEX-SEC:
    dexsec scan --path sandbox/vuln_web --target http://127.0.0.1:8080
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

DB_PATH = Path(__file__).parent / "products.db"

PRODUCTS = [
    (1, "Kaos polos cotton", 85000),
    (2, "Hoodie unisex", 189000),
    (3, "Kemeja linen", 245000),
    (4, "Celana jeans", 299000),
]


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    """Halaman utama: daftar produk (aman)."""
    conn = get_db()
    rows = conn.execute("SELECT id, name, price FROM products").fetchall()
    conn.close()
    items = "\n".join(
        f'<li><b>{row["name"]}</b> — Rp {row["price"]:,}</li>' for row in rows
    )
    return f"""
    <html><head><title>Toko Latihan DEX-SEC</title></head>
    <body style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
      <h1>Toko Latihan DEX-SEC</h1>
      <p>Aplikasi ini <b>sengaja</b> memiliki SQL injection pada halaman pencarian.</p>
      <form action="/search" method="get">
        <input name="q" placeholder="cari produk..." style="padding:8px;width:280px;">
        <button>Cari</button>
      </form>
      <h2>Daftar produk</h2>
      <ul>{items}</ul>
    </body></html>
    """


@app.route("/search")
def search():
    """Pencarian produk — VULNERABLE: input pasted ke query SQL.

    Seharusnya memakai query berparameter:
        conn.execute("SELECT ... WHERE name LIKE ?", (f"%{q}%",))
    """
    keyword = request.args.get("q", "")
    conn = get_db()
    # ----- RENTAN: string dirangkai langsung ke SQL -----
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        return f"<html><body><h1>Database error</h1><pre>{exc}</pre></body></html>", 500
    conn.close()

    items = "\n".join(
        f'<li><b>{row["name"]}</b> — Rp {row["price"]:,}</li>' for row in rows
    )
    return f"""
    <html><body style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
      <h1>Hasil pencarian</h1>
      <p>Query yang dijalankan: <code>{query}</code></p>
      <ul>{items or "<li>Tidak ada hasil</li>"}</ul>
      <p><a href="/">kembali</a></p>
    </body></html>
    """


@app.route("/product/<int:product_id>")
def product(product_id: int):
    """Detail produk — aman (query berparameter)."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, name, price FROM products WHERE id = ?", (product_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return "<html><body>Produk tidak ditemukan</body></html>", 404
    return (
        f"<html><body style='font-family: system-ui; max-width:720px;margin:40px auto'>"
        f"<h1>{row['name']}</h1><p>Harga: Rp {row['price']:,}</p>"
        f"<p><a href='/'>kembali</a></p></body></html>"
    )


def init_db() -> None:
    """Buat database contoh (dibiarkan relatif ke file agar mudah dihapus)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS products")
    conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER)")
    conn.executemany("INSERT INTO products (id, name, price) VALUES (?, ?, ?)", PRODUCTS)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" APLIKASI LATIHAN DEX-SEC (SENGaja rentan: SQL Injection)")
    print(" Buka:  http://127.0.0.1:8080")
    print(" Jalankan DEX-SEC:")
    print("   dexsec scan --path sandbox/vuln_web --target http://127.0.0.1:8080")
    print("=" * 60)
    app.run(host="127.0.0.1", port=8080, debug=False)
