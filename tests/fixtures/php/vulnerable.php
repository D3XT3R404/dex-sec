<?php
/**
 * Fixture DEX-SEC — sengaja rentan, hanya untuk pengujian internal.
 * Meniru pola umum aplikasi PHP: input dari request -> query/file/echo.
 */

session_start();

$q = $_GET['q'] ?? '';
$page = $_GET['page'] ?? 'home';
$upload_name = $_POST['filename'] ?? '';

// 1. SQL Injection — input dirangkai ke query
$conn = new mysqli('localhost', 'root', '', 'demo');
$result = $conn->query("SELECT id, name FROM products WHERE name LIKE '%$q%'");

// 2. XSS reflected — input langsung dicetak
echo "<h1>Hasil pencarian untuk $q</h1>";

// 3. Local File Inclusion — nama file dari request
include($page);

// 4. Command injection — input masuk ke shell
$host = $_GET['host'] ?? '';
system("ping -c 1 " . $host);

// 5. File upload tanpa validasi ekstensi
if (isset($_FILES['file'])) {
    $target = "uploads/" . $upload_name;
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
}

// 6. Cookie session tanpa flag keamanan
setcookie('session_id', $_GET['sid'] ?? '', ['expires' => time() + 3600, 'path' => '/']);
