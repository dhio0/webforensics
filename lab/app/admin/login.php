<?php // INTENTIONALLY VULNERABLE - lab only
session_start();
require __DIR__ . '/../db.php';
$message = '';
if (isset($_GET['username'], $_GET['password'])) {
    $username = $_GET['username'];
    $password = $_GET['password'];
    $query = "SELECT id, username FROM users WHERE username = '$username' AND password = '$password'";
    $user = $pdo->query($query)->fetch(PDO::FETCH_ASSOC);
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $message = 'Login successful';
    } else {
        http_response_code(401);
        $message = 'Login failed';
    }
}
?>
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Lab login</title></head>
  <body>
    <h1>Lab login</h1>
    <p><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></p>
    <form method="get">
      <input name="username" required>
      <input name="password" type="password" required>
      <button type="submit">Log in</button>
    </form>
  </body>
</html>
