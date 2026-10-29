<?php // INTENTIONALLY VULNERABLE - lab only
require __DIR__ . '/db.php';
$id = $_GET['id'] ?? '0';
$query = "SELECT id, name FROM products WHERE id = $id";
$products = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Product lookup</title></head>
  <body>
    <h1>Product lookup</h1>
    <?php foreach ($products as $product): ?>
      <p><?= htmlspecialchars($product['name'], ENT_QUOTES, 'UTF-8') ?></p>
    <?php endforeach; ?>
  </body>
</html>
