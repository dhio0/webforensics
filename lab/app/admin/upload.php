<?php // INTENTIONALLY VULNERABLE - lab only
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $name = basename($_FILES['file']['name']);
    $destination = __DIR__ . '/../uploads/' . $name;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $destination)) {
        echo 'Uploaded: ' . htmlspecialchars('/uploads/' . $name, ENT_QUOTES, 'UTF-8');
        exit;
    }
    http_response_code(400);
    echo 'Upload failed';
    exit;
}
?>
<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Lab upload</title></head>
  <body>
    <h1>Lab upload</h1>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file" required>
      <button type="submit">Upload</button>
    </form>
  </body>
</html>
