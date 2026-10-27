CREATE TABLE products (
    id INT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

INSERT INTO products (id, name) VALUES
    (1, 'Desk lamp'),
    (2, 'Notebook');

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL
);

INSERT INTO users (id, username, password) VALUES
    (1, 'admin', 'lab-only-password');
