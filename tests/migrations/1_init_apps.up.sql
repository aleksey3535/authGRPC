INSERT INTO apps(id, name, secret)
VALUES (2, 'app', 'qwerty')
ON CONFLICT DO NOTHING;
