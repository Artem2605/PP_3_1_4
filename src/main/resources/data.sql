DELETE from users_roles;
DELETE from roles;
DELETE from users;
INSERT INTO roles (name)
values ('ADMIN'),
       ('USER');
INSERT INTO users (username, first_name, last_name, password, age)
VALUES ('admin@mail.ru', 'admin', 'admin', '$2a$10$Q/b7EGrTR1TUhLVJxifxieNWm0PBtt0wW0HXgzaDOYcHwv6nD9Pg2', 777);
INSERT INTO users_roles
SET user_id=(SELECT id FROM users WHERE username = 'admin@mail.ru'),
    role_id = (SELECT id FROM roles WHERE name = 'ADMIN');
INSERT INTO users_roles
SET user_id=(SELECT id FROM users WHERE username = 'admin@mail.ru'),
    role_id = (SELECT id FROM roles WHERE name = 'USER');
INSERT INTO users (username, first_name, last_name, password, age)
VALUES ('user@mail.ru', 'user', 'user', '$2a$12$3sa6ec/eVkjtk0Fsp4p8RuwDNK5EbTHlZ1srZjz2adXEJGEzLx1GC', 20);
INSERT INTO users_roles
SET user_id=(SELECT id FROM users WHERE username = 'user@mail.ru'),
    role_id = (SELECT id FROM roles WHERE name = 'USER');
INSERT INTO users (username, first_name, last_name, password, age)
VALUES ('ivan@mail.ru', 'ivan', 'ivanov', '$2a$12$ZLij0jYEBVbWiiLndaoIe.06eB1mVoUpcd.ue1bf9urymRUjvcQsG', 20);
INSERT INTO users_roles
SET user_id=(SELECT id FROM users WHERE username = 'ivan@mail.ru'),
    role_id = (SELECT id FROM roles WHERE name = 'ADMIN');
INSERT INTO users_roles
SET user_id=(SELECT id FROM users WHERE username = 'ivan@mail.ru'),
    role_id = (SELECT id FROM roles WHERE name = 'USER');