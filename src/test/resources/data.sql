INSERT INTO lnlauth2."user"(user_id, email, password, activated, first_name, last_name) VALUES ('582a42633dfd4bea897c88f7612bc165', 'admin@lnl.com', '$2a$10$r8FwK5xjVRZwcd/fxehlH.Idp9NQgadd.pQR.JprZkmynyzCtUVqa',true , 'piomin', 'minkowski');
INSERT INTO lnlauth2.authority (name) VALUES ('ROLE_ADMIN');
INSERT INTO lnlauth2.authority (name) VALUES ('ROLE_USER');
INSERT INTO lnlauth2.user_authority (user_id, authority) VALUES ('582a42633dfd4bea897c88f7612bc165', 'ROLE_ADMIN');

INSERT INTO lnlauth2."user"(user_id, email, password, activated, first_name, last_name) VALUES ('9217c4b3ef1a4b178657da25654c3afd', 'sayan@lnl.com', '$2a$10$r8FwK5xjVRZwcd/fxehlH.Idp9NQgadd.pQR.JprZkmynyzCtUVqa',false , 'sayan', 'roy');
INSERT INTO lnlauth2.user_authority (user_id, authority) VALUES ('9217c4b3ef1a4b178657da25654c3afd', 'ROLE_ADMIN');


INSERT INTO lnlauth2."user"(user_id, email, password, activated, first_name, last_name) VALUES ('ec66f7790ae34d869ba9204a47590ce5', 'user2@lnl.com', '$2a$10$r8FwK5xjVRZwcd/fxehlH.Idp9NQgadd.pQR.JprZkmynyzCtUVqa',true , 'user2', 'user2');
INSERT INTO lnlauth2.user_authority (user_id, authority) VALUES ('ec66f7790ae34d869ba9204a47590ce5', 'ROLE_ADMIN');

INSERT INTO lnlauth2.oauth_client_details VALUES('authserver','', '$2a$10$Do19evC2D04s8MK4RQzxdOaUnwEHlapNLhReYekfzqOX0svv22FVS', 'read,write,myscope', 'client_credentials,authorization_code,implicit,password', 'http://localhost:8080/login/oauth2/code/authserver', 'ROLE_ADMIN', NULL, 0, NULL, 'true');