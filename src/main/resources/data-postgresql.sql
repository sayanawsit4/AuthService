-- Run all actions in a transaction for safety.
BEGIN;

SET search_path = lnlauth2;

INSERT INTO lnlauth2.authority (name) VALUES ('ROLE_USER')  ON CONFLICT (name) DO NOTHING;
INSERT INTO lnlauth2.authority (name) VALUES ('ROLE_ADMIN') ON CONFLICT (name) DO NOTHING;

-- Create user records for AuthService.
DO'
   <<first_block>>
    DECLARE
     counter integer := 0;
    BEGIN
     SELECT count(*) INTO counter FROM lnlauth2."user";
       IF counter = 0 THEN
            INSERT INTO lnlauth2."user" (email, user_id, password ,activated, first_name, last_name)
            SELECT DISTINCT ON (t.email) email ,
                               CAST (t.user_id  AS UUID) user_id,
                               t.password,
                               t.is_active,
                               t.first_name,
                               t.last_name
                               FROM (SELECT CAST (u.user_id  AS UUID),
                                            u.email,
                                            password,
                                            is_active,
                                            first_name,
                                            last_name FROM lnlauth."user" u
                                            GROUP BY u.user_id,u.email HAVING is_active=true) as t;
       END IF;
     END first_block';

INSERT INTO lnlauth2."user_authority" (user_id,authority)
SELECT user_id,'ROLE_USER' FROM lnlauth2."user" u
ON CONFLICT (user_id,authority)
DO NOTHING;

INSERT INTO lnlauth2.oauth_client_details (client_id, access_token_validity, additional_information, authorities, authorized_grant_types, autoapprove, client_secret, refresh_token_validity, resource_ids, scope, web_server_redirect_uri)
VALUES ('6ab37b5500fe440bb6cf2f93f6f37140',null, '{}', 'ROLE_ADMIN', 'client_credentials,implicit,authorization_code,refresh_token,password', 'true', '$2a$10$TnVBcMF7qQVJEgSdPsC1LObinh6XON5YobJkEf0WrkI3YQPUyjNSa', null, '', 'read,ad-hoc-auth-sso,one-time,write,ad-hoc-extn,ad-hoc', 'https://apps-staging.lnl.com')
ON CONFLICT (client_id)
DO NOTHING;
INSERT INTO lnlauth2.oauth_client_details (client_id, access_token_validity, additional_information, authorities, authorized_grant_types, autoapprove, client_secret, refresh_token_validity, resource_ids, scope, web_server_redirect_uri)
VALUES ('93dca73c-6406-443e-8ead-e98c2d37519f', null, '{}', 'ROLE_ADMIN', 'client_credentials,implicit,authorization_code,refresh_token,password', 'true', '$2a$10$3WV3ARrRu9qUeuAcerQv5uuOT24nUvbSr0N5YTog6x6fYiSQoLRcK', null, '', 'read,ad-hoc-auth-sso,one-time,write,ad-hoc-extn,ad-hoc', 'https://test.lnl.com')
ON CONFLICT (client_id)
DO NOTHING;

COMMIT;