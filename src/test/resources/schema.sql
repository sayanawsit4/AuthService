CREATE SCHEMA  IF NOT EXISTS  lnlauth2;

SET SCHEMA lnlauth2;

CREATE TABLE IF NOT EXISTS  lnlauth2.oauth_access_token ( token_id VARCHAR(255), token bytea, authentication_id VARCHAR(255), user_name VARCHAR(255), client_id VARCHAR(255), authentication bytea, refresh_token VARCHAR(255), expiration TIMESTAMP(6) );
CREATE TABLE IF NOT EXISTS  lnlauth2.oauth_client_details ( client_id VARCHAR(255), resource_ids VARCHAR(255), client_secret VARCHAR(255), "scope" VARCHAR(255), authorized_grant_types VARCHAR(255), web_server_redirect_uri VARCHAR(255), authorities VARCHAR(255), access_token_validity INTEGER, refresh_token_validity INTEGER, additional_information VARCHAR(255), autoapprove VARCHAR(255) );
CREATE TABLE IF NOT EXISTS  lnlauth2."user" (user_id UUID NOT NULL, email CHARACTER VARYING(50), password CHARACTER VARYING(500), activated BOOLEAN DEFAULT false, first_name CHARACTER VARYING(255), last_name CHARACTER VARYING(255), PRIMARY KEY (user_id),version INTEGER);
CREATE TABLE IF NOT EXISTS  lnlauth2.authority (name CHARACTER VARYING(50) NOT NULL, PRIMARY KEY (name));
CREATE TABLE IF NOT EXISTS  lnlauth2.user_authority (user_id UUID NOT NULL, authority CHARACTER VARYING(50) NOT NULL);
CREATE TABLE IF NOT EXISTS  lnlauth2.operational_audit (ops_audit_rec_no UUID NOT NULL, client_id CHARACTER VARYING(255), created_time TIMESTAMP(6) WITHOUT TIME ZONE, ops_performed_by CHARACTER VARYING(255), remote_ip CHARACTER VARYING(255), response CHARACTER VARYING(255), scope CHARACTER VARYING(255), status CHARACTER VARYING(255), token_id CHARACTER VARYING(255), url CHARACTER VARYING(255), target_user CHARACTER VARYING(255), user_agent CHARACTER VARYING(255), PRIMARY KEY (ops_audit_rec_no));
CREATE TABLE IF NOT EXISTS  lnlauth2.spring_session (session_id CHARACTER(36) NOT NULL, creation_time BIGINT NOT NULL, last_access_time BIGINT NOT NULL, max_inactive_interval INTEGER NOT NULL, expiry_time BIGINT, principal_name CHARACTER VARYING(100), CONSTRAINT spring_session_pk PRIMARY KEY (session_id));
CREATE TABLE IF NOT EXISTS  lnlauth2.spring_session_attributes (session_id CHARACTER(36) NOT NULL, attribute_name CHARACTER VARYING(200) NOT NULL, attribute_bytes BYTEA NOT NULL, CONSTRAINT spring_session_attributes_pk PRIMARY KEY (session_id, attribute_name), CONSTRAINT spring_session_attributes_fk FOREIGN KEY (session_id) REFERENCES "spring_session" ("session_id") ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS  lnlauth2.access_attempt_counter (user_id UUID NOT NULL, counter INTEGER, last_attempt_time TIMESTAMP(6), PRIMARY KEY (user_id));
CREATE TABLE IF NOT EXISTS  lnlauth2.access_audit (access_audit_rec_no UUID NOT NULL, status CHARACTER VARYING(255), user_id UUID, no_of_attemps INTEGER, PRIMARY KEY (access_audit_rec_no));
CREATE TABLE IF NOT EXISTS  lnlauth2.oauth_refresh_token (token_id CHARACTER VARYING(255), token BYTEA, authentication BYTEA);


DELETE FROM lnlauth2.user_authority;
DELETE FROM lnlauth2.authority;
DELETE FROM lnlauth2."user";
DELETE FROM lnlauth2.oauth_client_details;
DELETE FROM lnlauth2.access_attempt_counter;