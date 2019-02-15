CREATE DATABASE certmiss;

CREATE TABLE lints (
  fingerprint CHAR(64) PRIMARY KEY NOT NULL,
  errors_present BOOLEAN NULL,
  warnings_present BOOLEAN NULL,
  fatals_present BOOLEAN NULL,
  notices_present BOOLEAN NULL,
  organization TEXT NULL,
  added_at TIMESTAMPTZ NULL,
  is_ca BOOLEAN NULL,
  valid_start TIMESTAMP NULL,
  valid_end TIMESTAMP NULL,
  issuing_certificate_url TEXT NULL,
  issuer_org TEXT NULL,
  organizationalunit TEXT NULL,
  country TEXT NULL,
  domaincomponent TEXT NULL,
  emailaddress TEXT NULL,
  givenname TEXT NULL,
  surname TEXT NULL,
  serialnumber TEXT NULL,
  updated_at TEXT NULL,
  -- lints
  e_dnsname_not_valid_tld varchar(10) NULL,
  e_ext_authority_key_identifier_missing varchar(10) NULL,
  e_dnsname_bad_character_in_label varchar(10) NULL,
  e_ext_san_missing varchar(10) NULL,
  e_subject_common_name_not_from_san varchar(10) NULL,
  e_ext_san_uniform_resource_identifier_present varchar(10) NULL,
  w_ext_subject_key_identifier_missing_sub_cert varchar(10) NULL,
  w_ext_key_usage_not_critical varchar(10) NULL,
  w_ext_cert_policy_explicit_text_not_utf8 varchar(10) NULL,
  w_ext_cert_policy_contains_noticeref varchar(10) NULL,
  w_sub_cert_aia_does_not_contain_issuing_ca_url varchar(10) NULL,
  w_sub_cert_eku_extra_values varchar(10) NULL,
  e_ext_san_rfc822_name_present varchar(10) NULL
);

CREATE USER mweise WITH PASSWORD '****';
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mweise;