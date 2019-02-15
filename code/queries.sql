-- TABLE 1: Largest Authorities

-- TOTAL CERTIFICATES OF let's encrypt
SELECT organization, COUNT(DISTINCT fingerprint) AS lets_total FROM lints WHERE organization SIMILAR TO 'Lets Encrypt%' GROUP BY organization;

-- TOTAL CERTIFICATES OF let's encrypt CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS lets_err FROM lints WHERE organization SIMILAR TO 'Lets Encrypt%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF let's encrypt CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS lets_warn FROM lints WHERE organization SIMILAR TO 'Lets Encrypt%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF cPanel
SELECT organization, COUNT(DISTINCT fingerprint) AS cpan_total FROM lints WHERE organization SIMILAR TO 'cPanel Inc%' GROUP BY organization;

-- TOTAL CERTIFICATES OF cPanel CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS cpan_err FROM lints WHERE organization SIMILAR TO 'cPanel Inc%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF cPanel CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS cpan_warn FROM lints WHERE organization SIMILAR TO 'cPanel Inc%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF Comodo
SELECT organization, COUNT(DISTINCT fingerprint) AS comodo_total FROM lints WHERE organization SIMILAR TO 'Comodo%' GROUP BY organization;

-- TOTAL CERTIFICATES OF Comodo CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS comodo_err FROM lints WHERE organization SIMILAR TO 'Comodo%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF Comodo CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS comodo_warn FROM lints WHERE organization SIMILAR TO 'Comodo%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF Symantec
SELECT organization, COUNT(DISTINCT fingerprint) AS symantec_total FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY organization;

-- TOTAL CERTIFICATES OF Symantec CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS symantec_err FROM lints WHERE organization SIMILAR TO 'Symantec%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF Symantec CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS symantec_warn FROM lints WHERE organization SIMILAR TO 'Symantec%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF geotrust Inc.
SELECT organization, COUNT(DISTINCT fingerprint) AS geo_total FROM lints WHERE organization SIMILAR TO 'GeoTrust%' GROUP BY organization;

-- TOTAL CERTIFICATES OF geotrust Inc. CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS geo_err FROM lints WHERE organization SIMILAR TO 'GeoTrust%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF geotrust Inc. CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS geo_warn FROM lints WHERE organization SIMILAR TO 'GeoTrust%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF godaddy
SELECT organization, COUNT(DISTINCT fingerprint) AS godaddy_total FROM lints WHERE organization SIMILAR TO 'Go Daddy%' GROUP BY organization;

-- TOTAL CERTIFICATES OF godaddy CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS godaddy_err FROM lints WHERE organization SIMILAR TO 'Go Daddy%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF godaddy CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS godaddy_warn FROM lints WHERE organization SIMILAR TO 'Go Daddy%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF globalsign
SELECT organization, COUNT(DISTINCT fingerprint) AS gsign_total FROM lints WHERE organization SIMILAR TO 'GlobalSign%' GROUP BY organization;

-- TOTAL CERTIFICATES OF globalsign CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS gsign_err FROM lints WHERE organization SIMILAR TO 'GlobalSign%' AND errors_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES OF globalsign CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS gsign_warn FROM lints WHERE organization SIMILAR TO 'GlobalSign%' AND warnings_present = 'true' GROUP BY organization;

-- TOTAL CERTIFICATES 
SELECT organization, COUNT(DISTINCT fingerprint) AS other_total FROM lints GROUP BY organization HAVING COUNT(DISTINCT fingerprint) >= 1000000;

-- TOTAL CERTIFICATES CONTAINING errors
SELECT organization, COUNT(DISTINCT fingerprint) AS other_err FROM lints WHERE errors_present = 'true' GROUP BY organization HAVING COUNT(DISTINCT fingerprint) >= 1000000;

-- TOTAL CERTIFICATES CONTAINING warnings
SELECT organization, COUNT(DISTINCT fingerprint) AS other_warn FROM lints WHERE warnings_present = 'true' GROUP BY organization HAVING COUNT(DISTINCT fingerprint) >= 1000000;




-- Fig. 2

-- CERTIFICATES FROM 2012
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2012-12-31') AND ('2012-01-01' <= valid_end);


-- CERTIFICATES FROM 2013
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2013-12-31') AND ('2013-01-01' <= valid_end);


-- CERTIFICATES FROM 2014
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2014-12-31') AND ('2014-01-01' <= valid_end);


-- CERTIFICATES FROM 2015
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2015-12-31') AND ('2015-01-01' <= valid_end);


-- CERTIFICATES FROM 2016
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2016-12-31') AND ('2016-01-01' <= valid_end);


-- CERTIFICATES FROM 2017
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2017-12-31') AND ('2017-01-01' <= valid_end);


-- CERTIFICATES FROM 2012 WITH WARNINGS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2012-12-31') AND ('2012-01-01' <= valid_end) AND warnings_present = 'true';


-- CERTIFICATES FROM 2013 WITH WARNINGS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2013-12-31') AND ('2013-01-01' <= valid_end) AND warnings_present = 'true';


-- CERTIFICATES FROM 2014 WITH WARNINGS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2014-12-31') AND ('2014-01-01' <= valid_end) AND warnings_present = 'true';


-- CERTIFICATES FROM 2015 WITH WARNINGS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2015-12-31') AND ('2015-01-01' <= valid_end) AND warnings_present = 'true';


-- CERTIFICATES FROM 2016 WITH WARNINGS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2016-12-31') AND ('2016-01-01' <= valid_end) AND warnings_present = 'true';


-- CERTIFICATES FROM 2017 WITH WARNINGS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2017-12-31') AND ('2017-01-01' <= valid_end) AND warnings_present = 'true';


-- CERTIFICATES FROM 2012 WITH ERRORS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2012-12-31') AND ('2012-01-01' <= valid_end) AND errors_present = 'true';


-- CERTIFICATES FROM 2013 WITH ERRORS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2013-12-31') AND ('2013-01-01' <= valid_end) AND errors_present = 'true';


-- CERTIFICATES FROM 2014 WITH ERRORS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2014-12-31') AND ('2014-01-01' <= valid_end) AND errors_present = 'true';


-- CERTIFICATES FROM 2015 WITH ERRORS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2015-12-31') AND ('2015-01-01' <= valid_end) AND errors_present = 'true';


-- CERTIFICATES FROM 2016 WITH ERRORS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2016-12-31') AND ('2016-01-01' <= valid_end) AND errors_present = 'true';


-- CERTIFICATES FROM 2017 WITH ERRORS_PRESENT
SELECT COUNT(DISTINCT fingerprint) FROM lints WHERE (valid_start <= '2017-12-31') AND ('2017-01-01' <= valid_end) AND errors_present = 'true';


-- TABLE II

-- Errors Subject
SELECT e_subject_common_name_not_from_san, COUNT(e_subject_common_name_not_from_san) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_subject_common_name_not_from_san;

-- Errors SAN
SELECT e_ext_san_missing, COUNT(e_ext_san_missing) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_ext_san_missing;

-- Errors Invalid Char DNSNAME
SELECT e_dnsname_not_valid_tld, COUNT(e_dnsname_not_valid_tld) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_dnsname_not_valid_tld;

-- Errors AKID
SELECT e_ext_authority_key_identifier_missing, COUNT(e_ext_authority_key_identifier_missing) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_ext_authority_key_identifier_missing;

-- Errors DNSNAME character
SELECT e_dnsname_bad_character_in_label, COUNT(e_dnsname_bad_character_in_label) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_dnsname_bad_character_in_label;

-- Errors SAN RIP
SELECT e_ext_san_uniform_resource_identifier_present, COUNT(e_ext_san_uniform_resource_identifier_present) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_ext_san_uniform_resource_identifier_present;

-- Errors RFC
SELECT e_ext_san_rfc822_name_present, COUNT(e_ext_san_rfc822_name_present) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY e_ext_san_rfc822_name_present;

-- Warnings KID
SELECT w_ext_subject_key_identifier_missing_sub_cert, COUNT(w_ext_subject_key_identifier_missing_sub_cert) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY w_ext_subject_key_identifier_missing_sub_cert;

-- Warnings KU 
SELECT w_ext_key_usage_not_critical, COUNT(w_ext_key_usage_not_critical) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY w_ext_key_usage_not_critical;

-- Warnings Policy UTF 
SELECT w_ext_cert_policy_explicit_text_not_utf8, COUNT(w_ext_cert_policy_explicit_text_not_utf8) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY w_ext_cert_policy_explicit_text_not_utf8;

-- Warnings Policy Noticeref 
SELECT w_ext_cert_policy_contains_noticeref, COUNT(w_ext_cert_policy_contains_noticeref) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY w_ext_cert_policy_contains_noticeref;

-- Warnings CA URL
SELECT w_sub_cert_aia_does_not_contain_issuing_ca_url, COUNT(w_sub_cert_aia_does_not_contain_issuing_ca_url) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY w_sub_cert_aia_does_not_contain_issuing_ca_url;

-- Warnings Subcert
SELECT w_sub_cert_eku_extra_values, COUNT(w_sub_cert_eku_extra_values) FROM lints WHERE organization SIMILAR TO 'Symantec%' GROUP BY w_sub_cert_eku_extra_values;


