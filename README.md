Syslog-Capture


This Collector requires the following set up:
  - For production or staging ensure you harden the mysql database (NO hardening is done in the below)

---------------------------------------------------------------------------------------------------------------------------------
sudo apt update 
sudo apt install mysql-server 

Once Mysql is installed:
	• shell>  sudo mysql -u root
	• mysql> CREATE USER IF NOT EXISTS 'logcatcher-user'@'localhost' identified by 'logcatcher-password';
	• mysql> CREATE DATABASE log_data;
	• mysql> GRANT ALL PRIVILEGES on log_data.* to 'logcatcher-user'@'localhost' identified by 'logcatcher-password';
	• mysql> CREATE TABLE `log_data`.`raw_data` (
          `index` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
          `priority` VARCHAR(4) NOT NULL DEFAULT '14',
          `version` VARCHAR(4) NOT NULL DEFAULT 0,
          `time_stamp`  TIMESTAMP(3) NULL,
          `hostname` VARCHAR(256) NULL,
          `app_name` varchar(49) NULL,
          `proc_id` varchar(129) NULL,
          `message_id` varchar(33) NULL,
          `structured_data` varchar(2048) NULL,
          `sd_application` varchar(64) NULL,
          `sd_bytes_from_client` varchar(20) NULL,
          `sd_bytes_from_server` varchar(20) NULL,
          `sd_connection_tag` varchar(10) NULL,
          `sd_destination_address` varchar(20) NULL,
          `sd_destination_interface_name` varchar(20) NULL,
          `sd_destination_port` varchar(10) NULL,
          `sd_destination_zone_name` varchar(64) NULL,
          `sd_dst_nat_rule_name` varchar(64) NULL,
          `sd_dst_nat_rule_type` varchar(32) NULL,
          `sd_elapsed_time` varchar(20) NULL,
          `sd_encrypted` varchar(20) NULL,
          `sd_icmp_type` varchar(10) NULL,
          `sd_message` varchar(256) NULL,
          `sd_name` varchar(32) NULL,
          `sd_nat_connection_tag` varchar(10) NULL,
          `sd_nat_destination_address` varchar(20) NULL,
          `sd_nat_destination_port` varchar(10) NULL,
          `sd_nat_source_address` varchar(20) NULL,
          `sd_nat_source_port` varchar(10) NULL,
          `sd_nested_application` varchar(64) NULL,
          `sd_packet_incoming_interface` varchar(10) NULL,
          `sd_packets_from_client` varchar(20) NULL,
          `sd_packets_from_server` varchar(20) NULL,
          `sd_policy_name` varchar(64) NULL,
          `sd_profile_name` varchar(64) NULL,
          `sd_protocol_id` varchar(10) NULL,
          `sd_reason` varchar(64) NULL,
          `sd_roles` varchar(64) NULL,
          `sd_routing_instance` varchar(64) NULL,
          `sd_rule_name` varchar(64) NULL,
          `sd_service_name` varchar(64) NULL,
          `sd_session_id_32` varchar(64) NULL,
          `sd_source_address` varchar(20) NULL,
          `sd_source_port` varchar(10) NULL,
          `sd_source_zone_name` varchar(64) NULL,
          `sd_src_nat_rule_name` varchar(26) NULL,
          `sd_src_nat_rule_type` varchar(16) NULL,
          `sd_username` varchar(64) NULL,
          PRIMARY KEY (`index`),
          UNIQUE INDEX `index_UNIQUE` (`index` ASC));


---------------------------------------------------------------------------------------------------------------------------------






mysql> show tables;
+--------------------+
| Tables_in_log_data |
+--------------------+
| raw_data           |
+--------------------+
1 row in set (0.00 sec)

mysql> show columns from raw_data;
+-------------------------------+------------------+------+-----+---------+-------+
| Field                         | Type             | Null | Key | Default | Extra |
+-------------------------------+------------------+------+-----+---------+-------+
| index                         | int(10) unsigned | NO   | PRI | NULL    |       |
| priority                      | varchar(4)       | NO   |     | NULL    |       |
| version                       | varchar(4)       | NO   |     | 0       |       |
| time_stamp                    | varchar(40)      | YES  |     | NULL    |       |
| hostname                      | varchar(256)     | YES  |     | NULL    |       |
| app_name                      | varchar(49)      | YES  |     | NULL    |       |
| proc_id                       | varchar(129)     | YES  |     | NULL    |       |
| message_id                    | varchar(33)      | YES  |     | NULL    |       |
| structured_data               | varchar(2048)    | YES  |     | NULL    |       |
| sd-application                | varchar(64)      | YES  |     | NULL    |       |
| sd-bytes-from-client          | varchar(20)      | YES  |     | NULL    |       |
| sd-bytes-from-server          | varchar(20)      | YES  |     | NULL    |       |
| sd-connection-tag             | varchar(10)      | YES  |     | NULL    |       |
| sd-destination-address        | varchar(20)      | YES  |     | NULL    |       |
| sd-destination-interface-name | varchar(20)      | YES  |     | NULL    |       |
| sd-destination-port           | varchar(10)      | YES  |     | NULL    |       |
| sd-destination-zone-name      | varchar(64)      | YES  |     | NULL    |       |
| sd-dst-nat-rule-name          | varchar(64)      | YES  |     | NULL    |       |
| sd-dst-nat-rule-type          | varchar(32)      | YES  |     | NULL    |       |
| sd-elapsed-time               | varchar(20)      | YES  |     | NULL    |       |
| sd-encrypted                  | varchar(20)      | YES  |     | NULL    |       |
| sd-icmp-type                  | varchar(10)      | YES  |     | NULL    |       |
| sd-message                    | varchar(256)     | YES  |     | NULL    |       |
| sd-name                       | varchar(32)      | YES  |     | NULL    |       |
| sd-nat-connection-tag         | varchar(10)      | YES  |     | NULL    |       |
| sd-nat-destination-address    | varchar(20)      | YES  |     | NULL    |       |
| sd-nat-destination-port       | varchar(10)      | YES  |     | NULL    |       |
| sd-nat-source-address         | varchar(20)      | YES  |     | NULL    |       |
| sd-nat-source-port            | varchar(10)      | YES  |     | NULL    |       |
| sd-nested-application         | varchar(64)      | YES  |     | NULL    |       |
| sd-packet-incoming-interface  | varchar(10)      | YES  |     | NULL    |       |
| sd-packets-from-client        | varchar(20)      | YES  |     | NULL    |       |
| sd-packets-from-server        | varchar(20)      | YES  |     | NULL    |       |
| sd-policy-name                | varchar(64)      | YES  |     | NULL    |       |
| sd-profile-name               | varchar(64)      | YES  |     | NULL    |       |
| sd-protocol-id                | varchar(10)      | YES  |     | NULL    |       |
| sd-reason                     | varchar(64)      | YES  |     | NULL    |       |
| sd-roles                      | varchar(64)      | YES  |     | NULL    |       |
| sd-routing-instance           | varchar(64)      | YES  |     | NULL    |       |
| sd-rule-name                  | varchar(64)      | YES  |     | NULL    |       |
| sd-service-name               | varchar(64)      | YES  |     | NULL    |       |
| sd-session-id-32              | varchar(64)      | YES  |     | NULL    |       |
| sd-source-address             | varchar(20)      | YES  |     | NULL    |       |
| sd-source-port                | varchar(10)      | YES  |     | NULL    |       |
| sd-source-zone-name           | varchar(64)      | YES  |     | NULL    |       |
| sd-src-nat-rule-name          | varchar(26)      | YES  |     | NULL    |       |
| sd-src-nat-rule-type          | varchar(16)      | YES  |     | NULL    |       |
| sd-username                   | varchar(64)      | YES  |     | NULL    |       |
+-------------------------------+------------------+------+-----+---------+-------+
48 rows in set (0.00 sec)

---------------------------------------------------------------------------------------------------------------------------------

