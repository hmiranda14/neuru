-- ═══════════════════════════════════════════════════════════════════════
-- NEURU — full install schema + pre-loaded config (all disabled/sanitized)
-- Import into an EMPTY 'netmon' database. Idempotent (IF NOT EXISTS / IGNORE).
-- ═══════════════════════════════════════════════════════════════════════
SET FOREIGN_KEY_CHECKS=0;

-- ── 1) STRUCTURE — all tables (empty) ──

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `activity_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) DEFAULT NULL,
  `operation` varchar(50) DEFAULT NULL,
  `table_name` varchar(100) DEFAULT NULL,
  `record_id` int DEFAULT NULL,
  `description` text,
  `ip_address` varchar(45) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `container_fix_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `incident_id` bigint unsigned NOT NULL,
  `level` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'info',
  `line` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_incident` (`incident_id`,`id`)
) ENGINE=InnoDB AUTO_INCREMENT=676 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `container_incidents` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `endpoint_id` int NOT NULL DEFAULT '0',
  `host` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `host_ip` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `container_id` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `container_name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `severity` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ERROR',
  `error_text` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `ai_summary` mediumtext COLLATE utf8mb4_unicode_ci,
  `ai_solution` mediumtext COLLATE utf8mb4_unicode_ci,
  `fingerprint` char(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  `occurrences` int NOT NULL DEFAULT '1',
  `status` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'analyzing',
  `first_seen` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `ai_requested_at` datetime DEFAULT NULL,
  `remediation_status` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'none',
  `remediation_log` mediumtext COLLATE utf8mb4_unicode_ci,
  `remediated_at` datetime DEFAULT NULL,
  `fix_status` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'none',
  `fix_started_at` datetime DEFAULT NULL,
  `fix_finished_at` datetime DEFAULT NULL,
  `resolved_by` int DEFAULT NULL,
  `resolved_at` datetime DEFAULT NULL,
  `resolution_note` text COLLATE utf8mb4_unicode_ci,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_fingerprint` (`fingerprint`),
  KEY `idx_status` (`status`,`last_seen`),
  KEY `idx_container` (`container_id`),
  KEY `idx_severity` (`severity`)
) ENGINE=InnoDB AUTO_INCREMENT=5873 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `container_kb` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `incident_id` int unsigned DEFAULT NULL,
  `container_name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `image` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `severity` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `error_text` text COLLATE utf8mb4_unicode_ci,
  `fingerprint` char(40) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `summary` text COLLATE utf8mb4_unicode_ci,
  `resolution` text COLLATE utf8mb4_unicode_ci,
  `transcript` mediumtext COLLATE utf8mb4_unicode_ci,
  `tags` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `content_hash` char(40) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `reuse_count` int unsigned NOT NULL DEFAULT '0',
  `source` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'resolve',
  `created_by` int unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `vectorized_at` datetime DEFAULT NULL,
  `vector_ref` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `idx_kb_fingerprint` (`fingerprint`),
  KEY `idx_kb_incident` (`incident_id`),
  KEY `idx_kb_vectorized` (`vectorized_at`),
  KEY `idx_kb_container` (`container_name`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `container_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `endpoint_id` int NOT NULL DEFAULT '0',
  `container_id` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `container_name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `stream` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'stdout',
  `log_ts` datetime DEFAULT NULL,
  `message` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `line_hash` char(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_line` (`line_hash`),
  KEY `idx_container` (`container_id`,`id`),
  KEY `idx_name` (`container_name`,`id`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=19807598 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `container_net_samples` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `endpoint_id` int NOT NULL,
  `container_id` varchar(64) NOT NULL,
  `container_name` varchar(128) NOT NULL,
  `rx_bytes` bigint NOT NULL DEFAULT '0',
  `tx_bytes` bigint NOT NULL DEFAULT '0',
  `rx_rate` double NOT NULL DEFAULT '0',
  `tx_rate` double NOT NULL DEFAULT '0',
  `sampled_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_ct` (`endpoint_id`,`container_id`,`id`),
  KEY `idx_time` (`sampled_at`)
) ENGINE=InnoDB AUTO_INCREMENT=483204 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ai_baselines` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `metric_type` varchar(40) NOT NULL,
  `metric_key` varchar(80) NOT NULL DEFAULT '',
  `hour_of_week` tinyint unsigned NOT NULL,
  `mean` double NOT NULL DEFAULT '0',
  `stdev` double NOT NULL DEFAULT '0',
  `samples` int NOT NULL DEFAULT '0',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_bl` (`node_id`,`metric_type`,`metric_key`,`hour_of_week`),
  KEY `idx_node` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=162539 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ai_ignores` (
  `id` int NOT NULL AUTO_INCREMENT,
  `match_type` varchar(12) NOT NULL,
  `match_val` varchar(255) NOT NULL,
  `label` varchar(255) DEFAULT '',
  `active` tinyint DEFAULT '1',
  `created_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_match` (`match_type`,`match_val`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ai_insights` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int DEFAULT NULL,
  `kind` varchar(40) NOT NULL DEFAULT 'insight',
  `severity` varchar(20) NOT NULL DEFAULT 'info',
  `title` varchar(255) NOT NULL,
  `body` mediumtext,
  `data` json DEFAULT NULL,
  `source` varchar(40) NOT NULL DEFAULT 'n8n',
  `status` varchar(20) NOT NULL DEFAULT 'open',
  `correlation_key` varchar(120) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_node` (`node_id`),
  KEY `idx_status` (`status`),
  KEY `idx_created` (`created_at`),
  KEY `idx_sev` (`severity`)
) ENGINE=InnoDB AUTO_INCREMENT=668 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_aip_actions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `node_id` int NOT NULL,
  `tool` varchar(64) NOT NULL,
  `args` mediumtext,
  `risk` varchar(8) DEFAULT 'high',
  `reason` text,
  `status` varchar(16) DEFAULT 'proposed',
  `result` mediumtext,
  `proposed_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `decided_at` datetime DEFAULT NULL,
  `decided_by` int DEFAULT NULL,
  `executed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `session_id` (`session_id`),
  KEY `status` (`status`),
  KEY `node_id` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=241 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_aip_devices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `enabled` tinyint DEFAULT '1',
  `autonomy_mode` varchar(12) DEFAULT 'observe',
  `allow_destructive` tinyint DEFAULT '0',
  `added_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `allow_commands` tinyint DEFAULT '0',
  `telegram_approve` tinyint DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=42 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_aip_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `node_id` int NOT NULL,
  `phase` varchar(12) NOT NULL,
  `title` varchar(240) DEFAULT '',
  `body` mediumtext,
  `data` mediumtext,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `session_id` (`session_id`),
  KEY `node_id` (`node_id`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=7259 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_aip_sessions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `trigger_kind` varchar(16) DEFAULT 'manual',
  `status` varchar(20) DEFAULT 'active',
  `title` varchar(220) DEFAULT '',
  `summary` text,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `node_id` (`node_id`),
  KEY `status` (`status`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=2847 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_aip_tg_approvals` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `action_id` bigint NOT NULL,
  `chat_id` varchar(40) NOT NULL,
  `message_id` bigint DEFAULT NULL,
  `token` varchar(24) NOT NULL,
  `status` varchar(12) DEFAULT 'pending',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `decided_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_action` (`action_id`),
  KEY `status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_alert_state` (
  `id` int NOT NULL AUTO_INCREMENT,
  `entity_type` varchar(10) NOT NULL,
  `entity_id` int NOT NULL,
  `node_id` int NOT NULL,
  `last_status` varchar(20) NOT NULL DEFAULT 'up',
  `open_insight_id` bigint unsigned DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ent` (`entity_type`,`entity_id`)
) ENGINE=InnoDB AUTO_INCREMENT=858 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_archaeology_findings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pattern_key` varchar(64) NOT NULL,
  `title` varchar(255) NOT NULL,
  `confidence` int NOT NULL DEFAULT '0',
  `support` int NOT NULL DEFAULT '0',
  `avg_lag_min` double DEFAULT '0',
  `hypothesis` text,
  `evidence` text,
  `suggested_fix` text,
  `source` varchar(8) NOT NULL DEFAULT 'stat',
  `status` varchar(12) NOT NULL DEFAULT 'open',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_pat` (`pattern_key`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=171 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_audit_log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `username` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `action` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `target_type` varchar(60) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `target_id` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ok',
  `details` text COLLATE utf8mb4_unicode_ci,
  `method` varchar(10) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `uri` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ip` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_agent` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_ts` (`ts`),
  KEY `idx_user` (`username`),
  KEY `idx_action` (`action`),
  KEY `idx_target` (`target_type`,`target_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=91574 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_config_changes` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL,
  `snapshot_id` bigint NOT NULL,
  `prev_snapshot_id` bigint DEFAULT NULL,
  `detected_at` datetime NOT NULL,
  `added` int NOT NULL DEFAULT '0',
  `removed` int NOT NULL DEFAULT '0',
  `diff_text` mediumtext,
  `status` varchar(14) NOT NULL DEFAULT 'open',
  `acked_by` varchar(60) DEFAULT NULL,
  `acked_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_dev` (`device_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_config_devices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int DEFAULT NULL,
  `name` varchar(120) NOT NULL,
  `host_ip` varchar(64) NOT NULL,
  `vendor_key` varchar(40) NOT NULL,
  `command_override` varchar(255) DEFAULT NULL,
  `ssh_cred_id` int DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `last_backup_at` datetime DEFAULT NULL,
  `last_status` varchar(16) NOT NULL DEFAULT 'never',
  `last_error` varchar(400) DEFAULT NULL,
  `last_hash` char(64) DEFAULT NULL,
  `last_snapshot_id` bigint DEFAULT NULL,
  `versions` int NOT NULL DEFAULT '0',
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_enabled` (`enabled`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_config_snapshots` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL,
  `captured_at` datetime NOT NULL,
  `sha256` char(64) NOT NULL,
  `size_bytes` int NOT NULL DEFAULT '0',
  `line_count` int NOT NULL DEFAULT '0',
  `source` varchar(12) NOT NULL DEFAULT 'cron',
  `config_text` mediumtext,
  PRIMARY KEY (`id`),
  KEY `idx_dev_time` (`device_id`,`captured_at`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_config_vendors` (
  `vendor_key` varchar(40) NOT NULL,
  `label` varchar(80) NOT NULL,
  `command` varchar(255) NOT NULL,
  `ignore_regex` text,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`vendor_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ctr_templates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  `category` varchar(40) DEFAULT 'Custom',
  `image` varchar(200) NOT NULL,
  `description` varchar(255) DEFAULT '',
  `icon` varchar(60) DEFAULT 'fa-solid fa-cube',
  `ports_json` text,
  `env_json` text,
  `volumes_json` text,
  `restart` varchar(20) DEFAULT 'unless-stopped',
  `is_builtin` tinyint DEFAULT '0',
  `created_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=289 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_dash_layout` (
  `uid` int NOT NULL,
  `layout` longtext,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_db_advice` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `kind` varchar(16) NOT NULL DEFAULT 'index',
  `title` varchar(255) DEFAULT NULL,
  `rationale` text,
  `ddl` text,
  `risk` varchar(10) DEFAULT 'low',
  `benefit` varchar(160) DEFAULT NULL,
  `source` varchar(12) DEFAULT 'ai',
  `status` varchar(12) NOT NULL DEFAULT 'proposed',
  `result` text,
  `fingerprint` varchar(120) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `applied_at` datetime DEFAULT NULL,
  `applied_by` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_fp` (`target_id`,`fingerprint`),
  KEY `idx_t` (`target_id`,`status`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_db_repl` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `sampled_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `io_running` tinyint DEFAULT '0',
  `sql_running` tinyint DEFAULT '0',
  `seconds_behind` int DEFAULT NULL,
  `last_error` varchar(400) DEFAULT NULL,
  `source_host` varchar(190) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_t` (`target_id`,`sampled_at`)
) ENGINE=InnoDB AUTO_INCREMENT=1872 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_db_samples` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `sampled_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `connections` int DEFAULT NULL,
  `max_connections` int DEFAULT NULL,
  `threads_running` int DEFAULT NULL,
  `uptime_s` bigint DEFAULT NULL,
  `blocked` int DEFAULT '0',
  `slow` int DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_t` (`target_id`,`sampled_at`)
) ENGINE=InnoDB AUTO_INCREMENT=5116 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_db_schema_drift` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `detected_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `summary` varchar(255) DEFAULT NULL,
  `changes_json` longtext,
  PRIMARY KEY (`id`),
  KEY `idx_t` (`target_id`,`detected_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_db_schema_snap` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `captured_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `schema_hash` char(40) NOT NULL,
  `item_count` int DEFAULT '0',
  `items_json` longtext,
  PRIMARY KEY (`id`),
  KEY `idx_t` (`target_id`,`captured_at`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_db_targets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int DEFAULT NULL,
  `display_name` varchar(120) NOT NULL,
  `engine` varchar(20) NOT NULL DEFAULT 'mysql',
  `transport` varchar(10) NOT NULL DEFAULT 'direct',
  `host` varchar(190) NOT NULL DEFAULT '127.0.0.1',
  `port` int DEFAULT NULL,
  `db_name` varchar(190) DEFAULT NULL,
  `username` varchar(190) DEFAULT NULL,
  `password_enc` text,
  `ssl_mode` varchar(20) DEFAULT NULL,
  `enabled` tinyint NOT NULL DEFAULT '1',
  `last_status` varchar(20) DEFAULT NULL,
  `last_error` varchar(400) DEFAULT NULL,
  `last_version` varchar(120) DEFAULT NULL,
  `last_checked` datetime DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `role` varchar(12) NOT NULL DEFAULT 'standalone',
  `replica_of` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_node` (`node_id`),
  KEY `idx_enabled` (`enabled`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_decoy_diversions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `target_port` int DEFAULT '0',
  `protocol` varchar(6) DEFAULT 'tcp',
  `pot_id` int NOT NULL,
  `border_node_id` int NOT NULL,
  `nat_comment` varchar(64) DEFAULT '',
  `threat_id` int DEFAULT '0',
  `status` varchar(12) DEFAULT 'active',
  `source` varchar(16) DEFAULT 'manual',
  `detail` varchar(500) DEFAULT '',
  `started_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `expires_at` datetime DEFAULT NULL,
  `reverted_at` datetime DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `ai_verdict` varchar(16) DEFAULT '',
  `ai_score` int DEFAULT '0',
  `ai_summary` varchar(600) DEFAULT '',
  `ai_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `status` (`status`),
  KEY `src_ip` (`src_ip`),
  KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_decoy_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `diversion_id` bigint NOT NULL,
  `ts` datetime DEFAULT CURRENT_TIMESTAMP,
  `kind` varchar(16) DEFAULT 'hit',
  `src_ip` varchar(45) DEFAULT '',
  `data` mediumtext,
  PRIMARY KEY (`id`),
  KEY `diversion_id` (`diversion_id`),
  KEY `ts` (`ts`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_decoy_pots` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  `service_kind` varchar(16) DEFAULT 'generic',
  `image` varchar(160) NOT NULL,
  `container_port` int DEFAULT '2222',
  `listen_port` int DEFAULT '2222',
  `portainer_endpoint_id` int DEFAULT '0',
  `host_ip` varchar(45) DEFAULT '',
  `container_id` varchar(80) DEFAULT '',
  `container_name` varchar(120) DEFAULT '',
  `status` varchar(12) DEFAULT 'draft',
  `last_deploy` datetime DEFAULT NULL,
  `last_error` varchar(400) DEFAULT '',
  `created_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_device_stats` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `recorded_at` datetime NOT NULL,
  `metric_type` varchar(50) NOT NULL,
  `metric_key` varchar(200) DEFAULT '',
  `value` decimal(12,4) DEFAULT NULL,
  `raw_value` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_node_metric_time` (`node_id`,`metric_type`,`recorded_at`),
  KEY `idx_metric_time` (`metric_type`,`metric_key`,`recorded_at`,`node_id`),
  KEY `idx_node_recorded` (`node_id`,`recorded_at`),
  KEY `idx_node_type_key_time` (`node_id`,`metric_type`,`metric_key`,`recorded_at`)
) ENGINE=InnoDB AUTO_INCREMENT=1406659 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_discovery_candidates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `sys_name` varchar(200) DEFAULT NULL,
  `sys_descr` varchar(500) DEFAULT NULL,
  `snmp_community` varchar(100) DEFAULT NULL,
  `snmp_version` varchar(10) DEFAULT NULL,
  `os_guess` varchar(50) DEFAULT 'generic',
  `subnet` varchar(45) DEFAULT NULL,
  `discovered_at` datetime NOT NULL,
  `status` enum('pending','imported','rejected') DEFAULT 'pending',
  `node_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ip` (`ip_address`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=97 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_geoip_cache` (
  `ip` varchar(45) NOT NULL,
  `lat` double DEFAULT NULL,
  `lon` double DEFAULT NULL,
  `city` varchar(80) DEFAULT NULL,
  `country` varchar(80) DEFAULT NULL,
  `asn` varchar(140) DEFAULT NULL,
  `fetched_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_gpu` (
  `id` int NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `gpu_index` int NOT NULL,
  `uuid` varchar(80) DEFAULT NULL,
  `name` varchar(160) DEFAULT NULL,
  `vendor` varchar(16) DEFAULT NULL,
  `memory_total_mb` int DEFAULT NULL,
  `driver_version` varchar(40) DEFAULT NULL,
  `first_seen` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_gpu` (`target_id`,`gpu_index`)
) ENGINE=InnoDB AUTO_INCREMENT=8929 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_gpu_models` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `target_id` int NOT NULL,
  `name` varchar(160) DEFAULT NULL,
  `size_mb` int DEFAULT NULL,
  `vram_mb` int DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  `sampled_at` datetime NOT NULL,
  `running` tinyint DEFAULT '0',
  `family` varchar(80) DEFAULT NULL,
  `params` varchar(40) DEFAULT NULL,
  `quant` varchar(40) DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `k_t` (`target_id`)
) ENGINE=InnoDB AUTO_INCREMENT=69383 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_gpu_proc` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `gpu_id` int NOT NULL,
  `pid` int DEFAULT NULL,
  `used_mb` int DEFAULT NULL,
  `name` varchar(200) DEFAULT NULL,
  `sampled_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `k_gpu` (`gpu_id`)
) ENGINE=InnoDB AUTO_INCREMENT=197238 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_gpu_stats` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `gpu_id` int NOT NULL,
  `util_pct` float DEFAULT NULL,
  `mem_util_pct` float DEFAULT NULL,
  `mem_used_mb` int DEFAULT NULL,
  `mem_total_mb` int DEFAULT NULL,
  `temp_c` float DEFAULT NULL,
  `power_w` float DEFAULT NULL,
  `power_limit_w` float DEFAULT NULL,
  `fan_pct` float DEFAULT NULL,
  `clock_sm_mhz` int DEFAULT NULL,
  `sampled_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `k_gpu_time` (`gpu_id`,`sampled_at`)
) ENGINE=InnoDB AUTO_INCREMENT=8929 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_gpu_targets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `node_id` int DEFAULT NULL,
  `host_ip` varchar(64) DEFAULT NULL,
  `ollama_url` varchar(200) DEFAULT NULL,
  `vendor` varchar(16) DEFAULT NULL,
  `temp_warn` int DEFAULT '85',
  `vram_warn` int DEFAULT '90',
  `enabled` tinyint DEFAULT '1',
  `status` varchar(16) DEFAULT 'new',
  `last_poll` datetime DEFAULT NULL,
  `last_error` varchar(300) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ollama_version` varchar(40) DEFAULT NULL,
  `ollama_ok` tinyint DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_groups` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `color` varchar(20) DEFAULT '#4da3ff',
  `sort_order` int DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_heal_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `pb_key` varchar(24) NOT NULL,
  `indicator` varchar(120) NOT NULL,
  `kind` varchar(8) NOT NULL DEFAULT 'ip',
  `trigger_detail` varchar(400) DEFAULT NULL,
  `action` varchar(24) NOT NULL DEFAULT 'none',
  `status` varchar(10) NOT NULL DEFAULT 'proposed',
  `report` varchar(600) DEFAULT NULL,
  `revert_at` datetime DEFAULT NULL,
  `detected_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `acted_at` datetime DEFAULT NULL,
  `reverted_at` datetime DEFAULT NULL,
  `reported_by` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`),
  KEY `idx_ind` (`indicator`)
) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_heal_playbooks` (
  `pb_key` varchar(24) NOT NULL,
  `name` varchar(80) NOT NULL,
  `detector` varchar(24) NOT NULL,
  `action` varchar(24) NOT NULL,
  `mode` varchar(10) NOT NULL DEFAULT 'off',
  `auto_revert_min` int NOT NULL DEFAULT '15',
  `threshold` int NOT NULL DEFAULT '0',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`pb_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_health_counters` (
  `node_id` int NOT NULL,
  `if_index` int NOT NULL,
  `metric` varchar(24) NOT NULL,
  `counter` bigint NOT NULL,
  `polled_at` datetime NOT NULL,
  PRIMARY KEY (`node_id`,`if_index`,`metric`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_health_optical_oids` (
  `id` int NOT NULL AUTO_INCREMENT,
  `vendor_key` varchar(40) NOT NULL DEFAULT 'generic',
  `node_id` int DEFAULT NULL,
  `label` varchar(80) NOT NULL DEFAULT '',
  `metric` varchar(24) NOT NULL,
  `oid` varchar(160) NOT NULL,
  `scale` double NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_vendor` (`vendor_key`),
  KEY `idx_node` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_health_predictions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `entity` varchar(120) NOT NULL,
  `metric` varchar(24) NOT NULL,
  `kind` varchar(12) NOT NULL DEFAULT 'eth',
  `severity` varchar(8) NOT NULL DEFAULT 'ok',
  `direction` varchar(4) NOT NULL DEFAULT 'rise',
  `current_val` double DEFAULT NULL,
  `threshold` double DEFAULT NULL,
  `slope_per_day` double DEFAULT NULL,
  `eta_days` double DEFAULT NULL,
  `samples` int DEFAULT '0',
  `detail` varchar(400) DEFAULT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'open',
  `first_seen` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_series` (`node_id`,`entity`,`metric`),
  KEY `idx_status` (`status`,`severity`)
) ENGINE=InnoDB AUTO_INCREMENT=17595 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_health_samples` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `kind` varchar(12) NOT NULL DEFAULT 'eth',
  `entity` varchar(120) NOT NULL,
  `metric` varchar(24) NOT NULL,
  `value` double DEFAULT NULL,
  `recorded_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_series` (`node_id`,`entity`,`metric`,`recorded_at`),
  KEY `idx_time` (`recorded_at`)
) ENGINE=InnoDB AUTO_INCREMENT=200165 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_if_counters` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `if_index` int NOT NULL,
  `in_octets` bigint unsigned DEFAULT '0',
  `out_octets` bigint unsigned DEFAULT '0',
  `polled_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_node_if` (`node_id`,`if_index`),
  KEY `idx_node` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=195642 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_incident_signals` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `incident_id` bigint NOT NULL,
  `fingerprint` varchar(160) NOT NULL,
  `source` varchar(20) NOT NULL,
  `severity` varchar(10) NOT NULL,
  `entity` varchar(160) DEFAULT NULL,
  `node_id` int DEFAULT NULL,
  `title` varchar(400) DEFAULT NULL,
  `detail` text,
  `link` varchar(200) DEFAULT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'active',
  `first_seen` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `cleared_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `fingerprint` (`fingerprint`),
  KEY `idx_inc` (`incident_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=649666 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_incidents` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `corr_key` varchar(120) NOT NULL,
  `title` varchar(255) NOT NULL,
  `severity` varchar(10) NOT NULL DEFAULT 'warning',
  `status` varchar(14) NOT NULL DEFAULT 'open',
  `root_source` varchar(20) DEFAULT NULL,
  `root_entity` varchar(160) DEFAULT NULL,
  `root_node_id` int DEFAULT NULL,
  `signal_count` int NOT NULL DEFAULT '0',
  `impact_count` int NOT NULL DEFAULT '0',
  `impact` text,
  `opened_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `acked_by` varchar(60) DEFAULT NULL,
  `acked_at` datetime DEFAULT NULL,
  `resolved_at` datetime DEFAULT NULL,
  `muted_by` varchar(60) DEFAULT NULL,
  `muted_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `corr_key` (`corr_key`),
  KEY `idx_status` (`status`),
  KEY `idx_sev` (`severity`)
) ENGINE=InnoDB AUTO_INCREMENT=84 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_interfaces` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `lnms_port_id` int DEFAULT NULL,
  `if_name` varchar(100) DEFAULT NULL,
  `if_alias` varchar(200) DEFAULT NULL,
  `display_name` varchar(100) DEFAULT NULL,
  `show_graph` tinyint(1) DEFAULT '1',
  `sort_order` int DEFAULT '0',
  `if_index` int DEFAULT NULL,
  `if_ip_address` varchar(45) DEFAULT NULL,
  `is_dummy` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_np` (`node_id`,`lnms_port_id`)
) ENGINE=InnoDB AUTO_INCREMENT=202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ipam_allocations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `subnet_id` int NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `ip_bin` varbinary(16) NOT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'reserved',
  `source` varchar(12) NOT NULL DEFAULT 'manual',
  `node_id` int DEFAULT NULL,
  `wg_peer_id` int DEFAULT NULL,
  `hostname` varchar(120) DEFAULT NULL,
  `description` varchar(200) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `released_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_subnet_ip` (`subnet_id`,`ip_address`),
  KEY `idx_status` (`status`),
  KEY `idx_ipbin` (`ip_bin`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ipam_subnets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `cidr` varchar(43) NOT NULL,
  `network_addr` varbinary(16) NOT NULL,
  `prefix_len` tinyint unsigned NOT NULL,
  `family` tinyint unsigned NOT NULL DEFAULT '4',
  `description` varchar(200) DEFAULT NULL,
  `vlan_id` int DEFAULT NULL,
  `gateway_ip` varchar(45) DEFAULT NULL,
  `gateway_node_id` int DEFAULT NULL,
  `group_id` int DEFAULT NULL,
  `kind` varchar(12) NOT NULL DEFAULT 'lan',
  `is_managed` tinyint(1) NOT NULL DEFAULT '1',
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_cidr` (`cidr`),
  KEY `idx_group` (`group_id`),
  KEY `idx_net` (`network_addr`,`prefix_len`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_latency_alerts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `severity` varchar(8) NOT NULL,
  `metric` varchar(8) NOT NULL,
  `value` double DEFAULT NULL,
  `threshold` double DEFAULT NULL,
  `state` varchar(8) NOT NULL DEFAULT 'open',
  `opened_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `cleared_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_node_state` (`node_id`,`state`),
  KEY `idx_state_time` (`state`,`opened_at`)
) ENGINE=InnoDB AUTO_INCREMENT=400 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_latency_samples` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `target_key` varchar(64) NOT NULL,
  `rtt_ms` double DEFAULT NULL,
  `loss` double DEFAULT NULL,
  `sampled_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_node_ts` (`node_id`,`sampled_at`),
  KEY `idx_time` (`sampled_at`)
) ENGINE=InnoDB AUTO_INCREMENT=922785 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_latency_thresholds` (
  `node_id` int NOT NULL,
  `rtt_warn` double DEFAULT NULL,
  `rtt_crit` double DEFAULT NULL,
  `loss_warn` double DEFAULT NULL,
  `loss_crit` double DEFAULT NULL,
  PRIMARY KEY (`node_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_link_hidden` (
  `id` int NOT NULL AUTO_INCREMENT,
  `a_node_id` int NOT NULL,
  `z_node_id` int NOT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_pair` (`a_node_id`,`z_node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_links` (
  `id` int NOT NULL AUTO_INCREMENT,
  `a_node_id` int NOT NULL,
  `a_iface_id` int DEFAULT NULL,
  `z_node_id` int NOT NULL,
  `z_iface_id` int DEFAULT NULL,
  `traffic_side` enum('a','z') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'z',
  `label` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_a` (`a_node_id`),
  KEY `idx_z` (`z_node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_lx_actions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `host_id` int NOT NULL,
  `service_name` varchar(160) DEFAULT NULL,
  `action` varchar(30) DEFAULT NULL,
  `ok` tinyint(1) DEFAULT NULL,
  `detail` varchar(400) DEFAULT NULL,
  `uid` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_lx_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `host_id` int NOT NULL,
  `record_id` bigint NOT NULL,
  `log_name` varchar(60) DEFAULT NULL,
  `event_id` int DEFAULT NULL,
  `level` tinyint DEFAULT NULL,
  `provider` varchar(160) DEFAULT NULL,
  `message` text,
  `created_at` datetime DEFAULT NULL,
  `ingested_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ev` (`host_id`,`record_id`),
  KEY `idx_h` (`host_id`,`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=241329 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_lx_health` (
  `host_id` int NOT NULL,
  `data` mediumtext,
  `sampled_at` datetime DEFAULT NULL,
  PRIMARY KEY (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_lx_hosts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `node_id` int DEFAULT NULL,
  `host_ip` varchar(64) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT '1',
  `status` varchar(16) DEFAULT 'new',
  `last_error` varchar(255) DEFAULT NULL,
  `os_caption` varchar(160) DEFAULT NULL,
  `last_event_poll` datetime DEFAULT NULL,
  `last_health_poll` datetime DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `source` varchar(8) NOT NULL DEFAULT 'ssh',
  `alloy_url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_lx_layout` (
  `uid` int NOT NULL,
  `layout` text,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_lx_watch` (
  `id` int NOT NULL AUTO_INCREMENT,
  `host_id` int NOT NULL,
  `service_name` varchar(160) NOT NULL,
  `display_name` varchar(200) DEFAULT NULL,
  `auto_restart` tinyint(1) DEFAULT '0',
  `last_state` varchar(20) DEFAULT NULL,
  `last_checked` datetime DEFAULT NULL,
  `restart_count` int DEFAULT '0',
  `last_action_at` datetime DEFAULT NULL,
  `last_restart_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_w` (`host_id`,`service_name`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_maintenance_windows` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `starts_at` datetime NOT NULL,
  `ends_at` datetime NOT NULL,
  `scope` varchar(20) NOT NULL DEFAULT 'all',
  `scope_val` varchar(120) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_n8n_webhooks` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `slug` varchar(80) NOT NULL,
  `url` varchar(500) NOT NULL,
  `method` enum('POST','GET') NOT NULL DEFAULT 'POST',
  `description` varchar(300) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_slug` (`slug`)
) ENGINE=InnoDB AUTO_INCREMENT=57989 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_netalert_alerts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `container_id` varchar(64) NOT NULL,
  `container_name` varchar(128) NOT NULL,
  `severity` varchar(8) NOT NULL,
  `metric` varchar(8) NOT NULL,
  `value` double DEFAULT NULL,
  `threshold` double DEFAULT NULL,
  `state` varchar(8) NOT NULL DEFAULT 'open',
  `opened_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `cleared_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_cont_state` (`container_id`,`state`),
  KEY `idx_state_time` (`state`,`opened_at`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_netalert_thresholds` (
  `scope_key` varchar(64) NOT NULL,
  `rx_warn` double DEFAULT NULL,
  `rx_crit` double DEFAULT NULL,
  `tx_warn` double DEFAULT NULL,
  `tx_crit` double DEFAULT NULL,
  PRIMARY KEY (`scope_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_netflow_alerts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scope` varchar(60) NOT NULL,
  `kind` varchar(16) NOT NULL DEFAULT 'app',
  `severity` varchar(10) NOT NULL,
  `value_mbps` double NOT NULL,
  `threshold_mbps` double NOT NULL,
  `baseline_mbps` double DEFAULT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'open',
  `opened_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  `cleared_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`),
  KEY `idx_scope` (`scope`)
) ENGINE=InnoDB AUTO_INCREMENT=131 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_netflow_flows` (
  `bucket` datetime NOT NULL,
  `exporter` varchar(45) NOT NULL,
  `src_ip` varchar(45) NOT NULL,
  `dst_ip` varchar(45) NOT NULL,
  `src_port` int unsigned NOT NULL DEFAULT '0',
  `dst_port` int unsigned NOT NULL DEFAULT '0',
  `protocol` tinyint unsigned NOT NULL DEFAULT '0',
  `app_port` int unsigned NOT NULL DEFAULT '0',
  `bytes` bigint unsigned NOT NULL DEFAULT '0',
  `packets` bigint unsigned NOT NULL DEFAULT '0',
  `flows` int unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`bucket`,`exporter`,`src_ip`,`dst_ip`,`src_port`,`dst_port`,`protocol`),
  KEY `idx_bucket` (`bucket`),
  KEY `idx_app` (`bucket`,`app_port`,`protocol`),
  KEY `idx_src` (`bucket`,`src_ip`),
  KEY `idx_dst` (`bucket`,`dst_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_netflow_thresholds` (
  `scope_key` varchar(60) NOT NULL,
  `warn_mbps` double DEFAULT NULL,
  `crit_mbps` double DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`scope_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_node_geo` (
  `node_id` int NOT NULL,
  `lat` double NOT NULL,
  `lon` double NOT NULL,
  `link_type` varchar(16) DEFAULT 'fiber',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `city` varchar(80) DEFAULT NULL,
  `country` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`node_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_nodes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `group_id` int DEFAULT NULL,
  `lnms_device_id` int DEFAULT NULL,
  `display_name` varchar(100) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `hostname` varchar(200) DEFAULT NULL,
  `location` varchar(200) DEFAULT NULL,
  `os_icon` varchar(50) DEFAULT 'generic',
  `hw_model` varchar(200) DEFAULT NULL,
  `sort_order` int DEFAULT '0',
  `added_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `snmp_community` varchar(100) DEFAULT NULL,
  `snmp_version` varchar(10) DEFAULT NULL,
  `monitor_type` varchar(10) NOT NULL DEFAULT 'snmp',
  `graylog_source` varchar(255) DEFAULT NULL,
  `ssh_cred_id` int DEFAULT NULL,
  `oid_template_id` int DEFAULT NULL,
  `subnet_mask` varchar(18) NOT NULL DEFAULT '/24',
  `gateway_node_id` int DEFAULT NULL,
  `gateway_iface_id` int DEFAULT NULL,
  `poll_interval_health` int DEFAULT NULL,
  `poll_interval_ifaces` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_dev` (`lnms_device_id`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_notify_channels` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  `type` varchar(16) NOT NULL DEFAULT 'n8n',
  `target` varchar(500) NOT NULL,
  `secret_enc` mediumtext,
  `min_severity` varchar(10) NOT NULL DEFAULT 'warning',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_notify_log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `incident_id` bigint NOT NULL,
  `channel_id` int DEFAULT NULL,
  `channel_name` varchar(80) DEFAULT NULL,
  `step_order` int NOT NULL DEFAULT '0',
  `event` varchar(20) NOT NULL DEFAULT 'open',
  `severity` varchar(10) DEFAULT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'sent',
  `detail` varchar(400) DEFAULT NULL,
  `sent_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_inc` (`incident_id`),
  KEY `idx_time` (`sent_at`)
) ENGINE=InnoDB AUTO_INCREMENT=46 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_notify_steps` (
  `id` int NOT NULL AUTO_INCREMENT,
  `step_order` int NOT NULL DEFAULT '0',
  `after_minutes` int NOT NULL DEFAULT '0',
  `channel_id` int NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_order` (`step_order`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_oid_configs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `template_id` int DEFAULT NULL,
  `node_id` int DEFAULT NULL,
  `metric_name` varchar(100) NOT NULL,
  `metric_type` varchar(50) DEFAULT 'custom',
  `oid` varchar(200) NOT NULL,
  `oid_total` varchar(200) DEFAULT NULL,
  `unit` varchar(20) DEFAULT '%',
  `walk` tinyint(1) DEFAULT '0',
  `scale` decimal(12,6) DEFAULT '1.000000',
  `description` varchar(300) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT '1',
  `sort_order` int DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_template` (`template_id`),
  KEY `idx_node` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_oid_templates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `os_type` varchar(50) DEFAULT 'generic',
  `description` varchar(500) DEFAULT NULL,
  `is_builtin` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=34616 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_pihole_servers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL DEFAULT 'Pi-hole',
  `url` varchar(255) NOT NULL,
  `password_enc` mediumtext,
  `verify_tls` tinyint(1) NOT NULL DEFAULT '0',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `sort_order` int NOT NULL DEFAULT '0',
  `sid` varchar(80) DEFAULT NULL,
  `sid_exp` int NOT NULL DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ping_stats` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `recorded_at` datetime NOT NULL,
  `is_up` tinyint(1) NOT NULL DEFAULT '0',
  `latency_ms` decimal(8,2) DEFAULT NULL,
  `packet_loss` decimal(5,2) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_node_time` (`node_id`,`recorded_at`)
) ENGINE=InnoDB AUTO_INCREMENT=101629 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_poller_config` (
  `id` int NOT NULL AUTO_INCREMENT,
  `cfg_key` varchar(100) NOT NULL,
  `cfg_value` varchar(500) NOT NULL DEFAULT '',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_cfg` (`cfg_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_poller_log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `ran_at` datetime NOT NULL,
  `duration_ms` int DEFAULT '0',
  `nodes_polled` int DEFAULT '0',
  `ports_polled` int DEFAULT '0',
  `errors` int DEFAULT '0',
  `status` varchar(20) DEFAULT 'ok',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7930 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_port_stats` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `port_id` int NOT NULL,
  `recorded_at` datetime NOT NULL,
  `in_rate` bigint DEFAULT '0',
  `out_rate` bigint DEFAULT '0',
  `in_util` decimal(6,2) DEFAULT NULL,
  `out_util` decimal(6,2) DEFAULT NULL,
  `oper_status` varchar(20) DEFAULT NULL,
  `if_speed` bigint DEFAULT '0',
  `raw_in_bytes` bigint unsigned DEFAULT NULL,
  `raw_out_bytes` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_port_time` (`port_id`,`recorded_at`),
  KEY `idx_node_time` (`node_id`,`recorded_at`)
) ENGINE=InnoDB AUTO_INCREMENT=195675 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_rc_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` int NOT NULL,
  `level` varchar(16) NOT NULL DEFAULT 'info',
  `line` mediumtext NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_sess` (`session_id`,`id`)
) ENGINE=InnoDB AUTO_INCREMENT=743 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_rc_sessions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `target_kind` varchar(12) NOT NULL DEFAULT 'manual',
  `target_ref` int DEFAULT NULL,
  `name` varchar(120) NOT NULL DEFAULT '',
  `host` varchar(64) NOT NULL DEFAULT '',
  `vendor_key` varchar(40) NOT NULL DEFAULT 'generic',
  `transport` varchar(8) NOT NULL DEFAULT 'cli',
  `ssh_cred_id` int DEFAULT NULL,
  `title` varchar(255) NOT NULL DEFAULT '',
  `problem` text,
  `status` varchar(16) NOT NULL DEFAULT 'open',
  `kb_id` int DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_service_deps` (
  `id` int NOT NULL AUTO_INCREMENT,
  `service_id` int NOT NULL,
  `node_id` int NOT NULL,
  `weight` int NOT NULL DEFAULT '1',
  `is_critical` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_sd` (`service_id`,`node_id`),
  KEY `idx_svc` (`service_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_services` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `criticality` varchar(8) NOT NULL DEFAULT 'high',
  `description` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `setting_key` varchar(100) NOT NULL,
  `setting_val` text,
  `label` varchar(200) DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_key` (`setting_key`)
) ENGINE=InnoDB AUTO_INCREMENT=80245 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_shadowit_findings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(45) NOT NULL,
  `dst_ip` varchar(45) NOT NULL,
  `protocol` tinyint unsigned NOT NULL DEFAULT '0',
  `app_port` int unsigned NOT NULL DEFAULT '0',
  `classification` varchar(16) NOT NULL,
  `confidence` int NOT NULL DEFAULT '0',
  `evidence` varchar(400) DEFAULT NULL,
  `mbps` double DEFAULT '0',
  `status` varchar(12) NOT NULL DEFAULT 'new',
  `first_seen` datetime DEFAULT CURRENT_TIMESTAMP,
  `last_seen` datetime DEFAULT CURRENT_TIMESTAMP,
  `hits` int DEFAULT '1',
  `exporter` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_f` (`src_ip`,`dst_ip`,`protocol`,`app_port`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ssh_credentials` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  `username` varchar(80) NOT NULL,
  `auth_type` enum('password','key') NOT NULL DEFAULT 'password',
  `secret_enc` mediumtext,
  `port` int NOT NULL DEFAULT '22',
  `is_default` tinyint(1) NOT NULL DEFAULT '0',
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_default` (`is_default`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_ssh_host_creds` (
  `host` varchar(64) NOT NULL,
  `cred_id` int NOT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`host`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_syslog` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `received_at` datetime NOT NULL,
  `host_ip` varchar(45) NOT NULL,
  `hostname` varchar(128) NOT NULL DEFAULT '',
  `facility` tinyint DEFAULT NULL,
  `severity` tinyint DEFAULT NULL,
  `tag` varchar(64) NOT NULL DEFAULT '',
  `message` text,
  PRIMARY KEY (`id`),
  KEY `idx_time` (`received_at`),
  KEY `idx_host_time` (`host_ip`,`received_at`),
  KEY `idx_sev_time` (`severity`,`received_at`)
) ENGINE=InnoDB AUTO_INCREMENT=9070847 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_threat_actions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `threat_id` int NOT NULL,
  `target_type` varchar(10) NOT NULL,
  `target_id` int DEFAULT NULL,
  `target_name` varchar(120) DEFAULT NULL,
  `status` varchar(10) NOT NULL,
  `detail` varchar(300) DEFAULT NULL,
  `acted_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_threat` (`threat_id`)
) ENGINE=InnoDB AUTO_INCREMENT=257 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_threats` (
  `id` int NOT NULL AUTO_INCREMENT,
  `indicator` varchar(255) NOT NULL,
  `ind_type` varchar(8) NOT NULL DEFAULT 'domain',
  `severity` varchar(8) NOT NULL DEFAULT 'high',
  `source` varchar(40) NOT NULL DEFAULT 'manual',
  `detail` varchar(400) DEFAULT NULL,
  `hits` int NOT NULL DEFAULT '1',
  `status` varchar(10) NOT NULL DEFAULT 'pending',
  `distributed_ok` int NOT NULL DEFAULT '0',
  `distributed_fail` int NOT NULL DEFAULT '0',
  `first_seen` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `vaccinated_at` datetime DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `reported_by` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_ind` (`indicator`,`ind_type`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=141 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_tplink_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `switch_id` int NOT NULL,
  `port` int NOT NULL,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `kind` varchar(16) NOT NULL,
  `severity` varchar(8) NOT NULL DEFAULT 'warn',
  `detail` varchar(255) NOT NULL DEFAULT '',
  `acked` tinyint NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_sw` (`switch_id`,`ts`),
  KEY `idx_ack` (`switch_id`,`acked`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_tplink_samples` (
  `switch_id` int NOT NULL,
  `port` int NOT NULL,
  `ts` datetime NOT NULL,
  `enabled` tinyint NOT NULL DEFAULT '1',
  `link_code` tinyint NOT NULL DEFAULT '0',
  `speed_mbps` int NOT NULL DEFAULT '0',
  `tx_good` bigint unsigned NOT NULL DEFAULT '0',
  `tx_bad` bigint unsigned NOT NULL DEFAULT '0',
  `rx_good` bigint unsigned NOT NULL DEFAULT '0',
  `rx_bad` bigint unsigned NOT NULL DEFAULT '0',
  `tx_pps` double NOT NULL DEFAULT '0',
  `rx_pps` double NOT NULL DEFAULT '0',
  `tx_err_pps` double NOT NULL DEFAULT '0',
  `rx_err_pps` double NOT NULL DEFAULT '0',
  PRIMARY KEY (`switch_id`,`port`,`ts`),
  KEY `idx_sw_ts` (`switch_id`,`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_tplink_switches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  `host` varchar(64) NOT NULL,
  `port` int NOT NULL DEFAULT '80',
  `username` varchar(32) NOT NULL DEFAULT 'admin',
  `pass_enc` text,
  `model` varchar(40) NOT NULL DEFAULT '',
  `enabled` tinyint NOT NULL DEFAULT '1',
  `err_threshold_pps` double NOT NULL DEFAULT '1',
  `last_poll` datetime DEFAULT NULL,
  `last_status` varchar(12) NOT NULL DEFAULT '',
  `last_error` varchar(255) NOT NULL DEFAULT '',
  `created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_host` (`host`,`port`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_user_perms` (
  `uid` int NOT NULL,
  `button_key` varchar(50) NOT NULL,
  `effect` enum('allow','deny') NOT NULL,
  `updated_by` varchar(50) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`uid`,`button_key`),
  KEY `idx_uid` (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_wear_history` (
  `node_id` int NOT NULL,
  `recorded_at` date NOT NULL,
  `stress` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`node_id`,`recorded_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_weather_alerts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ext_id` varchar(120) DEFAULT NULL,
  `node_id` int DEFAULT NULL,
  `event` varchar(120) NOT NULL,
  `severity` varchar(12) NOT NULL DEFAULT 'moderate',
  `headline` varchar(400) DEFAULT NULL,
  `lat` double DEFAULT NULL,
  `lon` double DEFAULT NULL,
  `radius_km` double DEFAULT NULL,
  `effective` datetime DEFAULT NULL,
  `expires` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_alert` (`ext_id`,`node_id`),
  KEY `idx_exp` (`expires`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_wg_apply_log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `server_id` int NOT NULL,
  `peer_id` int DEFAULT NULL,
  `action` varchar(20) NOT NULL,
  `target_type` varchar(12) NOT NULL,
  `ok` tinyint(1) NOT NULL DEFAULT '0',
  `detail` text,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_server` (`server_id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_wg_peer_traffic` (
  `peer_id` int NOT NULL,
  `ts` datetime NOT NULL,
  `rx_bytes` bigint unsigned NOT NULL DEFAULT '0',
  `tx_bytes` bigint unsigned NOT NULL DEFAULT '0',
  `rx_rate` double NOT NULL DEFAULT '0',
  `tx_rate` double NOT NULL DEFAULT '0',
  PRIMARY KEY (`peer_id`,`ts`),
  KEY `idx_peer` (`peer_id`,`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_wg_peers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `server_id` int NOT NULL,
  `name` varchar(80) NOT NULL,
  `public_key` varchar(60) DEFAULT NULL,
  `privkey_enc` text,
  `preshared_enc` text,
  `address_ip` varchar(45) NOT NULL,
  `allocation_id` int DEFAULT NULL,
  `allowed_ips` varchar(200) NOT NULL DEFAULT '',
  `keepalive` int DEFAULT '25',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `status` varchar(12) NOT NULL DEFAULT 'draft',
  `last_handshake` datetime DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `origin` varchar(10) NOT NULL DEFAULT 'managed',
  `rx_bytes` bigint unsigned NOT NULL DEFAULT '0',
  `tx_bytes` bigint unsigned NOT NULL DEFAULT '0',
  `endpoint` varchar(60) DEFAULT NULL,
  `connected` tinyint(1) NOT NULL DEFAULT '0',
  `stats_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_srv_addr` (`server_id`,`address_ip`),
  KEY `idx_server` (`server_id`)
) ENGINE=InnoDB AUTO_INCREMENT=105 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_wg_servers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  `target_type` varchar(12) NOT NULL,
  `node_id` int DEFAULT NULL,
  `host_ip` varchar(45) DEFAULT NULL,
  `portainer_endpoint_id` int DEFAULT NULL,
  `container_name` varchar(80) DEFAULT NULL,
  `iface_name` varchar(32) NOT NULL DEFAULT 'wg0',
  `listen_port` int NOT NULL DEFAULT '51820',
  `vpn_subnet_id` int DEFAULT NULL,
  `address_cidr` varchar(43) NOT NULL,
  `endpoint_host` varchar(120) DEFAULT NULL,
  `public_key` varchar(60) DEFAULT NULL,
  `privkey_enc` text,
  `dns_servers` varchar(120) DEFAULT NULL,
  `default_allowed` varchar(200) DEFAULT '0.0.0.0/0',
  `status` varchar(12) NOT NULL DEFAULT 'draft',
  `last_apply` datetime DEFAULT NULL,
  `last_error` varchar(300) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `adopted` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_node` (`node_id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_widgets` (
  `row_id` int NOT NULL AUTO_INCREMENT,
  `widget_id` varchar(80) NOT NULL,
  `owner_uid` int NOT NULL,
  `scope` varchar(10) NOT NULL DEFAULT 'user',
  `name` varchar(120) NOT NULL,
  `manifest` longtext NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`row_id`),
  UNIQUE KEY `uq_owner_widget` (`owner_uid`,`widget_id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_win_actions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `host_id` int NOT NULL,
  `service_name` varchar(120) DEFAULT NULL,
  `action` varchar(20) DEFAULT NULL,
  `ok` tinyint DEFAULT '0',
  `detail` varchar(400) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `k_host` (`host_id`,`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_win_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `host_id` int NOT NULL,
  `record_id` bigint DEFAULT NULL,
  `log_name` varchar(60) DEFAULT NULL,
  `event_id` int DEFAULT NULL,
  `level` tinyint DEFAULT NULL,
  `provider` varchar(160) DEFAULT NULL,
  `message` text,
  `created_at` datetime DEFAULT NULL,
  `ingested_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_evt` (`host_id`,`log_name`,`record_id`),
  KEY `k_host_time` (`host_id`,`created_at`),
  KEY `k_level` (`level`)
) ENGINE=InnoDB AUTO_INCREMENT=923 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_win_health` (
  `host_id` int NOT NULL,
  `data` longtext,
  `sampled_at` datetime DEFAULT NULL,
  PRIMARY KEY (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_win_hosts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `node_id` int DEFAULT NULL,
  `host_ip` varchar(64) DEFAULT NULL,
  `os_caption` varchar(160) DEFAULT NULL,
  `enabled` tinyint DEFAULT '1',
  `status` varchar(16) DEFAULT 'new',
  `last_event_poll` datetime DEFAULT NULL,
  `last_health_poll` datetime DEFAULT NULL,
  `last_error` varchar(300) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_win_layout` (
  `uid` int NOT NULL,
  `layout` text,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `nm_win_watch` (
  `id` int NOT NULL AUTO_INCREMENT,
  `host_id` int NOT NULL,
  `service_name` varchar(120) NOT NULL,
  `display_name` varchar(200) DEFAULT NULL,
  `auto_restart` tinyint DEFAULT '0',
  `enabled` tinyint DEFAULT '1',
  `last_state` varchar(20) DEFAULT NULL,
  `last_checked` datetime DEFAULT NULL,
  `last_action_at` datetime DEFAULT NULL,
  `restart_count` int DEFAULT '0',
  `created_by` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_watch` (`host_id`,`service_name`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `role_profiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `role_name` varchar(50) NOT NULL,
  `button_key` varchar(50) NOT NULL,
  `enabled` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_role_btn` (`role_name`,`button_key`)
) ENGINE=InnoDB AUTO_INCREMENT=62879 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `user_action_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `action_type` varchar(255) NOT NULL,
  `action_details` text,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user` (`username`),
  KEY `idx_action` (`action_type`),
  KEY `idx_ts` (`timestamp`)
) ENGINE=InnoDB AUTO_INCREMENT=5087 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `users` (
  `UID` int NOT NULL AUTO_INCREMENT,
  `USERNAME` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `PASSWORD` varchar(255) DEFAULT NULL,
  `email` varchar(50) NOT NULL DEFAULT '',
  `role` varchar(20) DEFAULT 'user',
  `opt_popmsg` tinyint(1) NOT NULL DEFAULT '1',
  `user_bg_video` varchar(255) DEFAULT NULL,
  `user_bgsite_video` varchar(255) DEFAULT NULL,
  `vpn_pass` varchar(255) DEFAULT NULL,
  `video_option` tinyint(1) NOT NULL DEFAULT '1',
  `menu_mode` enum('old','new') DEFAULT 'new',
  `mbusers` tinyint(1) NOT NULL DEFAULT '0',
  `last_login` datetime DEFAULT NULL,
  PRIMARY KEY (`UID`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;


-- ── 2) PRE-LOADED CONFIG / REFERENCE / WIDGETS (INSERT IGNORE) ──

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

LOCK TABLES `role_profiles` WRITE;
/*!40000 ALTER TABLE `role_profiles` DISABLE KEYS */;
INSERT  IGNORE INTO `role_profiles` VALUES (1,'admin','net_mon',1),(2,'admin','net_mon_config',1),(3,'admin','net_mon_map',1),(4,'admin','net_mon_stats',1),(5,'admin','live_mon',1),(6,'user','net_mon',1),(7,'user','net_mon_map',1),(8,'user','net_mon_stats',1),(9,'user','live_mon',1),(10,'user','net_mon_config',0),(21,'admin','audit_log',1),(22,'admin','log_mon',1),(23,'user','log_mon',1),(24,'admin','ai_insights',1),(25,'user','ai_insights',1),(26,'admin','copilot',1),(27,'user','copilot',1),(28,'admin','containers',1),(29,'user','containers',1),(30,'admin','smokeping',1),(31,'user','smokeping',1),(32,'admin','user_admin',1),(33,'user','user_admin',0),(34,'admin','config_mgr',1),(35,'user','config_mgr',0),(36,'admin','pihole',1),(37,'user','pihole',0),(38,'admin','netflow',1),(39,'user','netflow',0),(40,'admin','incidents',1),(41,'user','incidents',0),(42,'admin','reports',1),(43,'user','reports',0),(44,'admin','router_commander',1),(45,'admin','health',1),(46,'admin','timetravel',1),(47,'admin','immunity',1),(48,'admin','chaos',1),(49,'admin','heal',1),(50,'admin','wear',1),(51,'admin','shadowit',1),(52,'admin','archaeology',1),(53,'admin','weather',1),(54,'admin','l2switch',1),(55,'admin','ipam',1),(56,'admin','wireguard',1),(57,'admin','nettools_ping',1),(58,'admin','nettools_trace',1),(59,'admin','nettools_netstat',1),(60,'admin','geomap',1),(61,'dashboard','geomap',1),(62,'dashboard','net_mon_map',1),(63,'admin','command',1),(64,'admin','nettools_lookup',1),(65,'admin','sonify',1),(66,'admin','gpu',1),(67,'admin','windows',1),(68,'admin','linux',1),(69,'admin','aiopilot',1),(49576,'admin','troubleshoot',1),(49843,'admin','dbmon',1),(52067,'admin','sla_live',1),(56286,'admin','hologram',1),(57762,'admin','deception',1),(57763,'admin','license',1),(57764,'admin','update',1),(57765,'admin','traffic_view',1),(57766,'admin','cisco',1),(57767,'admin','cisco_switch',1),(57768,'admin','cisco_asa',1),(57769,'admin','cisco_router',1),(57770,'admin','cisco_orch',1);
/*!40000 ALTER TABLE `role_profiles` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_widgets` WRITE;
/*!40000 ALTER TABLE `nm_widgets` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_widgets` VALUES (6,'acme.top-talkers',3,'user','Top Talkers','{\"sdk\":\"1.0\",\"id\":\"acme.top-talkers\",\"name\":\"Top Talkers\",\"icon\":\"fa-fire\",\"refresh\":20,\"needs\":[{\"source\":\"netflow.top\",\"as\":\"nf\",\"params\":{\"limit\":8}}],\"kind\":\"declarative\",\"view\":{\"type\":\"bar\",\"from\":\"nf\",\"label\":\"{ip}\",\"value\":\"{mbps}\"}}',1,'2026-06-25 12:00:56','2026-06-25 12:00:56'),(7,'neuru.sla-board',3,'user','SLA Leaderboard','{\"sdk\":\"1.0\",\"id\":\"neuru.sla-board\",\"name\":\"SLA Leaderboard\",\"icon\":\"fa-gauge-high\",\"author\":\"NEURU\",\"category\":\"Reports\",\"description\":\"Uptime % per node as a table (worst first).\",\"refresh\":120,\"needs\":[{\"source\":\"sla.nodes\",\"as\":\"sla\",\"params\":{\"mins\":1440}}],\"kind\":\"declarative\",\"view\":{\"type\":\"table\",\"from\":\"sla\",\"columns\":[{\"label\":\"Node\",\"field\":\"name\"},{\"label\":\"Uptime %\",\"field\":\"uptime\"},{\"label\":\"Outages\",\"field\":\"outages\"}]}}',1,'2026-06-25 14:21:47','2026-06-25 14:21:47'),(11,'neuru.gpu-graphs',3,'user','GPU Graphs','{\"sdk\":\"1.0\",\"id\":\"neuru.gpu-graphs\",\"name\":\"GPU Graphs\",\"icon\":\"fa-chart-line\",\"author\":\"NEURU\",\"category\":\"AI / GPU\",\"description\":\"Full GPU telemetry as live line charts \\u2014 utilization, VRAM %, temperature and power over time, with the loaded model. Links to the GPU Monitor.\",\"refresh\":20,\"needs\":[{\"source\":\"gpu.series\",\"as\":\"g\",\"params\":{\"mins\":60}}],\"kind\":\"declarative\",\"view\":{\"type\":\"lines\",\"from\":\"g\",\"title\":\"target\",\"subtitle\":\"name\",\"link\":\"gpu.php\",\"series\":[{\"field\":\"util\",\"label\":\"GPU\",\"unit\":\"%\",\"color\":\"#76b900\",\"max\":100},{\"field\":\"vram\",\"label\":\"VRAM\",\"unit\":\"%\",\"color\":\"#4da3ff\",\"max\":100},{\"field\":\"temp\",\"label\":\"Temp\",\"unit\":\"\\u00b0C\",\"color\":\"#f39c12\"},{\"field\":\"power\",\"label\":\"Power\",\"unit\":\"W\",\"color\":\"#9b59b6\"}]}}',1,'2026-06-26 12:44:26','2026-06-26 12:44:26'),(12,'neuru.interface-graphs',3,'user','Interface Traffic Graphs','{\"sdk\":\"1.0\",\"id\":\"neuru.interface-graphs\",\"name\":\"Interface Traffic Graphs\",\"icon\":\"fa-network-wired\",\"author\":\"NEURU\",\"category\":\"Network\",\"description\":\"Top interfaces inbound/outbound throughput as live line charts over time, per node + interface. Links to the interface monitor.\",\"refresh\":20,\"needs\":[{\"source\":\"interfaces.series\",\"as\":\"ifs\",\"params\":{\"mins\":60,\"limit\":5}}],\"kind\":\"declarative\",\"view\":{\"type\":\"lines\",\"from\":\"ifs\",\"title\":\"iface\",\"subtitle\":\"node\",\"link\":\"interfaces.php\",\"series\":[{\"field\":\"in\",\"label\":\"In\",\"unit\":\"bps\",\"color\":\"#4da3ff\"},{\"field\":\"out\",\"label\":\"Out\",\"unit\":\"bps\",\"color\":\"#76b900\"}]}}',1,'2026-06-26 17:03:03','2026-06-26 17:03:03'),(13,'neuru.top-traffic-nodes',3,'user','Top Traffic Nodes','{\"sdk\":\"1.0\",\"id\":\"neuru.top-traffic-nodes\",\"name\":\"Top Traffic Nodes\",\"icon\":\"fa-solid fa-network-wired\",\"kind\":\"declarative\",\"needs\":[{\"source\":\"interfaces.top\",\"as\":\"iftop\",\"params\":[]}],\"view\":{\"type\":\"table\",\"from\":\"iftop\",\"columns\":[{\"label\":\"Node\",\"field\":\"node\"},{\"label\":\"Interface\",\"field\":\"iface\"},{\"label\":\"In\",\"field\":\"in_rate\"},{\"label\":\"Out\",\"field\":\"out_rate\"},{\"label\":\"Total\",\"field\":\"total\"}]},\"refresh\":20}',1,'2026-06-27 13:57:24','2026-06-27 13:57:24');
/*!40000 ALTER TABLE `nm_widgets` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_ctr_templates` WRITE;
/*!40000 ALTER TABLE `nm_ctr_templates` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_ctr_templates` VALUES (1,'Nginx','Web','nginx:alpine','Lightweight web server / reverse proxy','fa-solid fa-server','{\"80\\/tcp\":\"8080\"}','[]','[\"\\/srv\\/nginx\\/html:\\/usr\\/share\\/nginx\\/html:ro\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(2,'Apache httpd','Web','httpd:alpine','Apache HTTP server','fa-solid fa-server','{\"80\\/tcp\":\"8081\"}','[]','[]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(3,'Redis','Cache','redis:7-alpine','In-memory key/value cache','fa-solid fa-bolt','{\"6379\\/tcp\":\"6379\"}','[]','[\"\\/srv\\/redis:\\/data\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(4,'PostgreSQL','Database','postgres:16-alpine','PostgreSQL database','fa-solid fa-database','{\"5432\\/tcp\":\"5432\"}','[\"POSTGRES_PASSWORD=change_me\",\"POSTGRES_DB=app\"]','[\"\\/srv\\/pg:\\/var\\/lib\\/postgresql\\/data\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(5,'MySQL','Database','mysql:8','MySQL database','fa-solid fa-database','{\"3306\\/tcp\":\"3306\"}','[\"MYSQL_ROOT_PASSWORD=change_me\",\"MYSQL_DATABASE=app\"]','[\"\\/srv\\/mysql:\\/var\\/lib\\/mysql\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(6,'MariaDB','Database','mariadb:11','MariaDB database','fa-solid fa-database','{\"3306\\/tcp\":\"3307\"}','[\"MARIADB_ROOT_PASSWORD=change_me\",\"MARIADB_DATABASE=app\"]','[\"\\/srv\\/mariadb:\\/var\\/lib\\/mysql\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(7,'MongoDB','Database','mongo:7','MongoDB document database','fa-solid fa-leaf','{\"27017\\/tcp\":\"27017\"}','[\"MONGO_INITDB_ROOT_USERNAME=root\",\"MONGO_INITDB_ROOT_PASSWORD=change_me\"]','[\"\\/srv\\/mongo:\\/data\\/db\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(8,'Grafana','Observability','grafana/grafana:latest','Dashboards & visualization','fa-solid fa-chart-line','{\"3000\\/tcp\":\"3000\"}','[\"GF_SECURITY_ADMIN_PASSWORD=change_me\"]','[\"\\/srv\\/grafana:\\/var\\/lib\\/grafana\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(9,'Prometheus','Observability','prom/prometheus:latest','Metrics time-series DB','fa-solid fa-fire','{\"9090\\/tcp\":\"9090\"}','[]','[\"\\/srv\\/prometheus:\\/prometheus\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(10,'Uptime Kuma','Monitoring','louislam/uptime-kuma:1','Self-hosted uptime monitor','fa-solid fa-heart-pulse','{\"3001\\/tcp\":\"3001\"}','[]','[\"\\/srv\\/uptime-kuma:\\/app\\/data\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(11,'Portainer Agent','Infra','portainer/agent:latest','Adopt a new Docker host into Portainer','fa-brands fa-docker','{\"9001\\/tcp\":\"9001\"}','[]','[\"\\/var\\/run\\/docker.sock:\\/var\\/run\\/docker.sock\",\"\\/var\\/lib\\/docker\\/volumes:\\/var\\/lib\\/docker\\/volumes\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(12,'Watchtower','Infra','containrrr/watchtower:latest','Auto-update running containers','fa-solid fa-arrows-rotate','[]','[]','[\"\\/var\\/run\\/docker.sock:\\/var\\/run\\/docker.sock\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(13,'Adminer','Database','adminer:latest','Web DB management UI','fa-solid fa-table','{\"8080\\/tcp\":\"8082\"}','[]','[]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(14,'Vaultwarden','Security','vaultwarden/server:latest','Self-hosted Bitwarden','fa-solid fa-shield-halved','{\"80\\/tcp\":\"8200\"}','[\"ADMIN_TOKEN=change_me\"]','[\"\\/srv\\/vaultwarden:\\/data\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(15,'Nextcloud','Productivity','nextcloud:apache','Self-hosted file cloud','fa-solid fa-cloud','{\"80\\/tcp\":\"8300\"}','[]','[\"\\/srv\\/nextcloud:\\/var\\/www\\/html\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09'),(16,'Pi-hole','Network','pihole/pihole:latest','Network-wide ad/DNS blocker','fa-solid fa-shield-virus','{\"53\\/tcp\":\"53\",\"53\\/udp\":\"53\",\"80\\/tcp\":\"8888\"}','[\"TZ=America\\/Puerto_Rico\",\"WEBPASSWORD=change_me\"]','[\"\\/srv\\/pihole\\/etc:\\/etc\\/pihole\",\"\\/srv\\/pihole\\/dnsmasq.d:\\/etc\\/dnsmasq.d\"]','unless-stopped',1,NULL,'2026-06-30 23:39:09');
/*!40000 ALTER TABLE `nm_ctr_templates` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_heal_playbooks` WRITE;
/*!40000 ALTER TABLE `nm_heal_playbooks` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_heal_playbooks` VALUES ('crypto_mining','Crypto-mining traffic','crypto_mining','block_ip','armed',60,1,'2026-06-25 18:11:06'),('flood_dos','SYN/UDP flood (DoS)','flood','block_ip','armed',15,800,'2026-06-25 18:11:16'),('internal_scan','Internal host scanning (lateral)','internal_scan','block_ip','armed',15,10,'2026-06-25 18:11:09'),('l2_loop','L2 loop / broadcast storm','l2_loop','isolate_port','armed',10,0,'2026-06-23 14:00:48'),('ntp_amp','NTP amplification','ntp_amp','block_ip','armed',20,50,'2026-06-23 14:00:52'),('portscan','Port-scan source','portscan','block_ip','armed',15,10,'2026-06-23 14:00:54'),('ssh_bruteforce','SSH/RDP brute-force','ssh_bruteforce','block_ip','armed',30,8,'2026-06-25 18:11:12'),('web_attack','Web attack (SQLi/RCE/scanner)','web_attack','block_ip','armed',30,5,'2026-06-25 18:11:19');
/*!40000 ALTER TABLE `nm_heal_playbooks` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_oid_templates` WRITE;
/*!40000 ALTER TABLE `nm_oid_templates` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_oid_templates` VALUES (1,'Generic / HOST-RESOURCES-MIB','generic','Standard HOST-RESOURCES-MIB metrics (CPU, RAM, disk) — works on most SNMP agents',1,'2026-06-18 23:18:10'),(2,'MikroTik RouterOS','mikrotik','MikroTik-specific OIDs (CPU, memory, voltage)',1,'2026-06-18 23:18:10'),(3,'Linux / NET-SNMP','linux','NET-SNMP UCD-SNMP-MIB metrics for Linux hosts',1,'2026-06-18 23:18:10'),(4,'Cisco IOS / IOS-XE','cisco','Cisco IOS OIDs (CPU 5-sec, 1-min; memory)',1,'2026-06-18 23:18:10'),(293,'Cisco Aironet / AireOS (Mobility Express)','cisco','Airespace MIB (enterprise 14179) for Cisco Aironet APs running Mobility Express / AireOS WLC. CPU via agentCurrentCPUUtilization; memory used% computed from agentFreeMemory/agentTotalMemory. HOST-RESOURCES and IOS CPU OIDs are not implemented on these.',1,'2026-06-19 12:06:30'),(698,'HP Printer / Printer-MIB (RFC 3805)','printer','Standard Printer-MIB for HP (and most networked) printers: ink/toner % per supply (prtMarkerSuppliesLevel / MaxCapacity), total page count, and printer status. Supply indices follow the common HP 4-ink order (1=Black,2=Cyan,3=Magenta,4=Yellow); adjust per model in this template if a printer orders them differently.',1,'2026-06-19 14:49:47'),(19422,'Windows Server / HOST-RESOURCES-MIB','windows','For Windows (SNMP Service enabled). CPU, RAM% and per-volume disk are already auto-collected via HOST-RESOURCES-MIB; this template adds the Windows-specific extras: running processes, logged-in users, and total physical RAM.',1,'2026-06-26 19:43:02');
/*!40000 ALTER TABLE `nm_oid_templates` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_oid_configs` WRITE;
/*!40000 ALTER TABLE `nm_oid_configs` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_oid_configs` VALUES (1,1,NULL,'CPU Usage','cpu','.1.3.6.1.2.1.25.3.3.1.2',NULL,'%',1,1.000000,'HOST-RESOURCES-MIB hrProcessorLoad (walk, avg)',1,1),(2,1,NULL,'RAM Used','ram','.1.3.6.1.2.1.25.2.3.1.6','.1.3.6.1.2.1.25.2.3.1.5','%',0,1.000000,'hrStorageUsed / hrStorageSize × 100 (first RAM entry)',1,2),(3,2,NULL,'CPU Usage','cpu','.1.3.6.1.4.1.14988.1.1.3.14',NULL,'%',0,1.000000,'MikroTik system CPU usage',1,1),(4,2,NULL,'RAM Used','ram','.1.3.6.1.4.1.14988.1.1.3.12','.1.3.6.1.4.1.14988.1.1.3.13','%',0,1.000000,'mtxrMemoryUsed / mtxrMemoryTotal × 100',1,2),(5,2,NULL,'Board Voltage','custom','.1.3.6.1.4.1.14988.1.1.3.8',NULL,'V',0,0.100000,'mtxrHlVoltage (×0.1 for volts)',1,3),(6,3,NULL,'CPU User %','cpu','.1.3.6.1.4.1.2021.11.9.0',NULL,'%',0,1.000000,'UCD-SNMP-MIB ssCpuUser',1,1),(7,3,NULL,'CPU System %','cpu','.1.3.6.1.4.1.2021.11.10.0',NULL,'%',0,1.000000,'UCD-SNMP-MIB ssCpuSystem',1,2),(8,3,NULL,'RAM Total','ram','.1.3.6.1.4.1.2021.4.5.0',NULL,'kB',0,1.000000,'UCD-SNMP-MIB memTotalReal',1,3),(9,3,NULL,'RAM Available','ram','.1.3.6.1.4.1.2021.4.6.0',NULL,'kB',0,1.000000,'UCD-SNMP-MIB memAvailReal',1,4),(10,4,NULL,'CPU 5-sec','cpu','.1.3.6.1.4.1.9.2.1.56.0',NULL,'%',0,1.000000,'Cisco OLD-CISCO-SYSTEM-MIB avgBusy5',1,1),(11,4,NULL,'CPU 1-min','cpu','.1.3.6.1.4.1.9.2.1.57.0',NULL,'%',0,1.000000,'Cisco OLD-CISCO-SYSTEM-MIB avgBusy1',1,2),(12,4,NULL,'Memory Free','custom','.1.3.6.1.4.1.9.2.1.8.0',NULL,'B',0,1.000000,'Cisco OLD-CISCO-SYSTEM-MIB freeMem',1,3),(13,1,NULL,'CPU Usage','cpu','.1.3.6.1.2.1.25.3.3.1.2',NULL,'%',1,1.000000,'HOST-RESOURCES-MIB hrProcessorLoad (walk, avg)',1,1),(14,1,NULL,'RAM Used','ram','.1.3.6.1.2.1.25.2.3.1.6','.1.3.6.1.2.1.25.2.3.1.5','%',0,1.000000,'hrStorageUsed / hrStorageSize × 100 (first RAM entry)',1,2),(15,2,NULL,'CPU Usage','cpu','.1.3.6.1.4.1.14988.1.1.3.14',NULL,'%',0,1.000000,'MikroTik system CPU usage',1,1),(16,2,NULL,'RAM Used','ram','.1.3.6.1.4.1.14988.1.1.3.12','.1.3.6.1.4.1.14988.1.1.3.13','%',0,1.000000,'mtxrMemoryUsed / mtxrMemoryTotal × 100',1,2),(17,2,NULL,'Board Voltage','custom','.1.3.6.1.4.1.14988.1.1.3.8',NULL,'V',0,0.100000,'mtxrHlVoltage (×0.1 for volts)',1,3),(18,3,NULL,'CPU User %','cpu','.1.3.6.1.4.1.2021.11.9.0',NULL,'%',0,1.000000,'UCD-SNMP-MIB ssCpuUser',1,1),(19,3,NULL,'CPU System %','cpu','.1.3.6.1.4.1.2021.11.10.0',NULL,'%',0,1.000000,'UCD-SNMP-MIB ssCpuSystem',1,2),(20,3,NULL,'RAM Total','ram','.1.3.6.1.4.1.2021.4.5.0',NULL,'kB',0,1.000000,'UCD-SNMP-MIB memTotalReal',1,3),(21,3,NULL,'RAM Available','ram','.1.3.6.1.4.1.2021.4.6.0',NULL,'kB',0,1.000000,'UCD-SNMP-MIB memAvailReal',1,4),(22,4,NULL,'CPU 5-sec','cpu','.1.3.6.1.4.1.9.2.1.56.0',NULL,'%',0,1.000000,'Cisco OLD-CISCO-SYSTEM-MIB avgBusy5',1,1),(23,4,NULL,'CPU 1-min','cpu','.1.3.6.1.4.1.9.2.1.57.0',NULL,'%',0,1.000000,'Cisco OLD-CISCO-SYSTEM-MIB avgBusy1',1,2),(24,4,NULL,'Memory Free','custom','.1.3.6.1.4.1.9.2.1.8.0',NULL,'B',0,1.000000,'Cisco OLD-CISCO-SYSTEM-MIB freeMem',1,3),(25,293,NULL,'CPU Utilization','cpu','.1.3.6.1.4.1.14179.1.1.5.1.0',NULL,'%',0,1.000000,'agentCurrentCPUUtilization',1,1),(26,293,NULL,'System Memory','memory','.1.3.6.1.4.1.14179.1.1.5.3.0','.1.3.6.1.4.1.14179.1.1.5.2.0','%',0,1024.000000,'Used% from agentFreeMemory/agentTotalMemory (KB)',1,2),(33,698,NULL,'Magenta Ink','custom','.1.3.6.1.2.1.43.11.1.1.9.1.1','.1.3.6.1.2.1.43.11.1.1.8.1.1','%',0,1.000000,'prtMarkerSupplies idx1',1,1),(34,698,NULL,'Cyan Ink','custom','.1.3.6.1.2.1.43.11.1.1.9.1.2','.1.3.6.1.2.1.43.11.1.1.8.1.2','%',0,1.000000,'prtMarkerSupplies idx2',1,2),(35,698,NULL,'Yellow Ink','custom','.1.3.6.1.2.1.43.11.1.1.9.1.3','.1.3.6.1.2.1.43.11.1.1.8.1.3','%',0,1.000000,'prtMarkerSupplies idx3',1,3),(36,698,NULL,'Black Ink','custom','.1.3.6.1.2.1.43.11.1.1.9.1.4','.1.3.6.1.2.1.43.11.1.1.8.1.4','%',0,1.000000,'prtMarkerSupplies idx4',1,4),(37,698,NULL,'Page Count','custom','.1.3.6.1.2.1.43.10.2.1.4.1.1',NULL,'pages',0,1.000000,'prtMarkerLifeCount',1,5),(38,698,NULL,'Printer Status','custom','.1.3.6.1.2.1.25.3.5.1.1.1',NULL,'',0,1.000000,'hrPrinterStatus 3=idle 4=printing 5=warmup',1,6),(40,293,NULL,'Clients Connected','custom','.1.3.6.1.4.1.14179.2.1.1.1.38.1',NULL,'clients',0,1.000000,'bsnAPIfLoadNumOfClients (total associated wireless clients)',1,3),(41,19422,NULL,'Running Processes','custom','.1.3.6.1.2.1.25.1.6.0',NULL,'proc',0,1.000000,'hrSystemProcesses — number of process contexts currently loaded',1,10),(42,19422,NULL,'Logged-in Users','custom','.1.3.6.1.2.1.25.1.5.0',NULL,'users',0,1.000000,'hrSystemNumUsers — user sessions on the host',1,20),(43,19422,NULL,'Physical RAM Total','custom','.1.3.6.1.2.1.25.2.2.0',NULL,'kB',0,1.000000,'hrMemorySize — total installed physical RAM (kB)',1,30);
/*!40000 ALTER TABLE `nm_oid_configs` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_health_optical_oids` WRITE;
/*!40000 ALTER TABLE `nm_health_optical_oids` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_health_optical_oids` VALUES (1,'entity_sensor',NULL,'ENTITY-SENSOR entPhySensorValue','rx_dbm','0.1',1,0,'2026-06-23 11:59:56'),(2,'mikrotik',NULL,'MikroTik SFP Rx power (×0.01 dBm? verify)','rx_dbm','0.1',0.01,0,'2026-06-23 11:59:56'),(3,'mikrotik',NULL,'MikroTik SFP Tx power','tx_dbm','0.1',0.01,0,'2026-06-23 11:59:56'),(4,'mikrotik',NULL,'MikroTik SFP temperature','temp_c','0.1',0.001,0,'2026-06-23 11:59:56'),(5,'mikrotik',NULL,'MikroTik SFP Tx bias','bias_ma','0.1',0.001,0,'2026-06-23 11:59:56'),(6,'mikrotik',NULL,'MikroTik SFP supply voltage','volt_v','0.1',0.001,0,'2026-06-23 11:59:56'),(7,'cisco',NULL,'Cisco entSensorValue (DOM)','rx_dbm','0.1',1,0,'2026-06-23 11:59:56');
/*!40000 ALTER TABLE `nm_health_optical_oids` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_n8n_webhooks` WRITE;
/*!40000 ALTER TABLE `nm_n8n_webhooks` DISABLE KEYS */;
INSERT  IGNORE INTO `nm_n8n_webhooks` VALUES (1,'log-rca','log-rca','','POST',NULL,1,3,'2026-06-19 17:05:31'),(2,'self-heal','self-heal','','POST',NULL,1,3,'2026-06-19 19:05:27'),(3,'self-heal-apply','self-heal-apply','','POST',NULL,1,3,'2026-06-19 19:07:18'),(4,'netops-copilot','netops-copilot','','POST',NULL,1,3,'2026-06-20 10:20:36'),(5,'Config Backup','config-backup','','POST','Router Configuration Manager: n8n SSHes the router, runs the brand command, returns the running config.',1,NULL,'2026-06-22 12:16:54'),(6,'AI Copilot (NetAIObot) webhook/log_rca','aiopilot','','POST','NetAIObot ReAct brain — receives full device context + tool catalog, runs the Observe→Think→Act loop, calls back aiopilot_api.php.',1,NULL,'2026-06-28 13:13:35'),(49705,'db-advisor','db-advisor','','POST','Root-caoiuse for analysis',1,3,'2026-06-30 15:19:14'),(53804,'Deception Analyst','deception-analyst','','POST','Auto-added by NEURU (Deception Grid). To activate: paste your n8n URL http://<n8n>:5678/webhook/deception-analyst and tick Enabled. It analyses a diverted attacker and returns {threat_score,verdict,summary}. See docs/N8N_DECEPTION.md.',1,NULL,'2026-07-01 13:57:01');
/*!40000 ALTER TABLE `nm_n8n_webhooks` ENABLE KEYS */;
UNLOCK TABLES;

LOCK TABLES `nm_settings` WRITE;
/*!40000 ALTER TABLE `nm_settings` DISABLE KEYS */;
INSERT IGNORE INTO `nm_settings` (`setting_key`,`setting_val`,`label`) VALUES
('poll_interval','60','Default poll interval (seconds)'),
('poll_interval_health','60','Health poll interval (seconds)'),
('poll_interval_ifaces','300','Interface poll interval (seconds)'),
('retention_days','30','Stats retention (days)'),
('discovery_enabled','1','Enable LAN discovery'),
('discovery_subnet','','Discovery subnet (CIDR, blank = auto)'),
('discovery_subnets','','Discovery subnets (CIDR list)'),
('discovery_community','public','SNMP community for discovery'),
('discovery_communities','public','SNMP communities'),
('discovery_version','2c','SNMP version for discovery'),
('discovery_schedule','manual','Discovery schedule'),
('snmp_timeout','3','SNMP timeout (seconds)'),
('snmp_retries','1','SNMP retries'),
('app_timezone','UTC','Display timezone'),
('log_source','syslog','Primary log source'),
('syslog_port','514','Syslog listen port'),
('syslog_retention_days','30','Syslog retention (days)'),
('syslog_tcp_enabled','1','Syslog TCP enabled'),
('netflow_enabled','0','NetFlow collector enabled'),
('netflow_port','2055','NetFlow/IPFIX port'),
('netflow_retention_days','7','NetFlow retention (days)'),
('netflow_sampling','1','NetFlow sampling'),
('netflow_topn','300','NetFlow top-N'),
('netflow_baseline_mult','4','NetFlow baseline multiplier'),
('ping_fail_threshold','2','Consecutive ping fails before down'),
('thr_cpu_info','70','CPU info level %'),
('thr_cpu_warn','85','CPU warn level %'),
('thr_cpu_crit','95','CPU crit level %'),
('thr_mem_info','80','Mem info %'),
('thr_mem_warn','90','Mem warn %'),
('thr_mem_crit','97','Mem crit %'),
('thr_disk_info','80','Disk info %'),
('thr_disk_warn','90','Disk warn %'),
('thr_disk_crit','96','Disk crit %'),
('thr_reboot_max_h','12','Flag reboot only if uptime under N h'),
('thr_reboot_warn_h','3','Reboot warning if under N h'),
('thr_incident_min_sev','warning','Min AI severity to open an incident'),
('ai_insight_ttl_hours','6','Auto-resolve open AI insights older than N hours'),
('imm_detect_dns','1','Immunity: detect malicious DNS'),
('imm_detect_portscan','1','Immunity: detect port scans'),
('imm_portscan_window','10','Portscan window (s)'),
('imm_portscan_ports','10','Portscan distinct-port threshold'),
('imm_auto_vaccinate','0','Immunity: auto fan-out (off by default)'),
('lnms_enabled','0','LibreNMS integration'),
('graylog_enabled','0','Graylog integration'),
('smtp_enabled','0','Email (SMTP) enabled'),
('notify_enabled','0','Notifications enabled'),
('notify_min_severity','warning','Min notification severity'),
('notify_resolve_notice','1','Send resolve notices'),
('pihole_enabled','0','Pi-hole integration'),
('smokeping_enabled','0','Smokeping integration'),
('immunity_enabled','0','Collective Immunity'),
('deception_enabled','0','Deception Grid'),
('aip_enabled','0','NetAIObot autonomous agent'),
('kb_enabled','0','Copilot knowledge base'),
('error_watch_enabled','0','Container error watch'),
('netalert_enabled','1','Network up/down alerts');
/*!40000 ALTER TABLE `nm_settings` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;



-- ── 2b) TABLES ADDED SINCE v1 (biosphere, firewall, routing, db-observatory, aiopilot) ──
-- (also created idempotently by install/apply_updates.php / each engine _ensure)
CREATE TABLE IF NOT EXISTS `nm_ai_heal_link` (
  `node_id` int NOT NULL,
  `correlation_key` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL,
  `source_id` bigint NOT NULL,
  `requested_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`node_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `nm_bio_flags` (
  `id` int NOT NULL AUTO_INCREMENT,
  `service_id` int DEFAULT NULL,
  `kind` varchar(24) NOT NULL,
  `indicator` varchar(255) DEFAULT NULL,
  `severity` varchar(12) NOT NULL DEFAULT 'medium',
  `detail` text,
  `status` varchar(12) NOT NULL DEFAULT 'open',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_bio_links` (
  `id` int NOT NULL AUTO_INCREMENT,
  `from_service` int NOT NULL,
  `to_service` int NOT NULL,
  `kind` varchar(12) NOT NULL DEFAULT 'depends',
  `source` varchar(12) NOT NULL DEFAULT 'manual',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_edge` (`from_service`,`to_service`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_bio_samples` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `service_id` int NOT NULL,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ok` tinyint NOT NULL DEFAULT '0',
  `latency_ms` double DEFAULT NULL,
  `err_rate` double DEFAULT NULL,
  `throughput` double DEFAULT NULL,
  `cache_hit` double DEFAULT NULL,
  `score` int DEFAULT NULL,
  `level` varchar(12) DEFAULT NULL,
  `extra` text,
  PRIMARY KEY (`id`),
  KEY `k_svc_ts` (`service_id`,`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_bio_services` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `kind` varchar(16) NOT NULL DEFAULT 'http',
  `target` varchar(255) DEFAULT NULL,
  `port` int DEFAULT NULL,
  `params` text,
  `db_target_id` int DEFAULT NULL,
  `pihole_id` int DEFAULT NULL,
  `node_id` int DEFAULT NULL,
  `enabled` tinyint NOT NULL DEFAULT '1',
  `last_ok` tinyint DEFAULT NULL,
  `last_level` varchar(12) DEFAULT NULL,
  `last_checked` datetime DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_bio_synthetic` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `service_id` int NOT NULL,
  `ts` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ok` tinyint NOT NULL DEFAULT '0',
  `vct_ms` double DEFAULT NULL,
  `total_ms` double DEFAULT NULL,
  `steps_total` int DEFAULT NULL,
  `steps_ok` int DEFAULT NULL,
  `broken_step` varchar(160) DEFAULT NULL,
  `console_errors` int DEFAULT NULL,
  `screenshot` mediumtext,
  `detail` text,
  PRIMARY KEY (`id`),
  KEY `k_svc_ts` (`service_id`,`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_bio_tg_approvals` (
  `id` int NOT NULL AUTO_INCREMENT,
  `kind` varchar(16) NOT NULL DEFAULT 'autotune',
  `ref_id` int NOT NULL,
  `service_id` int DEFAULT NULL,
  `token` varchar(40) NOT NULL,
  `chat_msg_id` bigint DEFAULT NULL,
  `detail` varchar(255) DEFAULT NULL,
  `status` varchar(12) NOT NULL DEFAULT 'pending',
  `created_by` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `decided_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_ref` (`kind`,`ref_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_dbobs_cache` (
  `id` tinyint NOT NULL,
  `payload` mediumtext,
  `ts` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_mtfw_pending` (
  `token` varchar(24) NOT NULL,
  `node_id` int NOT NULL,
  `fw_table` varchar(10) NOT NULL,
  `op` varchar(10) NOT NULL,
  `cmd` text,
  `revert` text,
  `window_min` int DEFAULT '2',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_by` int DEFAULT NULL,
  `status` varchar(12) DEFAULT 'armed',
  PRIMARY KEY (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_mtfw_snapshots` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `fw_table` varchar(10) NOT NULL DEFAULT 'filter',
  `taken_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `rule_count` int DEFAULT '0',
  `rules_json` mediumtext,
  `reason` varchar(64) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_node` (`node_id`,`fw_table`,`taken_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_routing_snapshots` (
  `id` int NOT NULL AUTO_INCREMENT,
  `node_id` int NOT NULL,
  `taken_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `route_count` int NOT NULL DEFAULT '0',
  `routes_json` mediumtext,
  PRIMARY KEY (`id`),
  KEY `idx_node` (`node_id`,`taken_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- ── 2c) FEDERATION tables (F1 cluster: master/slave) ──
CREATE TABLE IF NOT EXISTS `nm_cluster_sites` (
  `id` int NOT NULL AUTO_INCREMENT,
  `site_slug` varchar(50) NOT NULL,
  `name` varchar(120) NOT NULL,
  `endpoint_url` varchar(255) DEFAULT NULL,
  `token_enc` text,
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `last_seen` datetime DEFAULT NULL,
  `captured_at` datetime DEFAULT NULL,
  `node_total` int DEFAULT '0',
  `node_up` int DEFAULT '0',
  `node_down` int DEFAULT '0',
  `node_degraded` int DEFAULT '0',
  `inc_open` int DEFAULT '0',
  `inc_crit` int DEFAULT '0',
  `last_payload` mediumtext,
  `created_by` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_slug` (`site_slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_cluster_rollups` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `site_slug` varchar(50) NOT NULL,
  `captured_at` datetime NOT NULL,
  `received_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `node_total` int DEFAULT '0',
  `node_up` int DEFAULT '0',
  `node_down` int DEFAULT '0',
  `node_degraded` int DEFAULT '0',
  `inc_open` int DEFAULT '0',
  `inc_crit` int DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_site_time` (`site_slug`,`received_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_cluster_visibility` (
  `role_name` varchar(50) NOT NULL,
  `site_slug` varchar(50) NOT NULL,
  PRIMARY KEY (`role_name`,`site_slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_cluster_outbox` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `captured_at` datetime NOT NULL,
  `payload` mediumtext NOT NULL,
  `attempts` int NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- F2 federated incidents
CREATE TABLE IF NOT EXISTS `nm_cluster_incidents` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `site_slug` varchar(50) NOT NULL,
  `ext_id` int DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `severity` varchar(10) NOT NULL DEFAULT 'warning',
  `node_name` varchar(120) DEFAULT NULL,
  `age_s` int DEFAULT NULL,
  `received_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_site` (`site_slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- F3 cluster command queue
CREATE TABLE IF NOT EXISTS `nm_cluster_commands` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `type` varchar(24) NOT NULL,
  `payload` text,
  `summary` varchar(200) DEFAULT NULL,
  `created_by` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `nm_cluster_cmd_delivery` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `command_id` bigint NOT NULL,
  `site_slug` varchar(50) NOT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'pending',
  `detail` varchar(255) DEFAULT NULL,
  `acted_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_cmd_site` (`command_id`,`site_slug`),
  KEY `idx_site_status` (`site_slug`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ── 3) ADMIN USER (admin / admin@1.one) ──
INSERT IGNORE INTO users (UID, USERNAME, name, PASSWORD, email, role) VALUES
  (1, 'admin', 'Administrator', '$2y$10$tpEoQoSy/Ot2b9Oee9ffgu3hTJr0Md1/bbuQPh0HUPaSYewPGrLm6', 'admin@1.one', 'admin');

-- ── 4) SANITIZE — disable everything risky; blank per-install secrets ──
UPDATE nm_n8n_webhooks SET enabled=0;                       -- all webhooks OFF (fill URL + enable later)
UPDATE nm_heal_playbooks SET mode='off';                    -- all self-heal playbooks OFF
UPDATE nm_settings SET setting_val='0' WHERE setting_key IN
  ('deception_enabled','deception_auto','imm_auto_vaccinate','aip_enabled','discovery_enabled');
UPDATE nm_settings SET setting_val='' WHERE setting_key IN
  ('fix_ssh_password','graylog_token','lnms_token','n8n_api_key','pihole_password_enc','portainer_api_key','smtp_pass_enc');
SET FOREIGN_KEY_CHECKS=1;
