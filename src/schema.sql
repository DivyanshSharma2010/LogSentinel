CREATE DATABASE IF NOT EXISTS LogSentinel;
USE LogSentinel;
CREATE TABLE `events` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `log_type` varchar(32) NOT NULL,
  `event_time` datetime DEFAULT NULL,
  `ip` varchar(45) DEFAULT NULL,
  `username` varchar(128) DEFAULT NULL,
  `event_type` varchar(64) DEFAULT NULL,
  `details` json DEFAULT NULL,
  `raw_line` text NOT NULL,
  `source_file` varchar(255) NOT NULL,
  `line_number` int unsigned NOT NULL,
  `process` varchar(64) DEFAULT NULL,
  `ingested_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_analyzed` tinyint(1) NOT NULL DEFAULT '0',
  `is_quarantined` tinyint(1) DEFAULT '0',
  `risk_score` int DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_source_line` (`source_file`,`line_number`),
  KEY `idx_ip_time` (`ip`,`event_time`),
  KEY `idx_type_event` (`log_type`,`event_type`),
  KEY `idx_time` (`event_time`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_username` (`username`),
  KEY `idx_ip_event_time` (`ip`,`event_time`),
  KEY `idx_unanalyzed` (`is_analyzed`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `quarantine` (
  `id` int NOT NULL AUTO_INCREMENT,
  `log_hash` varchar(64) DEFAULT NULL,
  `log_line` text NOT NULL,
  `event_time` datetime DEFAULT NULL,
  `risk_score` int NOT NULL,
  `trigger_reasons` text,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  `threat_type` varchar(255) DEFAULT NULL,
  `user_name` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_log` (`log_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;