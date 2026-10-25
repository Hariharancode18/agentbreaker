CREATE TABLE `agentbreaker_agents` (
	`id` varchar(64) NOT NULL,
	`name` varchar(120) NOT NULL,
	`description` text NOT NULL,
	`role` varchar(32) NOT NULL,
	`version` varchar(32) NOT NULL,
	`policy` json NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `agentbreaker_agents_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `agentbreaker_attacks` (
	`id` varchar(64) NOT NULL,
	`category` varchar(80) NOT NULL,
	`name` varchar(120) NOT NULL,
	`description` text NOT NULL,
	`payload` text NOT NULL,
	`expectedBehavior` text NOT NULL,
	`detectionConditions` json NOT NULL,
	`baselineSeverity` varchar(16) NOT NULL,
	CONSTRAINT `agentbreaker_attacks_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `agentbreaker_events` (
	`id` varchar(64) NOT NULL,
	`executionId` varchar(64) NOT NULL,
	`eventType` varchar(40) NOT NULL,
	`title` varchar(160) NOT NULL,
	`detail` text NOT NULL,
	`payload` json,
	`timestamp` timestamp NOT NULL,
	CONSTRAINT `agentbreaker_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `agentbreaker_executions` (
	`id` varchar(64) NOT NULL,
	`agentId` varchar(64) NOT NULL,
	`attackId` varchar(64) NOT NULL,
	`status` varchar(24) NOT NULL,
	`input` text NOT NULL,
	`response` text NOT NULL,
	`analysis` json NOT NULL,
	`startedAt` timestamp NOT NULL,
	`completedAt` timestamp NOT NULL,
	CONSTRAINT `agentbreaker_executions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `agentbreaker_vulnerabilities` (
	`id` varchar(64) NOT NULL,
	`executionId` varchar(64) NOT NULL,
	`attackId` varchar(64) NOT NULL,
	`category` varchar(80) NOT NULL,
	`title` varchar(180) NOT NULL,
	`severity` varchar(16) NOT NULL,
	`riskScore` int NOT NULL,
	`evidence` json NOT NULL,
	`recommendation` json NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `agentbreaker_vulnerabilities_id` PRIMARY KEY(`id`)
);
