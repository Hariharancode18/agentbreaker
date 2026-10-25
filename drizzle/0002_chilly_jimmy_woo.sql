ALTER TABLE `agentbreaker_agents` ADD `agentType` varchar(16) NOT NULL;--> statement-breakpoint
ALTER TABLE `agentbreaker_agents` ADD `model` varchar(120) NOT NULL;--> statement-breakpoint
ALTER TABLE `agentbreaker_agents` ADD `status` varchar(16) NOT NULL;--> statement-breakpoint
ALTER TABLE `agentbreaker_agents` ADD `tools` json NOT NULL;--> statement-breakpoint
ALTER TABLE `agentbreaker_agents` ADD `lastTested` timestamp DEFAULT (now()) NOT NULL;