CREATE TABLE `fitness`.`profiles` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `version` INT NOT NULL DEFAULT 0,
  `gender` ENUM('M', 'F') NULL,
  `age` INT NULL,
  `height` FLOAT NULL,
  `weight` FLOAT NULL,
  `photo` VARCHAR(255) NULL,
  `user_id` INT NOT NULL,
  `created` TIMESTAMP NOT NULL DEFAULT NOW(),
  `modified` TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_users_v4`
  FOREIGN KEY (`user_id`)
  REFERENCES `fitness`.`users` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION);
