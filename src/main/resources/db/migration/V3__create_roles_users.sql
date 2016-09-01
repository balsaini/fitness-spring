CREATE TABLE `fitness`.`roles_users` (
  `role_id` INT NOT NULL,
  `user_id` INT NOT NULL,
  PRIMARY KEY (`role_id`, `user_id`),
  CONSTRAINT `fk_roles_v3`
  FOREIGN KEY (`role_id`)
  REFERENCES `fitness`.`roles` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_users_v3`
  FOREIGN KEY (`user_id`)
  REFERENCES `fitness`.`users` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION);
