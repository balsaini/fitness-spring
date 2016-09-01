package com.chyld.repositories;

import com.chyld.entities.User;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.List;

public interface IUserRepository extends PagingAndSortingRepository<User, Integer> {
    public User findByUsername(String username);
}
