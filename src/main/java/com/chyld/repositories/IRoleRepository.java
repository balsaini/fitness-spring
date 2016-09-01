package com.chyld.repositories;

import com.chyld.entities.Role;
import com.chyld.enums.RoleEnum;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface IRoleRepository extends PagingAndSortingRepository<Role, Integer> {
    public Role findByRole(RoleEnum role);
}
