package com.chyld.services;

import com.chyld.entities.Role;
import com.chyld.enums.RoleEnum;
import com.chyld.repositories.IRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleService {
    private IRoleRepository repository;

    @Autowired
    public void setRepository(IRoleRepository repository) {
        this.repository = repository;
    }

    public Role findByRole(RoleEnum role){
        return this.repository.findByRole(role);
    }
}
