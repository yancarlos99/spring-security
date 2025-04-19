package com.spring.security.repository;

import com.spring.security.entities.Role;
import com.spring.security.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Role findByName(String name);
}
