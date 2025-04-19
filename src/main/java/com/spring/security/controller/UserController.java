package com.spring.security.controller;

import com.spring.security.entities.Role;
import com.spring.security.entities.User;
import com.spring.security.entities.dto.CreateUserDTO;
import com.spring.security.repository.RoleRepository;
import com.spring.security.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Set;

@RestController
public class UserController {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder  bCryptPasswordEncoder;

    public UserController(UserRepository userRepository, RoleRepository roleRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping("/users")
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDTO request){
        var basicRole = roleRepository.findByName(Role.Values.BASIC.name());
        var userFromDB = userRepository.findByUsername(request.username());

        if(userFromDB.isPresent()){
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }

        User user = new User();
        user.setUsername(request.username());
        user.setPassword(bCryptPasswordEncoder.encode(request.password()));
        user.setRoles(Set.of(basicRole));

        userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<List<User>> listUsers(){
        return ResponseEntity.ok(userRepository.findAll());
    }
}
