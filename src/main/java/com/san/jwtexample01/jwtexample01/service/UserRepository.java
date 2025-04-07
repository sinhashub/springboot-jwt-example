package com.san.jwtexample01.jwtexample01.service;

import com.san.jwtexample01.jwtexample01.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface  UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

}
