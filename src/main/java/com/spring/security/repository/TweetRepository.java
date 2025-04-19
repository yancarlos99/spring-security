package com.spring.security.repository;

import com.spring.security.entities.Role;
import com.spring.security.entities.Tweet;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface TweetRepository extends JpaRepository<Tweet, Long> {
}
