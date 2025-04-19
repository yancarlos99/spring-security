package com.spring.security.entities.dto;

public record LoginResponse(String accessToken, Long expireIn) {
}
