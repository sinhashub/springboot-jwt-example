package com.san.jwtexample01.jwtexample01.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("/hello") // now it becomes /api/hello (protected!)
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello from secured endpoint!");
    }
}