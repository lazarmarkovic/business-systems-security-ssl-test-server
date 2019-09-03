package com.businesssystemssecurity.scds.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/testSSL")
public class SSLConnectionDemonstrationServerController {

    @GetMapping("/receiveFromSub")
    ResponseEntity<String> receiveFromSub() {
        return new ResponseEntity<>("I AM SUB.", HttpStatus.OK);
    }
}
