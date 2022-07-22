package com.app.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.dto.AuthRequest;
import com.app.dto.AuthResp;
import com.app.jwt_utils.JwtUtils;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class SignInSignUpController {

	@Autowired
	private JwtUtils utils;
	
	@Autowired
	private AuthenticationManager manager;
	
	
	@PostMapping("/signin")
	public ResponseEntity<?> validateUserCreateToken(@RequestBody @Valid AuthRequest request) {
		// store incoming user details(not yet validated) into Authentication object
		// Authentication i/f ---> imple by UserNamePasswordAuthToken
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(request.getEmail(),
				request.getPassword());
		log.info("auth token " + authToken);
		try {
			// authenticate the credentials
			Authentication authenticatedDetails = manager.authenticate(authToken);
			// => auth succcess
			return ResponseEntity.ok(new AuthResp("Auth successful!", utils.generateJwtToken(authenticatedDetails)));
		} catch (BadCredentialsException e) { // lab work : replace this by a method in global exc handler
			// send back err resp code
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
		}

	}
}
