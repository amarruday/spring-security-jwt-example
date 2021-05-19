package com.securityjwt.controller;

import com.securityjwt.commons.JwtUtils;
import com.securityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/")
    public String dashboard(){
        return "Public Dashboard";
    }

    @GetMapping("/secured")
    public String securedApi(){
        return "Secured API";
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> getAllUsers(){
        return ResponseEntity.ok().body(userRepo.findAll());
    }

    @PostMapping("/authenticate")
    public String generateToken(@RequestBody AuthRequest authRequest) throws Exception {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (Exception e) {
            throw new Exception("Invalid Username or Password");
        }

        String token = jwtUtils.generateToken(authRequest.getUsername());
        return token;
    }

    @GetMapping("/onlyuser")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String onlyUser(){
        return "Only user can access this URL";
    }

    @GetMapping("/onlymoderator")
    @PreAuthorize("hasAuthority('ROLE_MODERATOR')")
    public String onlyModerator() {
        return "Only Moderator can access this URL";
    }
}
