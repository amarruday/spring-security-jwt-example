package com.securityjwt.service;

import com.securityjwt.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class AuthUser implements UserDetails {

    private Long userId;
    private String username;
    private String password;
    private String email;
    private String mobileNumber;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private String profilePic;
    private Set<Authority> authorities;

    public AuthUser(User user) {
        this.userId = user.getUserId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.email = user.getEmail();
        this.mobileNumber = user.getMobileNumber();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.enabled = user.isEnabled();
        this.profilePic = user.getProfilePic();
        Set<Authority> authSet = new HashSet<>();
        user.getUserRoles().forEach(userRole ->{
            authSet.add(new Authority(userRole.getRole().getrolename()));
        });
        this.authorities = authSet;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
