package com.example.secservice.sec.services;

import com.example.secservice.sec.entities.AppRole;
import com.example.secservice.sec.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addUser(AppUser user);
    AppRole addRole(AppRole role);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> getUsers();
}
