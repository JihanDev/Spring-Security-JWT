package com.example.secservice.sec.repository;
import com.example.secservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends  JpaRepository<AppUser,Long> {
        AppUser findByUsername(String username);
}
