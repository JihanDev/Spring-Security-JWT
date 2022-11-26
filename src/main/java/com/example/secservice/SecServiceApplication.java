package com.example.secservice;

import com.example.secservice.sec.entities.AppRole;
import com.example.secservice.sec.entities.AppUser;
import com.example.secservice.sec.services.AccountServiceImpl;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.ArrayList;
@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecServiceApplication.class, args);
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner start(AccountServiceImpl  accountService) {
        return args -> {
            accountService.addRole(new AppRole(null, "USER"));
            accountService.addRole(new AppRole(null, "CUSTOMER_MANAGER"));
            accountService.addRole(new AppRole(null, "ADMIN"));
            accountService.addRole(new AppRole(null, "PRODUCT_MANAGER"));
            accountService.addRole(new AppRole(null, "BILLS_MANAGER"));

            accountService.addUser(new AppUser(null, "John Doe", "user1", "1234", new ArrayList<>()));
            accountService.addUser(new AppUser(null, "Will Smoth", "admin", "1234", new ArrayList<>()));
            accountService.addUser(new AppUser(null, "Jim Carry", "user2", "1234", new ArrayList<>()));
            accountService.addUser(new AppUser(null, "Arnold Schwazenegger", "user3", "1234", new ArrayList<>()));
            accountService.addUser(new AppUser(null, "Jane Doe", "user4", "1234", new ArrayList<>()));

            accountService.addRoleToUser("user1", "USER");
            accountService.addRoleToUser("admin", "USER");
            accountService.addRoleToUser("admin", "ADMIN");
            accountService.addRoleToUser("user2", "USER");
            accountService.addRoleToUser("user2", "CUSTOMER_MANAGER");
            accountService.addRoleToUser("user3", "USER");
            accountService.addRoleToUser("user3", "PRODUCT_MANAGER");
            accountService.addRoleToUser("user4", "USER");
            accountService.addRoleToUser("user4", "BILLS_MANAGER");


        };
    }
}
