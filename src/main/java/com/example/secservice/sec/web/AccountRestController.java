package com.example.secservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.secservice.sec.JWTUtil;
import com.example.secservice.sec.entities.AppRole;
import com.example.secservice.sec.entities.AppUser;
import com.example.secservice.sec.services.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class AccountRestController {
    private final AccountService accountService;
    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> listUsers(){
        return  accountService.getUsers();

    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public  AppUser saveUser(@RequestBody  AppUser user){
        return  accountService.addUser(user);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole role){

        return  accountService.addRole(role);
    }

    @PostMapping("/roles/addtouser")
    public  void addRoleToUser(@RequestBody RoleToUser form){

        accountService.addRoleToUser(form.getUsername(),form.getRoleName());
    }
    @GetMapping("/refreshToken")
    public  void  refreshToken(HttpServletRequest request, HttpServletResponse response) throws  Exception{
        String authToken=request.getHeader(JWTUtil.AUTH_HEADER);
        if(authToken != null && authToken.startsWith(JWTUtil.PREFIX)){

            try {
                String refreshToken=authToken.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm=Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT =jwtVerifier.verify(refreshToken);
                String username=decodedJWT.getSubject();
                AppUser appUser=accountService.loadUserByUsername(username);
                //créer un nouveau access token
                String jwtAccessToken= JWT.create().withSubject(appUser.getUsername()).
                        withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken =  new HashMap<>();
                idToken.put("access-token",jwtAccessToken);
                idToken.put("refresh-token",refreshToken);
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
                response.setContentType("application/json");
            }

            catch (Exception e){
                throw e;
                //response.setHeader("Error-message",e.getMessage());
                //forbidden 403
                //response.sendError(HttpServletResponse.SC_FORBIDDEN);

            }
        }
        else {

            throw  new RuntimeException("Refresh token required");
        }

    }
    @GetMapping("/profile")
    public  AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }
}

@Data
class  RoleToUser{
    private String username;
    private  String roleName;
}

