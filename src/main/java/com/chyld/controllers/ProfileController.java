package com.chyld.controllers;

import com.chyld.dtos.AuthDto;
import com.chyld.entities.Profile;
import com.chyld.entities.Role;
import com.chyld.entities.User;
import com.chyld.enums.RoleEnum;
import com.chyld.security.JwtToken;
import com.chyld.utilities.JwtUtil;
import com.chyld.services.RoleService;
import com.chyld.services.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.security.Principal;
import java.util.ArrayList;

@RestController
@RequestMapping("/profiles")
public class ProfileController {

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(value = "", method = RequestMethod.POST)
    public ResponseEntity<?> createProfile(@RequestBody Profile profile, Principal user) {
        int uid = ((JwtToken)user).getUserId();
        User u = userService.findUserById(uid);

        if(u.getProfile() == null){
            u.setProfile(profile);
            profile.setUser(u);
        } else {
            u.getProfile().setAge(profile.getAge());
            u.getProfile().setGender(profile.getGender());
            u.getProfile().setPhoto(profile.getPhoto());
            u.getProfile().setHeight(profile.getHeight());
            u.getProfile().setWeight(profile.getWeight());
        }

        userService.saveUser(u);
        return ResponseEntity.status(HttpStatus.CREATED).body(null);
    }

    @RequestMapping(value = "", method = RequestMethod.GET)
    public Profile getProfile(Principal user) {
        int uid = ((JwtToken)user).getUserId();
        User u = userService.findUserById(uid);
        return u.getProfile();
    }
}
