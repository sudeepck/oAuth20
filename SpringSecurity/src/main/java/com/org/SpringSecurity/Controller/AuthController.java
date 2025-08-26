package com.org.SpringSecurity.Controller;

import com.org.SpringSecurity.Model.Users;
import com.org.SpringSecurity.Security.AuthService;
import com.org.SpringSecurity.dto.LoginRequestDto;
import com.org.SpringSecurity.dto.LoginresponseDto;
import com.org.SpringSecurity.dto.SignUpRequestDto;
import com.org.SpringSecurity.dto.SignUpResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController("")
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponseDto> signup(@RequestBody SignUpRequestDto user) throws IllegalAccessException {
        System.out.println("hello");
        return  ResponseEntity.ok(authService.signup(user));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginresponseDto> login(@RequestBody LoginRequestDto user){
        return  ResponseEntity.ok(authService.verify(user));
    }

    @PutMapping("/updatePassword")
    public Users updatePassword(@RequestBody Users user){
        return authService.updatePassword(user);
    }
}
