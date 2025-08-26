package com.org.SpringSecurity.Security;

import com.org.SpringSecurity.Model.AuthProviderType;
import com.org.SpringSecurity.Model.Users;
import com.org.SpringSecurity.Repository.UserRepo;
import com.org.SpringSecurity.dto.LoginRequestDto;
import com.org.SpringSecurity.dto.LoginresponseDto;
import com.org.SpringSecurity.dto.SignUpRequestDto;
import com.org.SpringSecurity.dto.SignUpResponseDto;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private UserRepo userRepo;
    @Autowired
    private JwtAuthUtil jwtService;
    private AuthenticationManager authenticationManager;
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);


    public LoginresponseDto verify(LoginRequestDto loginRequestDto) {
        Authentication authentication = authenticationManager.
                authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword()));
        Users user = (Users) authentication.getPrincipal();
        String token="";
        if(authentication.isAuthenticated()){
           token = jwtService.generateToken(user);
            System.out.println("login Succefully the token is:" + " " + token);
        }
        return new LoginresponseDto(token,user.getId());
    }

    public Users updatePassword(Users user) throws UsernameNotFoundException {
        Users currentUser = userRepo.findByUsername(user.getUsername());
        System.out.println("currentUser" + " " + currentUser);
        if(currentUser == null){
            System.out.println("UsernameNotFoundException 404 !");
             throw new UsernameNotFoundException( "UsernameNotFoundException 404!");
        }
        currentUser.setPassword(encoder.encode(user.getPassword()));
        return userRepo.save(currentUser);
    }

    public  Users signUpInternal(SignUpRequestDto signUpRequestDto, AuthProviderType authProviderType , String providerId) throws IllegalAccessException {
        Users user = userRepo.findByUsername(signUpRequestDto.getUsername());
        System.out.println("currentUser" + " " + user);

        if(user != null){
            throw  new IllegalAccessException("user Already Exists");
        }
         user = userRepo.save(Users
                         .builder()
                         .providerId(providerId)
                         .providerType(authProviderType)
                         .username(signUpRequestDto.getUsername())
                        .build());

        if(authProviderType == AuthProviderType.EMAIL){
            user.setPassword(encoder.encode(signUpRequestDto.getPassword()));
        }
        return  userRepo.save(user);
    }

    public SignUpResponseDto signup(SignUpRequestDto signUpRequestDto) {
        try{
            Users user = signUpInternal(signUpRequestDto, AuthProviderType.EMAIL,null);
            return  new SignUpResponseDto(user.getId(),user.getUsername());
        }catch (Exception ex){
            log.error("err : { }", ex.getMessage());
            throw new RuntimeException("err : { }" + "  "+  ex.getMessage());
        }

    }

    @Transactional
    public ResponseEntity<LoginresponseDto> handleOAuthLoginRequest(OAuth2User oAuth2User, String registrationId) throws IllegalAccessException {
        // 1) fetch provider Id and providerType
        System.out.println("Hello in the handleOAuthLoginRequest SCreen");

        AuthProviderType providerType= jwtService.getProviderTypeFromRegistrationId(registrationId);
        String providerId = jwtService.determineProviderIdFromOAuth2User(oAuth2User,registrationId);

        // Fetch user
        Users user = userRepo.findByProviderIdAndProviderType(providerId,providerType).orElse(null);
        //fetch email if exists (when trying to login via google github etc)
        String email = oAuth2User.getAttribute("email");
        Users  emailUser = userRepo.findByUsername(email);

        // 1st time user
        if(user == null && emailUser == null){
            //signUp flow
            String userName = jwtService.determineUsernameFromOAuth2User(oAuth2User,registrationId,providerId);
             user =  signUpInternal(new SignUpRequestDto(userName, null), providerType,providerId);
        }else if (user != null){
            // check wheather email matches with the username
            if(email != null && !email.isBlank() && !emailUser.equals(user.getUsername())){
                user.setUsername(email);
                userRepo.save(user);
            }
        }else {
            //user != null && email != null
            throw  new BadCredentialsException("This Email is already register with provider : "+ emailUser.getProviderId());
        }
        //login
        LoginresponseDto loginresponseDto = new LoginresponseDto(jwtService.generateToken(user), user.getId());
        return  ResponseEntity.ok(loginresponseDto);
    }
}
