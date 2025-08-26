package com.org.SpringSecurity.Security;

import com.org.SpringSecurity.Model.Users;
import com.org.SpringSecurity.Repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user =  userRepo.findByUsername(username);
        if(user == null){
            System.out.println("User Not Found 404@!");
            throw new UsernameNotFoundException("User Not Found 404@!");
        }

        return  new Users(user);
    }
}
