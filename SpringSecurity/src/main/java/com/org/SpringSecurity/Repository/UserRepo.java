package com.org.SpringSecurity.Repository;

import com.org.SpringSecurity.Model.AuthProviderType;
import com.org.SpringSecurity.Model.Users;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface UserRepo extends JpaRepository<Users,Integer> {

    Users findByUsername(String username);

    Optional<Users> findByProviderIdAndProviderType(String providerId, AuthProviderType providerType);
}
