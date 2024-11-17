package com.example.buysell.services;

import com.example.buysell.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String email) {

        if(userRepository.findByEmail(email) == null){
            throw new UsernameNotFoundException("User not authorized.");
        }else {
            return userRepository.findByEmail(email);
        }

    }
}
