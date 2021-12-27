package com.tienngay.momopayment.service;

import com.tienngay.momopayment.entity.User;
import com.tienngay.momopayment.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public List<User> findUserByName(String name) {
        List<User> user = userRepository.findByName(name);
        return user;
    }
}
