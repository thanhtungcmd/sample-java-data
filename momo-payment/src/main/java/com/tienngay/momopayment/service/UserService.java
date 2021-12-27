package com.tienngay.momopayment.service;

import com.tienngay.momopayment.entity.User;

import java.util.List;

public interface UserService {

    List<User> findUserByName(String name);

}
