package com.tienngay.momopayment.repository;

import com.tienngay.momopayment.entity.User;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends BaseRepository<User, Long> {

    List<User> findByName(String name);

}
