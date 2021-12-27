package com.tienngay.momopayment.entity;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    private String phone;

    public static User of (String name, String phone) {
        User user = new User();
        user.name = name;
        user.phone = phone;
        return user;
    }
}
