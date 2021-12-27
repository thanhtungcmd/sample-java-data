package com.tienngay.momopayment.controller;

import com.tienngay.momopayment.entity.User;
import com.tienngay.momopayment.libs.PGPHelper;
import com.tienngay.momopayment.repository.UserRepository;
import com.tienngay.momopayment.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/")
public class MomoController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    UserService userService;

    @GetMapping("")
    public ResponseEntity<String> home() {
        User data = User.of(
            "tungbt",
            "0942990834"
        );
        userRepository.save(data);
        return ResponseEntity.ok("1234");
    }

    @GetMapping("/user")
    public ResponseEntity<List<User>> user() {
        List<User> listUser = userService.findUserByName("tungbt");
        return ResponseEntity.ok(listUser);
    }

    @GetMapping("/user/delete")
    public ResponseEntity<Long> userDelete(
        @RequestParam Long id
    ) {
        userRepository.deleteById(id);
        return ResponseEntity.ok(id);
    }

    @PostMapping("/momo/encode")
    public ResponseEntity<String> encode(
        @RequestBody String body
    ) throws Exception {
        System.out.print(body);
        PGPHelper.init(
            "./conf/tienngay-sec.asc",
            "./conf/momo-pub.asc",
            "MT15/09/2021");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PGPHelper.getInstance().encryptAndSign(body.getBytes(StandardCharsets.UTF_8), baos);
        return ResponseEntity.ok(baos.toString());
    }

    @PostMapping("/momo/decode")
    public ResponseEntity<String> decode(
            @RequestBody String body
    ) throws Exception {
        PGPHelper.init(
            "./conf/tienngay-sec.asc",
            "./conf/momo-pub.asc",
            "MT15/09/2021");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PGPHelper.getInstance().decryptAndVerifySignature(body.getBytes(StandardCharsets.UTF_8), baos);
        return ResponseEntity.ok(baos.toString());
    }

}
