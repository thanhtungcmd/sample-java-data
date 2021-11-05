package com.tienngay.momopayment.controller;

import com.tienngay.momopayment.dto.Encode;
import com.tienngay.momopayment.libs.PGPHelper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/")
public class MomoController {

    @GetMapping("")
    public ResponseEntity<String> home() {
        return ResponseEntity.ok("123");
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
