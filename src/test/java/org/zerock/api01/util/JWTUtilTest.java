package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;


@SpringBootTest
@Log4j2
class JWTUtilTest {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    void testGenerate() {

        Map<String, Object> claimMap = Map.of("mid", "ABCDE");

        String jwtStr = jwtUtil.generateToken(claimMap, 1);

        log.info(jwtStr);

    }

    @Test
    void testValidate() {

        //유효 시간이 지난 토큰
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MjUzNDY2ODIsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNzI1MzQ2NjIyfQ.2CiOMDPn_Y0HdI9KmxwK8SFwgM68uZ2j-lu7e1VA0Ek";

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);

        log.info(claim);
    }

    @Test
    void testAll() {

        String jwtStr = jwtUtil.generateToken(Map.of("mid", "AAAA", "email", "aaaa@bbb.com"), 1);

        log.info(jwtStr);

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);

        log.info("MID: " + claim.get("mid"));

        log.info("EMAIL: " + claim.get("email"));
    }

}