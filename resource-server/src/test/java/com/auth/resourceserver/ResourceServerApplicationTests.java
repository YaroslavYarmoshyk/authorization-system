package com.auth.resourceserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = "AUTHORIZATION_ISSUER=http://localhost:9000")
class ResourceServerApplicationTests {

    @Test
    void contextLoads() {
    }
}
