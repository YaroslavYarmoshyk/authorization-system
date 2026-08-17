package com.auth.resourceserver.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    record Order(String id, String item, int quantity, String status) {
    }

    private static final List<Order> ORDERS = List.of(
            new Order("ord-1001", "Wireless Mouse", 2, "SHIPPED"),
            new Order("ord-1002", "Mechanical Keyboard", 1, "PROCESSING"),
            new Order("ord-1003", "USB-C Hub", 3, "DELIVERED"));

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    List<Order> listOrders(@AuthenticationPrincipal Jwt jwt) {
        log.info("Orders listed for subject={} roles={}", jwt.getSubject(), jwt.getClaimAsStringList("roles"));
        return ORDERS;
    }
}
