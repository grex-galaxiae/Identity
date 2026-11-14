package br.app.coeur.identity.core.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health(HttpServletRequest request) {
        request.setAttribute("skipHealthAccessLog", Boolean.TRUE);
        return Map.of("status", "UP");
    }
}
