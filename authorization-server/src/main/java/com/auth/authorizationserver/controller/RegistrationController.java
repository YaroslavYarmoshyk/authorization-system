package com.auth.authorizationserver.controller;

import com.auth.authorizationserver.service.RegistrationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class RegistrationController {
    private final RegistrationService registrationService;

    public record RegistrationForm(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(max = 200) String displayName,
            @NotBlank @Size(min = 12, max = 128,
                    message = "Password should have at least 12 characters") String password) {
    }

    @GetMapping("/register")
    public String registerForm(@ModelAttribute("form") RegistrationForm form) {
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("form") RegistrationForm form, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "register";
        }
        try {
            registrationService.register(form.email(), form.displayName(), form.password());
        } catch (CompromisedPasswordException e) {
            bindingResult.rejectValue("password", "password.compromised", e.getMessage());
            return "register";
        }
        return "redirect:/register?submitted";
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam String token, Model model) {
        model.addAttribute("verified", registrationService.verify(token));
        return "verify-result";
    }
}
