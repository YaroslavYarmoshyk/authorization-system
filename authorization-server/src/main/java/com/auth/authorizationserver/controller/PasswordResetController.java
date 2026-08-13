package com.auth.authorizationserver.controller;

import com.auth.authorizationserver.service.PasswordResetService;
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
public class PasswordResetController {
    private final PasswordResetService passwordResetService;

    public record ForgotPasswordForm(@NotBlank @Email @Size(max = 320) String email) {
    }

    public record ResetPasswordForm(
            @NotBlank String token,
            @NotBlank @Size(min = 12, max = 128,
                    message = "Password should have at least 12 characters") String password) {
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordForm(@ModelAttribute("form") ForgotPasswordForm form) {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String forgotPassword(@Valid @ModelAttribute("form") ForgotPasswordForm form,
                                 BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "forgot-password";
        }
        passwordResetService.requestReset(form.email());
        return "redirect:/forgot-password?submitted";
    }

    @GetMapping("/reset-password")
    public String resetPasswordForm(@RequestParam(defaultValue = "") String token, Model model) {
        if (!passwordResetService.isTokenValid(token)) {
            model.addAttribute("invalidToken", true);
        }
        model.addAttribute("form", new ResetPasswordForm(token, null));
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String resetPassword(@Valid @ModelAttribute("form") ResetPasswordForm form,
                                BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "reset-password";
        }
        try {
            if (!passwordResetService.reset(form.token(), form.password())) {
                model.addAttribute("invalidToken", true);
                return "reset-password";
            }
        } catch (CompromisedPasswordException e) {
            bindingResult.rejectValue("password", "password.compromised", e.getMessage());
            return "reset-password";
        }
        return "redirect:/login?reset";
    }
}
