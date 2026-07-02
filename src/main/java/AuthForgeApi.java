package com.authforge.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.*;

import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AuthForge - Enterprise Spring Boot REST API
 * * Upgrades the standard Java logic into a fully accessible web service.
 * Includes @Scheduled for automatic memory cleanup, @RestController for HTTP
 * handling, and strict authorization headers to protect your service.
 */
@SpringBootApplication
@EnableScheduling // Allows Spring to run background tasks like memory cleanup
@RestController
@RequestMapping("/api/otp")
@CrossOrigin(origins = "*")
public class AuthForgeApi {

    // --- YOUR CREDENTIALS (Loaded securely from environment variables) ---
    @org.springframework.beans.factory.annotation.Value("${SENDER_EMAIL}")
    private String senderEmail;

    @org.springframework.beans.factory.annotation.Value("${SENDER_APP_PASSWORD}")
    private String senderAppPassword;

    // Only apps with this key can use your API (Add more keys as you get more clients)
    @org.springframework.beans.factory.annotation.Value("${MASTER_API_KEY}")
    private String masterApiKey;

    private static final Map<String, OtpDetails> otpCache = new ConcurrentHashMap<>();
    private static final long OTP_VALIDITY_MS = 5 * 60 * 1000; // 5 Minutes
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) {
        SpringApplication.run(AuthForgeApi.class, args);
        System.out.println("[AuthForge] API Gateway is LIVE and listening on Port 8080.");
    }

    // --- API ENDPOINT 1: GENERATE & SEND OTP ---

    @PostMapping("/generate")
    public ResponseEntity<String> generateOtp(
            @RequestHeader(value = "Authorization", required = false) String apiKey,
            @RequestBody OtpRequest request) {

        // 1. Security Check
        if (!masterApiKey.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or missing API Key.");
        }
        if (request.email == null || !request.email.contains("@")) {
            return ResponseEntity.badRequest().body("Invalid email address format.");
        }

        // 2. Logic
        String otpCode = String.format("%06d", secureRandom.nextInt(999999));
        otpCache.put(request.email, new OtpDetails(otpCode, System.currentTimeMillis() + OTP_VALIDITY_MS));

        // 3. Dispatch
        boolean isSent = sendEmail(request.email, otpCode);
        if (isSent) {
            return ResponseEntity.ok("OTP generated and dispatched successfully.");
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to dispatch email.");
        }
    }

    // --- API ENDPOINT 2: VERIFY OTP ---

    @PostMapping("/verify")
    public ResponseEntity<String> verifyOtp(
            @RequestHeader(value = "Authorization", required = false) String apiKey,
            @RequestBody OtpVerificationRequest request) {

        // 1. Security Check
        if (!masterApiKey.equals(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid API Key.");
        }

        // 2. Logic
        OtpDetails details = otpCache.get(request.email);

        if (details == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("OTP not found or expired.");
        }

        if (System.currentTimeMillis() > details.expirationTime) {
            otpCache.remove(request.email);
            return ResponseEntity.status(HttpStatus.GONE).body("OTP has expired.");
        }

        if (details.otpCode.equals(request.otp)) {
            otpCache.remove(request.email); // Burn after reading!
            return ResponseEntity.ok("Verification Successful! Access Granted.");
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Verification Failed! Invalid OTP.");
    }

    // --- CORE EMAIL ENGINE ---

    private boolean sendEmail(String recipient, String otp) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(senderEmail, senderAppPassword);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
            message.setSubject("Your Secure Login OTP");

            String htmlContent = "<div style='font-family: sans-serif; padding: 20px;'>"
                    + "<h2 style='color: #2c3e50;'>Authentication Required</h2>"
                    + "<p>Your secure One-Time Password is:</p>"
                    + "<h1 style='color: #2980b9; letter-spacing: 5px;'>" + otp + "</h1>"
                    + "<p style='color: #7f8c8d; font-size: 12px;'>This code expires in 5 minutes.</p>"
                    + "</div>";

            message.setContent(htmlContent, "text/html; charset=utf-8");
            Transport.send(message);
            return true;
        } catch (MessagingException e) {
            e.printStackTrace();
            return false;
        }
    }

    // --- BACKGROUND MEMORY MANAGEMENT ---

    // Spring Boot automatically runs this every 60,000 milliseconds (1 minute)
    @Scheduled(fixedRate = 60000)
    public void cleanupExpiredOtps() {
        long now = System.currentTimeMillis();
        otpCache.entrySet().removeIf(entry -> now > entry.getValue().expirationTime);
        System.out.println("[System Cache] Swept expired OTPs from memory.");
    }

    // --- HELPER CLASSES FOR JSON PARSING ---

    static class OtpRequest {
        public String email;
    }

    static class OtpVerificationRequest {
        public String email;
        public String otp;
    }

    static class OtpDetails {
        final String otpCode;
        final long expirationTime;

        OtpDetails(String otpCode, long expirationTime) {
            this.otpCode = otpCode;
            this.expirationTime = expirationTime;
        }
    }
}