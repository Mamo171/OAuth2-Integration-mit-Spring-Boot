package com.example.oauth2_example.config;

import com.example.oauth2_example.service.CustomAuthorizationRequestResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // Markiert diese Klasse als Konfigurationsklasse für Spring.
public class SecurityConfig {

    /**
     * Konfiguriert die Sicherheitsregeln für die Anwendung.
     * @param http HTTP-Sicherheitskonfiguration von Spring Security.
     * @param clientRegistrationRepository Repository für die Registrierung von OAuth2-Clients.
     * @return Ein SecurityFilterChain-Bean, das die Sicherheitskonfiguration definiert.
     * @throws Exception Falls bei der Konfiguration ein Fehler auftritt.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        http
                // Konfiguration der Autorisierungsregeln
                .authorizeHttpRequests(auth -> auth
                        // Diese Endpunkte sind für alle Benutzer öffentlich zugänglich.
                        .requestMatchers("/", "/login", "/css/**", "/js/**").permitAll()
                        // Alle anderen Anfragen erfordern eine Authentifizierung.
                        .anyRequest().authenticated()
                )
                // Konfiguration des OAuth2-Login-Mechanismus
                .oauth2Login(oauth -> oauth
                        // Definiert eine benutzerdefinierte Login-Seite.
                        .loginPage("/login")
                        // Erfolgreicher Login leitet den Benutzer auf das Dashboard weiter.
                        .defaultSuccessUrl("/dashboard", true)
                        // Konfiguriert benutzerdefinierte OAuth2-Anfrageparameter.
                        .authorizationEndpoint(authEndpoint -> authEndpoint
                                // Fügt einen benutzerdefinierten Resolver hinzu, um zusätzliche Parameter wie `access_type=offline` hinzuzufügen.
                                .authorizationRequestResolver(new CustomAuthorizationRequestResolver(
                                        clientRegistrationRepository, "/oauth2/authorization"
                                ))
                        )
                )
                // Konfiguration des Logout-Mechanismus
                .logout(logout -> logout
                        // Nach dem Logout wird der Benutzer auf die Startseite weitergeleitet.
                        .logoutSuccessUrl("/")
                );

        // Baut und gibt die Sicherheitskonfiguration zurück.
        return http.build();
    }
}
