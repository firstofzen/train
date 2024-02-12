package per.train.examoauth2;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;

@SpringBootApplication
public class ExamOauth2Application {

    public static void main(String[] args) {

        SpringApplication.run(ExamOauth2Application.class, args);
    }

    @Bean
    ApplicationRunner runner1() {
        return args -> {

        };
    }

    @Bean
    public Dotenv loadEnv() {
        return Dotenv.load();
    }

}

@Configuration
@EnableWebFluxSecurity
class SecurityConfig {
    @Bean
    public SecurityWebFilterChain webFilterChain(ServerHttpSecurity security) {
        return security
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .authorizeExchange(exc -> exc.anyExchange().authenticated())
                .oauth2Login(Customizer.withDefaults())
                .oauth2Client(Customizer.withDefaults())
                .build();
    }
}
