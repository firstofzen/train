package per.train.examoauth2;

import com.datastax.oss.driver.api.core.CqlIdentifier;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.PagingIterable;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import per.train.examoauth2.entities.Oidc;
import per.train.examoauth2.entities.User;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;

import static org.springframework.web.reactive.function.server.RouterFunctions.route;

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

    @Bean(name = "cqlSession")
    public CqlSession cqlSession() {
        return CqlSession.builder().withKeyspace(CqlIdentifier.fromCql("train")).build();
    }

    @Bean
    public Dotenv loadEnv() {
        return Dotenv.load();
    }

}

@Configuration
@EnableWebFluxSecurity
class SecurityConfig {
    private final MyWebFilter webFilter;

    SecurityConfig(MyWebFilter webFilter) {
        this.webFilter = webFilter;
    }

    @Bean
    public SecurityWebFilterChain webFilterChain(ServerHttpSecurity security) {
        return security
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .authorizeExchange(exc -> {
                    exc.pathMatchers("/loginAT/**").permitAll();
                    exc.anyExchange().authenticated();
                })
                .oauth2Login(Customizer.withDefaults())
                .oauth2Client(Customizer.withDefaults())
                .addFilterBefore(webFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public JwtBearerReactiveOAuth2AuthorizedClientProvider jwtBear() {
        return new JwtBearerReactiveOAuth2AuthorizedClientProvider();
    }
}

@Configuration
class Api {
    private final ApiHandler apiHandler;

    Api(ApiHandler apiHandler) {
        this.apiHandler = apiHandler;
    }

    @Bean
    public RouterFunction<ServerResponse> login() {
        return route().GET("/getuser", apiHandler::home).build();
    }

    @Bean
    public RouterFunction<ServerResponse> loginByAT() {
        return route().GET("/loginAT", apiHandler::loginAT).build();
    }
}

@Component
class ApiHandler {
    private final UserRepository repository;

    ApiHandler(UserRepository repository) {
        this.repository = repository;
    }

    public Mono<ServerResponse> home(ServerRequest request) {
        return ReactiveSecurityContextHolder.getContext().map(c -> c.getAuthentication().getPrincipal()).map(p -> (OidcUser) p).flatMap(usr -> {
            if (repository.checkUserExistByEmail(usr.getEmail())) {
                System.out.println("getting...");
                return repository.getUserByEmail(usr.getEmail());
            } else {
                System.out.println("adding...");
                return repository.addUser(new Oidc(usr.getName(), usr.getUserInfo().getPhoneNumber(), usr.getUserInfo().getPicture(), usr.getUserInfo().getLocale(), usr.getUserInfo().getGender(), usr.getUserInfo().getBirthdate()), usr.getEmail());
            }
        }).flatMap(o -> o.map(user -> ServerResponse.ok().bodyValue(user)).orElseGet(() -> ServerResponse.badRequest().bodyValue("user not found")));
    }

    public Mono<ServerResponse> loginAT(ServerRequest request) {
        var at = request.queryParam("accesstoken");
        System.out.println("login with accesstoken");
        return at.map(s -> repository.getUserByAT(s).flatMap(usr -> ServerResponse.ok().bodyValue(usr))).orElseGet(() -> ServerResponse.badRequest().bodyValue("accesstoken is invalid"));
    }
}

@Component
class UserRepository {
    @Qualifier("cqlSession")
    private final CqlSession cqlSession;
    private final Mapper mapper;

    UserRepository(CqlSession cqlSession, Mapper mapper) {
        this.cqlSession = cqlSession;
        this.mapper = mapper;
    }

    public Mono<Optional<User>> addUser(Oidc oidc, String email) {
        var id = UUID.randomUUID();
        var accessToken = UUID.randomUUID();
        var refreshToken = UUID.randomUUID();
        String stmt = "insert into train.user(id, email, oidc, refreshtoken, accesstoken) values" +
                "(" +
                id + "," +
                "'" + email + "'" + "," +
                "{" +
                "name: '" + oidc.name() + "'" + "," +
                "gender: '" + oidc.gender() + "'" + "," +
                "locale: '" + oidc.locale() + "'" + "," +
                "picurl: '" + oidc.picUrl() + "'" + "," +
                "phone: " + "'" + oidc.phone() + "'" + "," +
                "birthday: '" + oidc.birthday() + "'" +
                "}" + "," + "'" +
                refreshToken + "'" + "," +
                "'" + accessToken + "'" +
                ");";
        var rs = cqlSession.execute(stmt);
        if (rs.wasApplied()) {
            return Mono.just(new User(id, accessToken.toString(), refreshToken.toString(), email, oidc)).map(Optional::of);
        } else {
            return Mono.just(Optional.empty());
        }
    }

    public Mono<ResultSet> getAllUser() {
        return Mono.just(cqlSession.execute("select * from train.user;"));
    }

    public Mono<String> getRFTokenById(String id) {
        String stmt = "select refreshtoken from train.user where id=" + id + " ALLOW FILTERING;";
        return Mono.just(cqlSession.execute(stmt)).map(rs -> {
            if (rs.one() != null) {
                var rfTok = rs.one().getString("refreshtoken");
                if (rfTok != null) {
                    return rfTok;
                }
            }
            return "";
        });
    }

    public Mono<String> addAccessTokenById(String id, String accessToken) {
        String stmt = "update train.user using ttl 600 set accesstoken=" +
                "'" + accessToken + "'" + " where id=" + id + ";";

        var rs = cqlSession.execute(stmt);
        if (rs.wasApplied()) {
            return Mono.just(accessToken);
        } else {
            return Mono.just("");
        }
    }

    public Mono<String> getAccessTokenById(String id) {
        String stmt = "select accesstoken from train.user where id=" + id + " ALLOW FILTERING;";
        return Mono.just(cqlSession.execute(stmt)).map(rs -> {
            if (rs.one() != null) {
                var rfTok = rs.one().getString("accesstoken");
                if (rfTok != null) {
                    return rfTok;
                }
            }
            return "";
        });
    }

    public Mono<Optional<User>> getUserByEmail(String email) {
        String stmt = "select * from train.user where email=" + "'" + email + "'" + " ALLOW FILTERING" + ";";
        return Mono.just(cqlSession.execute(stmt)).map(PagingIterable::one).map(rs -> {
            if (rs != null) {
                return Optional.of(new User(rs.getUuid("id"), rs.getString("accesstoken"), rs.getString("refreshtoken"), rs.getString("email"), mapper.convert(rs.getUdtValue("oidc"))));
            } else {
                return Optional.empty();
            }
        });
    }

    public Mono<Optional<User>> getUserByAT(String at) {
        String stmt = "select * from train.user where accesstoken='" + at + "' allow filtering;";
        return Mono.just(cqlSession.execute(stmt).one()).map(rs -> {
            if (rs != null) {
                return Optional.of(new User(rs.getUuid("id"), rs.getString("accesstoken"), rs.getString("refreshtoken"), rs.getString("email"), mapper.convert(rs.getUdtValue("oidc"))));
            } else {
                return Optional.empty();
            }
        });
    }

    public Boolean checkUserExistByEmail(String email) {
        String stmt = "select count(*) from train.user where email=" + "'" + email + "'" + " ALLOW FILTERING" + ";";
        var lr = cqlSession.execute(stmt).one().getLong(0);
        return lr > 0;
    }

    public Boolean checkATExist(String at) {
        String stmt = "select count(*) from train.user where accesstoken='" + at + "' allow filtering;";
        var rs = cqlSession.execute(stmt).one().getLong("count");
        return rs > 0;
    }
}

@Component
class MyWebFilter implements org.springframework.web.server.WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if(exchange.getRequest().getQueryParams().containsKey("accesstoken")) {
            var newReq = exchange.getRequest().mutate().path("/loginAT").build();
            chain.filter(exchange.mutate().request(newReq).build());
        }
        return chain.filter(exchange);
    }
}