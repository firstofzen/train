package per.train.examoauth2.entities;


import java.util.UUID;

public record User(UUID id, String accessToken, String refreshToken,String email, Oidc oidc) {

}
