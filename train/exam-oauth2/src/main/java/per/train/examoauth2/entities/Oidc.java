package per.train.examoauth2.entities;

import java.time.LocalDate;
public record Oidc(String name, String phone, String picUrl, String locale, String gender, LocalDate birthday) {
}
