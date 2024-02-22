package per.train.examoauth2;

import com.datastax.oss.driver.api.core.data.UdtValue;
import org.springframework.stereotype.Component;
import per.train.examoauth2.entities.Oidc;
@Component
record Mapper() {
    public Oidc convert(UdtValue value) {
        return new Oidc(
                value.getString("name"),
                value.getString("phone"),
                value.getString("picUrl"),
                value.getString("locale"),
                value.getString("gender"),
                value.getString("birthday")
        );
    }
}
