package per.train.examoauth2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import per.train.examoauth2.entities.Oidc;
import per.train.examoauth2.entities.User;

import java.time.LocalDate;
import java.util.Objects;

@SpringBootTest
class ExamOauth2ApplicationTests {
	@Autowired UserRepository repository;

	@Test
	void contextLoads() {
	}

}
