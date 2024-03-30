package io.imi.aot_test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ImportResource;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = "io.imi.aot_test")
@EnableJpaRepositories("io.imi.aot_test")
@EntityScan("io.imi.aot_test.entities")
public class AotTestApplication {
	public static void main(String[] args) {
		SpringApplication.run(AotTestApplication.class, args);
	}
}
