package io.imi.aot_test;

import io.imi.aot_test.entities.UserEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Collections;

@RestController
@RequestMapping(value = "/api/v5")
public class UserApi {

    @RequestMapping(value = "/users", method = RequestMethod.GET,
            produces = "application/json")
    @Transactional
    public Collection<UserEntity> search() {
        return Collections.singletonList(new UserEntity());
    }
}
