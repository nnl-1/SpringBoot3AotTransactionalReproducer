package io.imi.aot_test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class Ref {

    @Autowired
    private UserRepository userRepository;
}
