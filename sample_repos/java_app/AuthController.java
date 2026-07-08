package sample;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    public ResponseEntity<String> login(Request request) {
        try {
            String token = request.getHeader("Authorization");
            log.info("failed login token=" + token);
            return ResponseEntity.status(401).body("denied");
        } catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }

    public void importUsers(Request request) {
        try {
            runImport(request.getBody());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void runImport(String body) {
        throw new RuntimeException("not implemented");
    }
}
