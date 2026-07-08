class AuthController {
    void login(String username, String password) {
        try {
            throw new RuntimeException("db failed");
        } catch (RuntimeException ex) {
            System.out.println("login failed for " + username);
            System.out.println("password=" + password);
            throw ex;
        }
    }

    String error(RuntimeException ex) {
        return ex.toString();
    }
}
