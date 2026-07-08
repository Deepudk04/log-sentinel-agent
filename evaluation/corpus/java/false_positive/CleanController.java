class CleanController {
    private static final org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(CleanController.class);

    String login(String username) {
        logger.warn("login failed for user={}", username);
        return "request failed";
    }
}
