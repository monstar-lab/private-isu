package lab.monstar;

import lombok.Data;
import org.eclipse.jetty.http.HttpStatus;
import org.sql2o.Connection;
import org.sql2o.Sql2o;
import spark.*;
import spark.template.thymeleaf.ThymeleafTemplateEngine;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static spark.Spark.*;

public class Application {
    private static final int POSTS_PER_PAGE = 20;
    private static Sql2o sql2o;
    private static final int UPLOAD_LIMIT = 10 * 1024 * 1024;

    public static void main(String[] args) {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");

            String host = System.getenv("ISUCONP_DB_HOST");
            if (host == null || host.equals("")) {
                host = "localhost";
            }

            String port = System.getenv("ISUCONP_DB_PORT");
            if (port == null || port.equals("")) {
                port = "3306";
            }

            String user = System.getenv("ISUCONP_DB_USER");
            if (user == null || user.equals("")) {
                user = "root";
            }

            String password = System.getenv("ISUCONP_DB_PASSWORD");

            String dbName = System.getenv("ISUCONP_DB_NAME");

            if (dbName == null || dbName.equals("")) {
                dbName = "isuconp";
            }

            sql2o = new Sql2o(String.format("jdbc:mysql://%s:%s/%s?useSSL=false", host, port, dbName), user, password);
            new Application();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    Application() {
        Spark.ipAddress("127.0.0.1");
        Spark.port(8080);
        Spark.staticFileLocation("/public");
        get("/initialize", this::getInitialize);
        get("/login", this::getLogin);
        post("/login", this::postLogin);
        get("/register", this::getRegister);
        post("/register", this::postRegister);
        get("/logout", this::getLogout);
        get("/posts", this::getPosts);
        get("/posts/:id", this::getPostsId);
        get("/image/:id", this::getImage);
        post("/comment", this::postComment);
        get("/admin/banned", this::getAdminBanned);
        post("/admin/banned", this::postAdminBanned);
        get("/:account_name", this::getAccountName);
        get("/", this::getIndex);
        post("/", this::postIndex);
    }

    @Data
    class User {
        Integer id;
        String account_name;
        String passhash;
        Boolean authority;
        Boolean del_flg;
        Date created_at;
    }

    @Data
    class Post {
        Integer id;
        Integer user_id;
        byte[] imgdata;
        String body;
        String mime;
        Date created_at;
        Integer comment_count;
        Comment[] comments;
        User user;
        String csrf_token;

        public String formatDate() {
            SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
            format.setTimeZone(TimeZone.getTimeZone("Asia/Tokyo"));
            return format.format(created_at);
        }

        public String imageURL() {
            String ext = "";

            if (mime.equals("image/jpeg")) {
                ext = ".jpg";
            } else if (mime.equals("image/png")) {
                ext = ".png";
            } else if (mime.equals("image/gif")) {
                ext = ".gif";
            }

            return "image/" + id + ext;
        }
    }

    @Data
    class Comment {
        Integer id;
        Integer post_id;
        Integer user_id;
        String comment;
        Date created_at;
        User user;
    }

    private void dbInitialize() {
        try (Connection connection = sql2o.beginTransaction()) {
            Arrays.asList("DELETE FROM users WHERE id > 1000",
                    "DELETE FROM posts WHERE id > 10000",
                    "DELETE FROM comments WHERE id > 100000",
                    "UPDATE users SET del_flg = false",
                    "UPDATE users SET del_flg = true WHERE id % 50 = 0")
                    .forEach((str) -> {
                        connection.createQuery(str).executeUpdate();
                    });
            connection.commit();
        }
    }

    private User tryLogin(String accountName, String password) throws IOException, InterruptedException {
        User user;
        try (Connection connection = sql2o.open()) {
            user = connection
                    .createQuery("SELECT * FROM users WHERE account_name = :account_name and del_flg = false")
                    .addParameter("account_name", accountName)
                    .executeAndFetchFirst(User.class);
        }
        if (user == null) {
            return null;
        }

        if (user.passhash.equals(calculatePassHash(user.account_name, password))) {
            return user;
        } else {
            return null;
        }
    }

    private boolean validateUser(String accountName, String password) {
        if (Pattern.compile("^[0-9a-zA-Z_]{3,}").matcher(accountName).matches()) {
            if (Pattern.compile("^[0-9a-zA-Z_]{6,}").matcher(password).matches()) {
                return true;
            }
        }
        return false;
    }

    private String digest(String src) throws IOException, InterruptedException {
        String[] command = {"sh", "-c", "printf  \"%s\" " + src + " | openssl dgst -sha512 | sed 's/^.*= //'"};

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process = processBuilder.start();
        process.waitFor();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                sb.append(line);
            }
        }

        return sb.toString();

    }

    private String calculateSalt(String accountName) throws IOException, InterruptedException {
        return digest(accountName);
    }

    private String calculatePassHash(String accountName, String password) throws IOException, InterruptedException {
        return digest(password + ":" + calculateSalt(accountName));
    }

    private Session getSession(Request request) {
        return request.session();
    }

    private User getSessionUser(Request request) {
        Session session = getSession(request);
        Object userId = session.attribute("user_id");

        if (userId == null) {
            return new User();
        }

        User user;

        try (Connection connection = sql2o.open()) {
            user = connection
                    .createQuery("SELECT * FROM users where id = :user_id")
                    .addParameter("user_id", userId)
                    .executeAndFetchFirst(User.class);
        }

        if (user == null) {
            return new User();
        }

        return user;
    }

    private String getFlash(Request request, String key) {
        Session session = getSession(request);
        Object value = session.attribute(key);

        if (value == null) {
            return "";
        } else {
            session.removeAttribute(key);
            return value.toString();
        }
    }

    private List<Post> makePosts(List<Post> results, String csrfToken, boolean allComments) {
        List<Post> posts = new ArrayList<>();

        for (Post post : results) {
            Integer commentCount;
            try (Connection connection = sql2o.open()) {
                commentCount = connection
                        .createQuery("SELECT COUNT(*) FROM comments WHERE post_id = :post_id")
                        .addParameter("post_id", post.id)
                        .executeScalar(Integer.class);

                String query = "SELECT * FROM comments WHERE post_id = :post_id ORDER BY created_at DESC";
                if (!allComments) {
                    query += " LIMIT 3";
                }

                List<Comment> comments;

                comments = connection.createQuery(query).addParameter("post_id", post.id).executeAndFetch(Comment.class);

                for (Comment comment : comments) {
                    comment.user = connection
                            .createQuery("SELECT * FROM users where id = :id")
                            .addParameter("id", comment.user_id)
                            .executeAndFetchFirst(User.class);
                }

                Collections.reverse(comments);

                post.comments = comments.toArray(new Comment[0]);

                post.user = connection
                        .createQuery("SELECT * FROM users WHERE id = :id")
                        .addParameter("id", post.user_id)
                        .executeAndFetchFirst(User.class);

                post.csrf_token = csrfToken;

                if (!post.user.del_flg) {
                    posts.add(post);
                }

                if (posts.size() >= POSTS_PER_PAGE) {
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw e;
            }
        }

        return posts;
    }

    private boolean isLogin(User user) {
        return user.id != null;
    }

    private String getCSRFToken(Request request) {
        Session session = getSession(request);
        Object csrfToken = session.attribute("csrf_token");

        if (csrfToken == null) {
            return "";
        }

        return csrfToken.toString();
    }

    private String secureRandomStr(int b) {
        byte[] bytes = new byte[b];
        new Random().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte by : bytes) {
            sb.append(by);
        }
        return sb.toString();
    }

    private String getInitialize(Request request, Response response) {
        dbInitialize();
        response.status(HttpStatus.OK_200);
        return "";
    }

    String getLogin(Request request, Response response) {
        User user = getSessionUser(request);

        if (isLogin(user)) {
            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        Map<String, Object> model = new HashMap<>();
        model.put("me", user);
        model.put("notice", getFlash(request, "notice"));
        model.put("content", "login");

        return render(model, request);
    }

    Object postLogin(Request request, Response response) throws IOException, InterruptedException {
        if (isLogin(getSessionUser(request))) {
            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        User user = tryLogin(request.queryParams("account_name"), request.queryParams("password"));

        if (user != null) {
            Session session = getSession(request);
            session.attribute("user_id", user.id);
            session.attribute("csrf_token", secureRandomStr(16));

            response.redirect("/", HttpStatus.FOUND_302);
        } else {
            Session session = getSession(request);
            session.attribute("notice", "アカウント名かパスワードが間違っています");

            response.redirect("/login", HttpStatus.FOUND_302);
        }
        return null;
    }

    String getRegister(Request request, Response response) {
        if (isLogin(getSessionUser(request))) {
            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        Map<String, Object> model = new HashMap<>();
        model.put("user", new User());
        model.put("notice", getFlash(request, "notice"));
        model.put("content", "register");

        return render(model, request);
    }

    Object postRegister(Request request, Response response) {
        if (isLogin(getSessionUser(request))) {
            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        String accountName = request.queryParams("account_name");
        String password = request.queryParams("password");

        if (!validateUser(accountName, password)) {
            Session session = getSession(request);
            session.attribute("notice", "アカウント名は3文字以上、パスワードは6文字以上である必要があります");

            response.redirect("/register", HttpStatus.FOUND_302);
            halt();
        }

        Integer exists = 0;

        try (Connection connection = sql2o.open()) {
            exists = connection.createQuery("SELECT 1 FROM users WHERE account_name = :account_name")
                    .addParameter("account_name", accountName)
                    .executeScalar(Integer.class);
        }

        if (exists != null && exists == 1) {
            Session session = getSession(request);
            session.attribute("notice", "アカウント名がすでに使われています");

            response.redirect("/register", HttpStatus.FOUND_302);
            halt(HttpStatus.FOUND_302);
        }

        try (Connection connection = sql2o.open()) {
            connection.createQuery("INSERT INTO users (account_name, passhash) VALUES (:account_name, :password)")
                    .addParameter("account_name", accountName)
                    .addParameter("password", calculatePassHash(accountName, password))
                    .executeUpdate();
            User user =connection.createQuery("SELECT * FROM users WHERE account_name = :account_name ORDER BY created_at DESC")
                    .addParameter("account_name", accountName)
                    .executeAndFetchFirst(User.class);

            Session session = getSession(request);
            session.attribute("user_id", user.id);
            session.attribute("csrf_token", secureRandomStr(16));

            response.redirect("/", HttpStatus.FOUND_302);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.INTERNAL_SERVER_ERROR_500);
        }

        return null;
    }

    Object getLogout(Request request, Response response) {
        Session session = getSession(request);
        session.removeAttribute("user_id");

        response.redirect("/", HttpStatus.FOUND_302);
        return null;
    }

    String getIndex(Request request, Response response) {
        User user = getSessionUser(request);

        List<Post> result = new ArrayList<>();

        try (Connection connection = sql2o.open()) {
            result = connection.createQuery("SELECT id, user_id, body, mime, created_at FROM posts ORDER BY created_at DESC")
                    .executeAndFetch(Post.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.INTERNAL_SERVER_ERROR_500);
        }

        List<Post> posts = makePosts(result, getCSRFToken(request), false);

        Map<String, Object> model = new HashMap<>();
        model.put("me", user);
        model.put("posts", posts);
        model.put("csrf_token", getCSRFToken(request));
        model.put("notice", getFlash(request, "notice"));
        model.put("content", "index");

        return render(model, request);
    }

    String getAccountName(Request request, Response response) {
        String accountName = request.params("account_name");

        // @とパラメータ名を含むuriをSpark frameworkのルーティングに認識させる方法がわからなかったので...
        if (!accountName.startsWith("@")) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        accountName = accountName.replace("@", "");

        User user = new User();

        try (Connection connection = sql2o.open()) {
            user = connection.createQuery("SELECT * FROM users WHERE account_name = :account_name AND del_flg = false")
                    .addParameter("account_name", accountName)
                    .executeAndFetchFirst(User.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        if (user.id == null) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        List<Post> result = new ArrayList<>();

        try (Connection connection = sql2o.open()) {
            result = connection.createQuery("SELECT id, user_id, body, mime, created_at FROM posts WHERE user_id = :user_id ORDER BY created_at DESC")
                    .addParameter("user_id", user.id)
                    .executeAndFetch(Post.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        List<Post> posts = makePosts(result, getCSRFToken(request), false);

        int commentCount = 0;

        try (Connection connection = sql2o.open()) {
            commentCount = connection
                    .createQuery("SELECT COUNT(*) FROM comments WHERE user_id = :user_id")
                    .addParameter("user_id", user.id)
                    .executeScalar(Integer.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        List<Integer> postIds = new ArrayList<>();

        try (Connection connection = sql2o.open()) {
            postIds = connection.createQuery("SELECT id FROM posts WHERE user_id = :user_id")
                    .addParameter("user_id", user.id)
                    .executeAndFetch(Integer.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        int postCount = postIds.size();

        int commentedCount = 0;

        if (postCount > 0) {
            List<String> s = new ArrayList<>();

            String args = "";
            for (int i = 0; i < postIds.size(); i++) {
                if (i != 0) {
                    args += ",";
                }
                args += postIds.get(i);
            }

            try (Connection connection = sql2o.open()) {
                commentedCount = connection.createQuery("SELECT COUNT(*) FROM comments WHERE post_id IN (" + args + ")")
                        .executeScalar(Integer.class);
            }
        }

        User me = getSessionUser(request);

        Map<String, Object> model = new HashMap<>();

        model.put("posts", posts);
        model.put("user", user);
        model.put("post_count", postCount);
        model.put("comment_count", commentCount);
        model.put("commented_count", commentedCount);
        model.put("csrf_token", getCSRFToken(request));
        model.put("me", me);
        model.put("content", "user");

        return render(model, request);
    }

    String getPosts(Request request, Response response) {
        String maxCreatedAt = request.queryParams("max_created_at");

        if (maxCreatedAt.equals("")) {
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        Date date = null;
        try {
            date = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX").parse(maxCreatedAt);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.BAD_REQUEST_400);
        }

        List<Post> result = new ArrayList<>();
        try (Connection connection = sql2o.open()) {
            result = connection.createQuery("SELECT id, user_id, body, mime, created_at FROM posts WHERE created_at <= :max_created_at ORDER BY created_at DESC")
                    .addParameter("max_created_at", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S").format(date))
                    .executeAndFetch(Post.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        List<Post> posts = makePosts(result, getCSRFToken(request), false);

        if (posts.size() == 0) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        Map<String, Object> model = new HashMap<>();
        model.put("posts", posts);
        model.put("content", "posts");

        return render(model, request);
    }

    String getPostsId(Request request, Response response) {
        String postId = request.params("id");

        Integer pid = null;

        try {
            pid = Integer.parseInt(postId);
        } catch (NumberFormatException e) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        List<Post> result = new ArrayList<>();
        try (Connection connection = sql2o.open()) {
            result = connection.createQuery("SELECT * FROM posts WHERE id = :id")
                    .addParameter("id", pid)
                    .executeAndFetch(Post.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        List<Post> posts = makePosts(result, getCSRFToken(request), true);

        if (posts.size() == 0) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        Post p = posts.get(0);

        User me = getSessionUser(request);

        Map<String, Object> model = new HashMap<>();
        model.put("post", p);
        model.put("me", me);
        model.put("csrf_token", getCSRFToken(request));
        model.put("content", "post");

        return render(model, request);
    }

    Object postIndex(Request request, Response response) {
        User me = getSessionUser(request);
        if (!isLogin(me)) {
            response.redirect("/login", HttpStatus.FOUND_302);
            halt();
        }

        MultipartConfigElement multipartConfigElement = new MultipartConfigElement(System.getProperty("java.io.tmpdir"));
        request.raw().setAttribute("org.eclipse.jetty.multipartConfig", multipartConfigElement);

        String csrfToken = "";
        String body = "";
        Part file = null;
        try {
            Collection<Part> parts = request.raw().getParts();
            for (Part part : parts) {
                if (part.getName().equals("csrf_token") && part.getContentType() == null) {
                    try(InputStream is = part.getInputStream()) {
                        csrfToken = new BufferedReader(new InputStreamReader(is)).lines().collect(Collectors.joining());
                    }
                } else if(part.getName().equals("body") && part.getContentType() == null) {
                    try(InputStream is = part.getInputStream()) {
                        body = new BufferedReader(new InputStreamReader(is)).lines().collect(Collectors.joining());
                    }
                } else if (part.getName().equals("file") && !part.getContentType().equals("application/octet-stream")) {
                    file = part;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        if (!csrfToken.equals(getCSRFToken(request))) {
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        if (file == null) {
            Session session = getSession(request);
            session.attribute("notice", "画像が必須です");

            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        String mime = "";

        if (file != null) {
            String contentType = file.getContentType();
            if (contentType.contains("jpeg")) {
                mime = "image/jpeg";
            } else if (contentType.contains("png")) {
                mime = "image/png";
            } else if (contentType.contains("gif")) {
                mime = "image/gif";
            } else {
                Session session = getSession(request);
                session.attribute("notice", "投稿できる画像形式はjpgとpngとgifだけです");

                response.redirect("/", HttpStatus.FOUND_302);
                halt();
            }
        }

        byte[] fileData = null;
        try {
            if (file.getSize() >  UPLOAD_LIMIT) {
                Session session = getSession(request);
                session.attribute("notice", "ファイルサイズが大きすぎます");

                response.redirect("/", HttpStatus.FOUND_302);
                halt();
            }
            InputStream is = file.getInputStream();
            byte[] buffer = new byte[1024];
            try(ByteArrayOutputStream bo = new ByteArrayOutputStream()) {
                while (true) {
                    int len = is.read(buffer);
                    if (len < 0) { break; }
                    bo.write(buffer, 0, len);
                }
                fileData = bo.toByteArray();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Integer pid = null;
        try (Connection connection = sql2o.open()) {
            connection.createQuery("INSERT INTO posts (user_id, mime, imgdata, body) VALUES (:user_id, :mime, :imgdata, :body)")
                    .addParameter("user_id", me.id)
                    .addParameter("mime", mime)
                    .addParameter("imgdata", new ByteArrayInputStream(fileData))
                    .addParameter("body", body)
                    .executeUpdate();
            Post result = connection.createQuery("SELECT * FROM posts WHERE user_id = :user_id ORDER BY created_at DESC")
                    .addParameter("user_id", me.id)
                    .executeAndFetchFirst(Post.class);
            pid = result.id;
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.INTERNAL_SERVER_ERROR_500);
        }

        response.redirect("/posts/" + pid, HttpStatus.FOUND_302);
        return null;
    }

    HttpServletResponse getImage(Request request, Response response) {
        String id = request.params("id");
        if(!Pattern.compile("^[a-zA-Z0-9]+\\.[a-zA-Z0-9]+$").matcher(id).matches()) {
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }
        String[] split = request.params("id").split("\\.");
        String pidStr = split[0];
        String ext = split[1];

        Integer pid = null;

        try {
            pid = Integer.parseInt(pidStr);
        } catch (NumberFormatException e) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        Post post = null;
        try (Connection connection = sql2o.open()) {
            post = connection.createQuery("SELECT * FROM posts WHERE id = :id")
                    .addParameter("id", pid)
                    .executeAndFetchFirst(Post.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        if (post == null) {
            halt(HttpStatus.NOT_FOUND_404);
        }

        if (ext.equals("jpg") && post.mime.equals("image/jpeg") ||
                ext.equals("png") && post.mime.equals("image/png") ||
                ext.equals("gif") && post.mime.equals("image/gif")) {
            response.type(post.mime);
            HttpServletResponse raw = response.raw();
            try(ServletOutputStream stream = raw.getOutputStream()) {
                stream.write(post.imgdata);
                stream.flush();
                return raw;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        halt(HttpStatus.NOT_FOUND_404);
        return null;
    }

    Object postComment(Request request, Response response) {
        User me = getSessionUser(request);

        if (!isLogin(me)) {
            response.redirect("/login", HttpStatus.FOUND_302);
            halt(HttpStatus.FOUND_302);
        }

        if (!request.queryParams("csrf_token").equals(getCSRFToken(request))) {
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        String postId = request.queryParams("post_id");

        if (!postId.matches("^[0-9]*$")) {
            System.out.println("post_idは整数のみです");
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        try (Connection connection = sql2o.open()) {
            connection.createQuery("INSERT INTO comments (post_id, user_id, comment) VALUES (:post_id, :user_id, :comment)")
                    .addParameter("post_id", new Integer(postId))
                    .addParameter("user_id", me.id)
                    .addParameter("comment", request.queryParams("comment"))
                    .executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        response.redirect("/posts/" + postId, HttpStatus.FOUND_302);
        return null;
    }

    String getAdminBanned(Request request, Response response) {
        User me = getSessionUser(request);

        if (!isLogin(me)) {
            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        if (!me.authority) {
            halt(HttpStatus.FORBIDDEN_403);
        }

        List<User> users = new ArrayList<>();
        try (Connection connection = sql2o.open()) {
            users = connection.createQuery("SELECT * FROM users WHERE authority = false AND del_flg = false ORDER BY created_at DESC")
                    .executeAndFetch(User.class);
        } catch (Exception e) {
            e.printStackTrace();
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        Map<String, Object> model = new HashMap<>();
        model.put("users", users);
        model.put("me", me);
        model.put("csrf_token", getCSRFToken(request));
        model.put("content", "banned");

        return render(model, request);
    }

    Object postAdminBanned(Request request, Response response) {
        User me = getSessionUser(request);

        if (!isLogin(me)) {
            response.redirect("/", HttpStatus.FOUND_302);
            halt();
        }

        if (!me.authority) {
            halt(HttpStatus.FORBIDDEN_403);
        }

        // request.queryMap().toMap().get("uid[]") では値が取得できないので無理矢理
        String body = request.body();
        String[] params = body.split("&");
        String csrfToken = null;
        List<String> uids = new ArrayList<>();
        for (String param : params) {
            String[] kv = param.split("=");
            if (kv[0].equals("uid%5B%5D")) {
                uids.add(kv[1]);
            } else if (kv[0].equals("csrf_token")) {
                csrfToken = kv[1];
            }
        }

        if (csrfToken == null || !csrfToken.equals(getCSRFToken(request))) {
            halt(HttpStatus.UNPROCESSABLE_ENTITY_422);
        }

        try (Connection connection = sql2o.beginTransaction()) {
            for (String uid : uids) {
                connection.createQuery("UPDATE users SET del_flg = :del_flg WHERE id = :id")
                        .addParameter("del_flg", true)
                        .addParameter("id", uid)
                        .executeUpdate();
            }
            connection.commit();
        }

        response.redirect("/admin/banned", HttpStatus.FOUND_302);
        return null;
    }


    private String render(Map<String, Object> model, Request request) {
        model.put("baseUrl", request.scheme() + "://" + request.raw().getServerName() + "/");
        return new ThymeleafTemplateEngine().render(new ModelAndView(model, "layout"));
    }
}
