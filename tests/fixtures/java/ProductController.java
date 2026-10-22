package com.dexsec.fixture;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.io.File;

@RestController
public class ProductController {

    // SQL injection: input concatenated into the statement
    @GetMapping("/products")
    public String products(HttpServletRequest request) {
        String name = request.getParameter("name");
        try (java.sql.Statement stmt = DB.getConnection().createStatement()) {
            java.sql.ResultSet rs = stmt.executeQuery("SELECT id, title FROM products WHERE title = '" + name + "'");
            return rs.toString();
        } catch (Exception exc) {
            return "error";
        }
    }

    // Path traversal: request parameter used as a file name
    @GetMapping("/download")
    public String download(HttpServletRequest request) {
        String path = request.getParameter("path");
        File file = new File("/var/data/" + path);
        return file.getAbsolutePath();
    }

    // XSS: the parameter is written into the response without encoding
    @GetMapping("/greet")
    public String greet(HttpServletRequest request) {
        String who = request.getParameter("who");
        return "<h1>Hello " + who + "</h1>";
    }
}
