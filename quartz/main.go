package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserCredential struct {
	Password string
	Email    string
}

var users = map[string]UserCredential{
	"alice": {Password: "password123", Email: "alice@example.com"},
	"bob":   {Password: "secret456", Email: "bob@example.com"},
}

const loginFormHTML = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
</head>
<body>
  <form id="login-form">
    <label>Username: <input type="text" name="username" /></label><br><br>
    <label>Password: <input type="password" name="password" /></label><br><br>
    <button type="submit">Login</button>
  </form>
  <script>
    function getCookie(name) {
      var match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[\^$.*+?()[\]{}|]/g, '\\$&') + '=([^;]*)'));
      return match ? decodeURIComponent(match[1]) : '';
    }

    document.getElementById('login-form').addEventListener('submit', function(e) {
      e.preventDefault();
      var form = e.target;
      var username = form.elements['username'].value;
      var password = form.elements['password'].value;

      var headers = { 'Content-Type': 'application/json' };
      var token = getCookie('PRISM-ACCESS-TOKEN');
      if (token) {
        headers['PRISM-SUBMIT-TOKEN'] = token;
      }

      fetch('/login', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ username: username, password: password }),
      }).then(function(res) {
        return res.json();
      }).then(function(data) {
        console.log(data);
      });
    });
  </script>
</body>
</html>`

func handleGetLogin(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(loginFormHTML))
}

func handlePostLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	cred, ok := users[req.Username]
	if !ok || cred.Password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "login successful", "email": cred.Email})
}

func handleLogout(c *gin.Context) {
	c.SetCookie("PRISM-ACCESS-TOKEN", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}

func main() {
	r := gin.Default()

	r.GET("/login", handleGetLogin)
	r.POST("/login", handlePostLogin)
	r.Any("/logout", handleLogout)

	r.NoRoute(func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)

		headers := make(map[string][]string)
		for k, v := range c.Request.Header {
			headers[k] = v
		}

		query := make(map[string][]string)
		for k, v := range c.Request.URL.Query() {
			query[k] = v
		}

		out, _ := json.MarshalIndent(gin.H{
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
			"query":   query,
			"headers": headers,
			"body":    string(body),
		}, "", "  ")
		c.Data(http.StatusOK, "application/json; charset=utf-8", out)
	})

	r.Run(":8080")
}
