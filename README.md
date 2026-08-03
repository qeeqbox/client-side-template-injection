<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/content/client-side-template-injection.svg"></p>

## Client-Side Template Injection (CSTI)
Client-Side Template Injection (CSTI) is a security vulnerability that arises when an application uses untrusted user input within a client-side template. In this scenario, a JavaScript template engine mistakenly interprets that input as template code rather than as plain text. Unlike Server-Side Template Injection (SSTI), which occurs on the server, CSTI takes place entirely within the user's browser. 

Modern web applications frequently utilize client-side frameworks and template engines to dynamically generate HTML content. Examples of these frameworks and engines include AngularJS, Vue.js, Handlebars.js, Mustache, and client-side implementations of EJS. If an application incorrectly handles user input as part of a template, an attacker may exploit this vulnerability to inject template expressions that the browser subsequently evaluates.

## How CSTI Works
1. Client-Side Template Rendering: The web application utilizes a JavaScript template engine or framework to generate dynamic content directly in the browser.
2. User-Controlled Input: The application improperly incorporates user-controlled input into a client-side template, treating it as executable code rather than regular data.
3. Template Evaluation: When the browser renders the template, the client-side template engine evaluates template expressions supplied by the attacker.

## Impact  
Depending on the framework and the application, a successful CSTI attack can enable an attacker to:
- Execute arbitrary JavaScript (leading to Cross-Site Scripting).
- Read or manipulate page content.
- Steal session tokens or sensitive user information.
- Perform actions on behalf of the user.
- Bypass client-side security controls.

## Mitigation Strategies  
To prevent CSTI vulnerabilities:
- Treat user input as data, not as template code. Never allow untrusted input to be integrated into a client-side template.
- Avoid dynamic template compilation. Refrain from using functions such as AngularJS's `$compile` on user-controlled content.
- Use secure framework features. Prefer data binding mechanisms that automatically treat user input as plain text instead of executable template expressions.
- Keep frameworks and libraries up to date. Newer versions often incorporate security improvements and protections against template injection attacks.
- Conduct regular security testing and code reviews. Review applications for unsafe client-side template rendering and test for CSTI during security assessments.

## Example
Clone this current repo recursively
```sh
git clone --recurse-submodules https://github.com/qeeqbox/client-side-template-injection
```
Run the webapp using Python
```sh
python3 client-side-template-injection/vulnerable-web-app/webapp.py
```
Open the webapp in your browser 127.0.0.1:5142 and click register
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/content/1.png"></p>
Fill in the username, password, email as an AngularJS expression {{constructor.constructor('alert(1)')()}}, and CAPTCHA answer
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/content/2.png"></p>
The test user is created
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/content/4.png"></p>
Right-click on the page and click on View Page source, go to the network section, then log in as test
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/content/5.png"></p>
The response includes {{constructor.constructor('alert(1)')()}}, which will be is executed in the client browser
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/content/6.png"></p>

## Code
When a user fills in the registration form, the POST request sends the values to the add_user() function
```py
elif parsed_url.path == "/register" and all(key in post_request_data for key in ["username","password","email","captcha","uuid"]):
    ret = self.add_user(post_request_data["username"][0],post_request_data["password"][0],post_request_data["email"][0],post_request_data["captcha"][0],post_request_data["uuid"][0],post_request_data["debug"][0])
    if ret == "valid":
        self.send_content(200, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data["username"][0]} created".encode("utf-8"), b"login"))
    elif ret == "captcha":
        self.send_content(200, [('Content-type', 'text/html')], self.msg_page(f"Wrong captcha".encode("utf-8"), b"login"))
    elif ret == "username":
        self.send_content(200, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data['username'][0]} already exists".encode("utf-8"), b"login"))
    else:
        self.send_content(200, [('Content-type', 'text/html')], self.msg_page(f"User {post_request_data["username"][0]} was not created".encode("utf-8"), b"login"))
    return
```
The add_user() function does verify the values, if a user enters AngularJS expression, it will be saved in the database
```py
def add_user(self, username,password,email,captcha,uuid,debug):
    try:
        with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
            cursor = connection.cursor()
            results_user = cursor.execute("SELECT * FROM users WHERE username='%s'" % (username)).fetchone()
            if results_user:
                return "username"
            results_captcha = cursor.execute("SELECT * FROM captcha WHERE uuid='%s'" % (uuid)).fetchone()
            if results_captcha[3] == captcha or debug == "1":
                cursor.execute("INSERT into users(username, hash, email, department, access, is_admin) values(?,?,?,?,?,?)", (username, sha512(password.encode("utf-8")+SALT).hexdigest(),email,"none","profile,tickets",0))
                return "valid"
            else:
                return "captcha"
    except Exception as e:
        return str(e).encode("utf-8")
```
When the user logs in and has access to the profile section, the profile section will be filled with the values
```py
@logged_in
@check_access(access="profile")
@render_page(file="profile.html")
def profile_section(self):
    temp = b""
    with connect(DATABASE, isolation_level=None, check_same_thread=False) as connection:
        cursor = connection.cursor()
        profile = cursor.execute("SELECT * FROM users WHERE username='%s'" % self.session["username"]).fetchone()
        if profile:
            temp += f"<div>username: {profile[1]}</div>".encode("utf-8")
            temp += f"<div>email: {profile[3]}</div>".encode("utf-8")
            temp += f"<div>department: {profile[4]}</div>".encode("utf-8")
            temp += f"<div>access: {profile[5]}</div>".encode("utf-8")
            temp += f"<div>admin: {profile[6]}</div>".encode("utf-8")
    return [((b"{{profile-results}}"),temp)]
```
The profile section is rendered using AngularJS, as indicated by the ng-app value, this will be rendered in the client browser
```html
<form class="box-border-style" id="target-section" method="post">
  <div class="div-header">
    <div class="div-left">Profile Info</div>
  </div>
  <div class="div-100 collapse show">
      <div id="profile-results" ng-app>
        {{profile-results}}
      </div>
  </div>
</form>
```
