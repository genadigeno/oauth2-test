<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<html>
<head>
    <title>Title</title>
    <%--<script src="https://apis.google.com/js/platform.js?onload=init" async defer></script>
    <script async defer crossorigin="anonymous" src="https://connect.facebook.net/en_US/sdk.js"></script>
    <meta name="google-signin-client_id" content="531089080960-vu0hlmfssab5s9g3qv401dohigc1s64j.apps.googleusercontent.com">--%>
</head>
<body>

<%--<form:form autocomplete="false" method="post" action="${pageContext}/login" commandName="">
    <form:input path="username" />
    <form:input path="password" />
    <form:button name="login" value="Log in"/>
</form:form>--%>

<%--<div class="g-signin2" data-onsuccess="onSignIn"></div>
<fb:login-button scope="public_profile,email" onlogin="checkLoginState();">
</fb:login-button>
<div id="status"></div>--%>
<h3>Login with:</h3>

<p>
    <a href="/oauth2/authorization/google">Google</a>
    <br>
    <a href="/oauth2/authorization/facebook">Facebook</a>
</p>

<br>

<h3>Or My Energo:</h3>

<form action="${request.getContextPath()}/login" method="post">
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
    <label>User Name
        <input type="text" name="username" value="user">
    </label>
    <label>Password
        <input type="password" name="password" value="password">
    </label>
    <button type="submit">Log in</button>
</form>

<a href="${request.getContextPath()}/home">Home Page</a>

<%--<script>
    // gapi.load('auth2', function () {
    //     gapi.auth2.init();
    // })
    function init() {
        console.log('Initialized');
        gapi.load('auth2', function() {
            /* Ready. Make a call to gapi.auth2.init or some other API */
        });
    }
    function onSignIn(googleUser) {
        var profile = googleUser.getBasicProfile();
        console.log('ID: ' + profile.getId()); // Do not send to your backend! Use an ID token instead.
        console.log('Name: ' + profile.getName());
        console.log('Image URL: ' + profile.getImageUrl());
        console.log('Email: ' + profile.getEmail()); // This is null if the 'email' scope is not present.
        // window.location.href = "/home";
    }
</script>

<script>

    function statusChangeCallback(response) {  // Called with the results from FB.getLoginStatus().
        console.log('statusChangeCallback');
        console.log(response);                   // The current login status of the person.
        if (response.status === 'connected') {   // Logged into your webpage and Facebook.
            testAPI();
        } else {                                 // Not logged into your webpage or we are unable to tell.
            document.getElementById('status').innerHTML = 'Please log ' +
                'into this webpage.';
        }
    }

    function checkLoginState() {               // Called when a person is finished with the Login Button.
        FB.getLoginStatus(function(response) {   // See the onlogin handler
            statusChangeCallback(response);
        });
    }

    window.fbAsyncInit = function() {
        FB.init({
            appId      : '208223840483753',
            cookie     : true,                     // Enable cookies to allow the server to access the session.
            xfbml      : true,                     // Parse social plugins on this webpage.
            version    : 'v7.0'                    // Use this Graph API version for this call.
        });


        FB.getLoginStatus(function(response) {   // Called after the JS SDK has been initialized.
            statusChangeCallback(response);        // Returns the login status.
        });

        FB.login(function(response) {
            if (response.status === 'connected') {
                console.log('Connected');
                console.log(response);
            } else {
                console.log('Not Connected');
                console.log(response);
            }
        });

        FB.logout(function(response) {
            console.log(response);
        });
    };

    function testAPI() {                      // Testing Graph API after login.  See statusChangeCallback() for when this call is made.
        console.log('Welcome!  Fetching your information.... ');
        FB.api('/me', function(response) {
            console.log('Successful login for: ' + response.name);
            document.getElementById('status').innerHTML = 'Thanks for logging in, ' + response.name + '!';

            // window.location.href = "/home";
        });
    }

</script>--%>
</body>
</html>
