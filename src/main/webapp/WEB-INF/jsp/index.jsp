<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%--<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>--%>
<%--<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>--%>
<html>
<head>
    <title>Title</title>
    <link rel="stylesheet" href="./css/login.css">
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
    <a href="/oauth2/authorization/google">
        <img src="./icons/google.png" alt="google">
        <span>Google</span>
    </a>
    <br>
    <a href="/oauth2/authorization/facebook">
        <img src="./icons/facebook.png" alt="facebook">
        <span>Facebook</span>
    </a>
    <br>
    <a href="/oauth2/authorization/yahoo">
        <img src="./icons/yahoo.png" alt="facebook">
        <span>Yahoo</span>
    </a>
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

</body>
</html>
