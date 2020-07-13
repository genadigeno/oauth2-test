<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<html>
<head>
    <title>Title</title>
    <script src="https://apis.google.com/js/platform.js" async defer></script>
    <meta name="google-signin-client_id" content="531089080960-vu0hlmfssab5s9g3qv401dohigc1s64j.apps.googleusercontent.com">
</head>
<body>

<%--<form:form autocomplete="false" method="post" action="${pageContext}/login" commandName="">
    <form:input path="username" />
    <form:input path="password" />
    <form:button name="login" value="Log in"/>
</form:form>--%>
<div class="g-signin2" data-onsuccess="onSignIn"></div>
<br>
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
